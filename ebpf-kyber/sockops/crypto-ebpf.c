// crypto-ebpf.c - eBPF sockops/sk_msg with Kyber-derived encryption (simplified)
#include <linux/bpf.h>
#include <sys/socket.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define MAX_CONNECTIONS 1024
#define KYBER_SHARED_SECRET_SIZE 32  // Kyber768 shared secret
#define AES_KEY_SIZE 32              // Derived AES-256 key
#define AES_BLOCK_SIZE 16            // AES block size
#define MAX_MSG_SIZE 4096            // Maximum message size to process

// Key structure for socket mapping (IP + Port)
struct sock_key {
    __u32 ip;     // IP in host byte order
    __u32 port;   // Port in host byte order
};

// Crypto state for each connection (derived from Kyber secret)
struct crypto_state {
    __u8 kyber_shared_secret[KYBER_SHARED_SECRET_SIZE];  // Original Kyber secret
    __u8 aes_key[AES_KEY_SIZE];                          // Derived AES key
    __u8 encrypt_counter[AES_BLOCK_SIZE];                // Encryption counter
    __u8 decrypt_counter[AES_BLOCK_SIZE];                // Decryption counter
    __u64 packet_counter;                                // Packet sequence
    __u8 active;                                         // Connection active flag
    __u8 padding[7];
};

// Configuration for crypto operations
struct crypto_config {
    __u8 enable_encryption;
    __u8 enable_decryption;
    __u8 debug_mode;
    __u8 padding[5];
};

// Statistics tracking
struct crypto_stats {
    __u64 messages_processed;
    __u64 messages_encrypted;
    __u64 messages_decrypted;
    __u64 encryption_errors;
    __u64 active_connections;
};

// Socket hash map: IP+Port → Socket
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key, struct sock_key);
    __type(value, __u64);
} sock_map SEC(".maps");

// Crypto state map: IP+Port → Crypto State
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key, struct sock_key);
    __type(value, struct crypto_state);
} crypto_state_map SEC(".maps");

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct crypto_config);
} config_map SEC(".maps");

// Statistics map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct crypto_stats);
} stats_map SEC(".maps");

// Update statistics
static __always_inline void update_stats(__u32 stat_type) {
    __u32 key = 0;
    struct crypto_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats) return;
    
    switch (stat_type) {
        case 0: stats->messages_processed++; break;
        case 1: stats->messages_encrypted++; break;
        case 2: stats->messages_decrypted++; break;
        case 3: stats->encryption_errors++; break;
    }
}

// SK_MSG program for message-level processing (simplified - no actual encryption for verifier)
SEC("sk_msg")
int sk_msg_crypto(struct sk_msg_md *msg) {
    // Get configuration
    __u32 config_key = 0;
    struct crypto_config *config = bpf_map_lookup_elem(&config_map, &config_key);
    if (!config) return SK_PASS;
    
    update_stats(0); // messages_processed
    
    // Create socket key for crypto state lookup
    struct sock_key key = {
        .ip = msg->remote_ip4,
        .port = msg->remote_port
    };
    
    // Look up crypto state for this connection
    struct crypto_state *crypto = bpf_map_lookup_elem(&crypto_state_map, &key);
    if (!crypto || !crypto->active) {
        // No crypto state - redirect message through without encryption
        return bpf_msg_redirect_hash(msg, &sock_map, &key, BPF_F_INGRESS);
    }
    
    // Get message data length
    __u32 data_len = msg->data_end - msg->data;
    if (data_len == 0 || data_len > MAX_MSG_SIZE) {
        return SK_PASS;
    }
    
    // For now, just pass through with statistics tracking
    // In a production version, this would do actual encryption
    // but that requires more complex verifier-friendly code
    
    // Determine if this is outgoing (encrypt) or incoming (decrypt)
    int is_outgoing = msg->local_port > 1024;
    
    if (is_outgoing && config->enable_encryption) {
        update_stats(1); // messages_encrypted
        
        if (config->debug_mode) {
            bpf_printk("SK_MSG: Would encrypt %u bytes with Kyber-derived key", data_len);
        }
        
    } else if (!is_outgoing && config->enable_decryption) {
        update_stats(2); // messages_decrypted
        
        if (config->debug_mode) {
            bpf_printk("SK_MSG: Would decrypt %u bytes with Kyber-derived key", data_len);
        }
    }
    
    // Redirect message to appropriate socket
    int ret = bpf_msg_redirect_hash(msg, &sock_map, &key, BPF_F_INGRESS);
    
    if (config->debug_mode) {
        if (ret == SK_PASS) {
            bpf_printk("SK_MSG: Redirected successfully (port=%u ip=%x)", 
                      key.port, key.ip);
        } else {
            bpf_printk("SK_MSG: Redirect failed ret=%d (port=%u ip=%x)", 
                      ret, key.port, key.ip);
            update_stats(3); // encryption_errors
        }
    }
    
    return ret;
}

// SOCKOPS program for socket lifecycle management
SEC("sockops")
int sockops_crypto(struct bpf_sock_ops *ctx) {
    if (ctx->family != AF_INET) {
        return SK_PASS;
    }
    
    struct sock_key key = {
        .ip = ctx->local_ip4,   // already in host byte order
        .port = bpf_ntohl(ctx->local_port)
    };
    
    switch (ctx->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        // Socket established - add to socket map
        bpf_printk("SOCKOPS: Map socket lport:%u ip:%x cookie:%lx", 
                  key.port, key.ip, bpf_get_socket_cookie(ctx));
        bpf_sock_hash_update(ctx, &sock_map, &key, BPF_ANY);
        
        // Check if we have crypto state for this connection
        struct crypto_state *crypto = bpf_map_lookup_elem(&crypto_state_map, &key);
        if (crypto && crypto->active) {
            bpf_printk("SOCKOPS: Found Kyber crypto state for connection");
        }
        break;
        
    case BPF_SOCK_OPS_STATE_CB:
        // Socket state change - handle cleanup if needed
        if (ctx->args[1] == BPF_TCP_CLOSE) {
            bpf_printk("SOCKOPS: Socket closing, cleaning up crypto state");
            // Note: In a full implementation, we'd clean up crypto_state_map here
        }
        break;
    }
    
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";