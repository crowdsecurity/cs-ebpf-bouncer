
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1 << 24);
  __type(key, __u32);   // IPv4 in network order
  __type(value, __u64); // dummy value
} ip_blacklist SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 1 << 8);
  __type(key, __u32);
  __type(value, __u64);
} ip_stats SEC(".maps");

static __always_inline void bump_counter(void *m, __u32 idx) {
  __u64 init = 1;
  __u64 *p = bpf_map_lookup_elem(m, &idx);
  if (p)
    __sync_fetch_and_add(p, 1);
  else
    bpf_map_update_elem(m, &idx, &init, BPF_NOEXIST);
}

SEC("xdp")
int xdp_block_ip_and_stats(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // parse ethernet header
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return XDP_PASS;
  }
  if (eth->h_proto != __constant_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  // parse IP header
  struct iphdr *ip = data + sizeof(*eth);
  if ((void *)(ip + 1) > data_end) {
    return XDP_PASS;
  }

  bump_counter(&ip_stats, 0);

  __u32 key = bpf_ntohl(ip->saddr); // source IP address in host order
  __u32 *origin = bpf_map_lookup_elem(&ip_blacklist, &key);

  if (origin) {
    bump_counter(&ip_stats, *origin);
    return XDP_DROP;
  }

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
