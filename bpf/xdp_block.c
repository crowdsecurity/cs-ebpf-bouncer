/* SPDX-License-Identifier: GPL-3.0-only */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1 << 24);
  __type(key, __u32);  // IPv4 in network order
  __type(value, __u8); // dummy value
} ip_blacklist SEC(".maps");

SEC("xdp")
int xdp_block_ip(struct xdp_md *ctx) {
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

  __u32 key = bpf_ntohl(ip->saddr); // source IP address in host order
  __u8 *present = bpf_map_lookup_elem(&ip_blacklist, &key);
  if (present) {
    bpf_printk("blocked\n");
    return XDP_DROP;
  }

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
