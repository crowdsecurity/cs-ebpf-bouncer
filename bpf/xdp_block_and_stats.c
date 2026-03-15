/* SPDX-License-Identifier: GPL-3.0-only */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* IPv4 blacklist: key = IPv4 in host order, value = origin */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1 << 24);
  __type(key, __u32);
  __type(value, __u32); /* origin code */
} ip4_blacklist SEC(".maps");

/* IPv6 blacklist: key = raw 128‑bit address, value = origin */
struct v6_key {
  __u64 hi, lo;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1 << 22);
  __type(key, struct v6_key);
  __type(value, __u32); /* origin code */
} ip6_blacklist SEC(".maps");

/* Per‑origin counters: one counter for IPv4 drops, one for IPv6 drops */
struct ip_origin_stats {
  __u32 v4_count;
  __u32 v6_count;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 1 << 12);
  __type(key, __u32); /* origin */
  __type(value, struct ip_origin_stats);
} ip_stats SEC(".maps");

/* Update per‑origin stats: family = 4 for IPv4, 6 for IPv6 */
static __always_inline void update_origin_stats(__u32 origin, __u32 family) {
  struct ip_origin_stats *p = bpf_map_lookup_elem(&ip_stats, &origin);
  if (p) {
    if (family == 4)
      __sync_fetch_and_add(&p->v4_count, 1);
    else if (family == 6)
      __sync_fetch_and_add(&p->v6_count, 1);
  } else {
    /* Initialise new entry */
    struct ip_origin_stats init = {};
    if (family == 4)
      init.v4_count = 1;
    else if (family == 6)
      init.v6_count = 1;
    bpf_map_update_elem(&ip_stats, &origin, &init, BPF_NOEXIST);
  }
}

static __always_inline void v6_network_to_host_order(const struct in6_addr *a,
                                                     struct v6_key *out) {
  const __be32 *w = a->in6_u.u6_addr32; // 4 x big-endian 32-bit words
  out->hi = ((__u64)bpf_ntohl(w[0]) << 32) | bpf_ntohl(w[1]);
  out->lo = ((__u64)bpf_ntohl(w[2]) << 32) | bpf_ntohl(w[3]);
}

static __always_inline int handle_ipv4(void *l3, void *data_end) {
  const struct iphdr *ip4 = l3;
  if ((void *)(ip4 + 1) > data_end)
    return XDP_PASS;

  __u32 k4 = bpf_ntohl(ip4->saddr);
  __u32 *origin = bpf_map_lookup_elem(&ip4_blacklist, &k4);
  if (origin) {
    update_origin_stats(*origin, 4);
    return XDP_DROP;
  }
  return XDP_PASS;
}

static __always_inline int handle_ipv6(void *l3, void *data_end) {
  const struct ipv6hdr *ip6 = l3;
  if ((void *)(ip6 + 1) > data_end)
    return XDP_PASS;

  struct v6_key k6 = {};
  //__builtin_memcpy(&k6, &ip6->saddr, sizeof(k6));
  v6_network_to_host_order(&ip6->saddr, &k6);
  __u32 *origin = bpf_map_lookup_elem(&ip6_blacklist, &k6);
  if (origin) {
    update_origin_stats(*origin, 6);
    return XDP_DROP;
  }
  return XDP_PASS;
}

SEC("xdp")
int xdp_block_ip_and_stats(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  __u16 h_proto = bpf_ntohs(eth->h_proto);
  void *l3 = eth + 1;

  if (h_proto == ETH_P_IP)
    return handle_ipv4(l3, data_end);
  if (h_proto == ETH_P_IPV6)
    return handle_ipv6(l3, data_end);

  return XDP_PASS;
}

/* ... after you've parsed and bounds-checked the IPv6 header ... */
struct v6_key k6 = {};

char LICENSE[] SEC("license") = "GPL";
