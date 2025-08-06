// SPDX-License-Identifier: MIT

package xdp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package xdp -tags linux -cc clang -target bpfel -cflags "-O2 -g -Wall -DUSE_CORE"  xdp  ../../bpf/xdp_block_and_stats.c -- -I../bpf/headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package xdp -tags linux -cc clang -target bpfeb -cflags "-O2 -g -Wall -DUSE_CORE"  xdp  ../../bpf/xdp_block_and_stats.c -- -I../bpf/headers
