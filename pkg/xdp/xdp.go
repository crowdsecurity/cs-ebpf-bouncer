// SPDX-License-Identifier: MIT

package xdp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

type ipOriginStats struct {
	V4Count uint32
	V6Count uint32
}

var (
	ipStats    *ebpf.Map
	blacklist6 *ebpf.Map
	blacklist4 *ebpf.Map
)

type v6Key struct {
	Hi uint64
	Lo uint64
}

// LoadXDP loads the embedded eBPF object, attaches it to ifaceName,
// and returns (link handle, blacklist map, cleanup fn).
func LoadXDP(ifaceName string, stats bool) (lk link.Link, cleanup func() error, err error) {
	// Allow BPF maps > RLIMIT_MEMLOCK on older kernels :contentReference[oaicite:1]{index=1}
	if err = rlimit.RemoveMemlock(); err != nil {
		err = fmt.Errorf("rlimit: %w", err)
		return
	}

	// 1. Load programs/maps into the kernel.
	var objs xdpObjects
	if err = loadXdpObjects(&objs, nil); err != nil {
		err = fmt.Errorf("load objects: %w", err)
		return nil, nil, fmt.Errorf("load objects: %w", err)
	}

	// 2. Resolve interface index.
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("resolve interface: %w", err)
	}

	// 3. Attach XDP program.
	lk, err = link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpBlockIpAndStats,
		Interface: iface.Index,
	})
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("attach XDP: %w", err)
	}

	blacklist6 = objs.Ip6Blacklist
	blacklist4 = objs.Ip4Blacklist
	ipStats = objs.IpStats

	info, _ := ipStats.Info()
	log.Infof("ip_stats: type=%v valueSize=%d maxEntries=%d\n",
		info.Type, info.ValueSize, info.MaxEntries)

	cleanup = func() error {
		lk.Close()          // detaches
		return objs.Close() // unpins maps/programs
	}
	return lk, cleanup, nil
}

func ip6Key(ip netip.Addr) v6Key {
	b := ip.AsSlice() // 16 bytes in network order

	w0 := binary.BigEndian.Uint32(b[0:4])
	w1 := binary.BigEndian.Uint32(b[4:8])
	w2 := binary.BigEndian.Uint32(b[8:12])
	w3 := binary.BigEndian.Uint32(b[12:16])

	return v6Key{
		Hi: (uint64(w0) << 32) | uint64(w1),
		Lo: (uint64(w2) << 32) | uint64(w3),
	}
}

func BlockIP4(ip netip.Addr, origin uint32) error {
	k := binary.BigEndian.Uint32(ip.AsSlice())
	return blacklist4.Update(k, origin, ebpf.UpdateAny)
}

func BlockIP6(ip netip.Addr, origin uint32) error {
	k := ip6Key(ip)
	return blacklist6.Update(k, origin, ebpf.UpdateAny)
}

// UnblockIP removes an address.
func UnblockIP4(ip netip.Addr) error {
	k := binary.BigEndian.Uint32(ip.AsSlice())
	return blacklist4.Delete(k)
}

func UnblockIP6(ip netip.Addr) error {
	k := ip6Key(ip)
	return blacklist6.Delete(k)
}

func BlacklistIterator() (*ebpf.MapIterator, *ebpf.MapIterator) {
	// Create an iterator for the blacklist map.
	return blacklist4.Iterate(), blacklist6.Iterate()
}

func GetStatsByOrigin(origin uint32) (float64, float64, error) {
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return 0, 0, fmt.Errorf("get possible CPUs: %w", err)
	}

	vals := make([]ipOriginStats, ncpu)
	if err := ipStats.Lookup(origin, &vals); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return 0, 0, nil // origin not found
		}
		return 0, 0, fmt.Errorf("lookup origin %d: %w", origin, err)
	}

	var v4, v6 uint64
	for _, v := range vals {
		v4 += uint64(v.V4Count)
		v6 += uint64(v.V6Count)
	}
	return float64(v4), float64(v6), nil
}
