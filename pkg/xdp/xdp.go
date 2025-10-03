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

var (
	ipStats   *ebpf.Map
	blacklist *ebpf.Map
)

// LoadXDP loads the embedded eBPF object, attaches it to ifaceName,
// and returns (link handle, blacklist map, cleanup fn).
func LoadXDP(ifaceName string, stats bool) (cleanup func() error, err error) {
	// Allow BPF maps > RLIMIT_MEMLOCK on older kernels :contentReference[oaicite:1]{index=1}

	var (
		lk  []*link.Link
		ifs []net.Interface
	)

	if err = rlimit.RemoveMemlock(); err != nil {
		err = fmt.Errorf("rlimit: %w", err)
		return
	}

	// 1. Load programs/maps into the kernel.
	var objs xdpObjects
	if err = loadXdpObjects(&objs, nil); err != nil {
		err = fmt.Errorf("load objects: %w", err)
		return nil, fmt.Errorf("load objects: %w", err)
	}

	// 2. Resolve interface index.
	if ifaceName == "" || ifaceName == "all" {
		ifs, err = net.Interfaces()
		if err != nil {
			objs.Close()
			return nil, fmt.Errorf("list interfaces: %w", err)
		}
	} else {
		var iface *net.Interface
		iface, err = net.InterfaceByName(ifaceName)
		if err != nil {
			objs.Close()
			return nil, fmt.Errorf("get interfaces %s: %w", ifaceName, err)
		}
		ifs = []net.Interface{*iface}
	}
	for _, iface := range ifs {
		if iface.Name == "lo" {
			continue // skip loopback
		}
		log.Infof("using interface: %s idx=%d flags=%s\n", iface.Name, iface.Index, iface.Flags)
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpBlockIpAndStats,
			Interface: iface.Index,
		})
		if err != nil {
			//objs.Close()
			log.Errorf("attach XDP failed to %s idx=%d: %v\n", iface.Name, iface.Index, err)
			continue
		}
		lk = append(lk, &l)
	}
	if len(lk) == 0 {
		objs.Close()
		return nil, fmt.Errorf("no interfaces available for XDP")
	}

	blacklist = objs.IpBlacklist
	ipStats = objs.IpStats

	info, _ := ipStats.Info()
	log.Infof("ip_stats: type=%v valueSize=%d maxEntries=%d\n",
		info.Type, info.ValueSize, info.MaxEntries)

	cleanup = func() error {
		for _, l := range lk {
			(*l).Close() // detaches
		}
		return objs.Close() // unpins maps/programs
	}
	return cleanup, nil
}

// For IPv4: returns 4-byte key as uint32.
// For IPv6: returns 16-byte key as [16]byte.
func ipKey(addr string) (any, error) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid IP %q: %w", addr, err)
	}

	if ip.Is4() {
		return binary.BigEndian.Uint32(ip.AsSlice()), nil
	}

	// not used for now
	if ip.Is6() {
		var key [16]byte
		copy(key[:], ip.AsSlice())
		return key, nil
	}

	return nil, fmt.Errorf("unsupported IP format: %q", addr)
}

func BlockIP(ip string, origin uint32) error {
	k, err := ipKey(ip)
	if err != nil {
		return err
	}
	return blacklist.Update(k, origin, ebpf.UpdateAny)
}

// UnblockIP removes an address.
func UnblockIP(ip string) error {
	k, err := ipKey(ip)
	if err != nil {
		return err
	}
	return blacklist.Delete(k)
}

func BlacklistIterator() *ebpf.MapIterator {
	// Create an iterator for the blacklist map.
	return blacklist.Iterate()
}

// IsBlocked checks membership.
func IsBlocked(m *ebpf.Map, ip string) (bool, error) {
	k, err := ipKey(ip)
	if err != nil {
		return false, err
	}
	var v uint8
	err = m.Lookup(k, &v)
	if errors.Is(err, syscall.ENOENT) {
		return false, nil
	}
	return err == nil, err
}

func GetStatsByOrigin(origin uint32) (float64, error) {
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return 0, fmt.Errorf("get possible CPUs: %w", err)
	}

	vals := make([]uint64, ncpu)
	if err := ipStats.Lookup(origin, &vals); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return 0, nil // origin not found
		}
		return 0, fmt.Errorf("lookup origin %d: %w", origin, err)
	}

	var total uint64
	for _, v := range vals {
		total += v
	}
	return float64(total), nil
}
