package xdp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	//	log "github.com/sirupsen/logrus"
)

var (
	originName = make(map[uint32]string)
	ipStats    *ebpf.Map
	blacklist  *ebpf.Map
)

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

	blacklist = objs.IpBlacklist
	ipStats = objs.IpStats
	cleanup = func() error {
		lk.Close()          // detaches
		return objs.Close() // unpins maps/programs
	}
	return lk, cleanup, nil
}

func ipv4Key(addr string) (uint32, error) {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4: %q", addr)
	}
	return binary.BigEndian.Uint32(ip), nil
}

func BlockIP(ip string, origin uint32) error {
	k, err := ipv4Key(ip)
	if err != nil {
		return err
	}
	return blacklist.Update(k, origin, ebpf.UpdateAny)
}

// UnblockIP removes an address.
func UnblockIP(ip string) error {
	k, err := ipv4Key(ip)
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
	k, err := ipv4Key(ip)
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
	var vals []uint64
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
