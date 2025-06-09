package xdp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	//	log "github.com/sirupsen/logrus"
)

var originName = make(map[uint32]string)

// LoadXDP loads the embedded eBPF object, attaches it to ifaceName,
// and returns (link handle, blacklist map, cleanup fn).
func LoadXDP(ifaceName string, stats bool) (lk link.Link, blacklist *ebpf.Map, cleanup func() error, err error) {
	// Allow BPF maps > RLIMIT_MEMLOCK on older kernels :contentReference[oaicite:1]{index=1}
	if err = rlimit.RemoveMemlock(); err != nil {
		err = fmt.Errorf("rlimit: %w", err)
		return
	}

	// 1. Load programs/maps into the kernel.
	var objs xdpObjects
	if err = loadXdpObjects(&objs, nil); err != nil {
		err = fmt.Errorf("load objects: %w", err)
		return nil, nil, nil, fmt.Errorf("load objects: %w", err)
	}

	// 2. Resolve interface index.
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		objs.Close()
		return nil, nil, nil, fmt.Errorf("resolve interface: %w", err)
	}

	// 3. Attach XDP program.
	lk, err = link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpBlockIpAndStats,
		Interface: iface.Index,
	})
	if err != nil {
		objs.Close()
		return nil, nil, nil, fmt.Errorf("attach XDP: %w", err)
	}

	blacklist = objs.IpBlacklist
	cleanup = func() error {
		lk.Close()          // detaches
		return objs.Close() // unpins maps/programs
	}
	return lk, blacklist, cleanup, nil
}

func ipv4Key(addr string) (uint32, error) {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4: %q", addr)
	}
	return binary.BigEndian.Uint32(ip), nil
}

func BlockIP(m *ebpf.Map, ip string, origin uint32) error {
	k, err := ipv4Key(ip)
	if err != nil {
		return err
	}
	return m.Update(k, origin, ebpf.UpdateAny)
}

// UnblockIP removes an address.
func UnblockIP(m *ebpf.Map, ip string) error {
	k, err := ipv4Key(ip)
	if err != nil {
		return err
	}
	return m.Delete(k)
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

type StatsDelta struct {
	Processed uint64
	DroppedBy map[string]uint64
}

func CollectAndReset(ipStats *ebpf.Map,
	prev map[uint32]uint64) (StatsDelta, map[uint32]uint64, error) {

	delta := StatsDelta{DroppedBy: make(map[string]uint64)}
	curr := make(map[uint32]uint64)          // snapshot we return for next call
	zero := make([]uint64, runtime.NumCPU()) // []uint64{0,0,…} to reset

	it := ipStats.Iterate()
	var (
		key uint32
		val []uint64 // one entry per CPU
	)
	for it.Next(&key, &val) {
		var total uint64
		for _, c := range val {
			total += c
		}

		curr[key] = total

		// compute interval delta
		prevVal := prev[key]
		if total < prevVal {
			// counter wrapped? shouldn't happen for u64 but guard anyway
			prevVal = 0
		}
		diff := total - prevVal

		switch key {
		case 0:
			delta.Processed = diff
		default:
			name := originName[key]
			if name == "" {
				name = fmt.Sprintf("origin_%d", key)
			}
			delta.DroppedBy[name] += diff
		}

		// reset this counter for *all* CPUs with one Update
		if err := ipStats.Update(key, zero, ebpf.UpdateExist); err != nil {
			return delta, curr, fmt.Errorf("reset key %d: %w", key, err)
		}
	}
	if err := it.Err(); err != nil {
		return delta, curr, err
	}
	return delta, curr, nil
}
