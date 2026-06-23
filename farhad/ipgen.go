package main

import (
	"context"
	"math"
	"net"
	"sort"
	"strings"
)

func ipToU32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func u32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func cidrHostCount(cidr string) uint64 {
	cidr = strings.TrimSpace(cidr)
	if strings.Contains(cidr, ":") {
		return 0
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0
	}
	ones, _ := n.Mask.Size()
	if ones < 8 {
		return 0
	}
	total := uint64(1) << uint(32-ones)
	if ones <= 30 {
		return total - 2
	}
	return total
}

func totalTasks(cfg Config) int64 {
	var total uint64
	for _, c := range cfg.CIDRList {
		total += cidrHostCount(c)
	}
	for _, r := range cfg.IPRanges {
		parts := strings.Split(r, "-")
		if len(parts) == 2 {
			s := net.ParseIP(strings.TrimSpace(parts[0]))
			e := net.ParseIP(strings.TrimSpace(parts[1]))
			if s != nil && e != nil && s.To4() != nil && e.To4() != nil {
				si, ei := uint64(ipToU32(s)), uint64(ipToU32(e))
				if ei >= si {
					total += ei - si + 1
				}
			}
		} else if p := net.ParseIP(strings.TrimSpace(r)); p != nil && p.To4() != nil {
			total++
		}
	}
	pl := uint64(len(cfg.Ports))
	if pl == 0 || total == 0 {
		return int64(total)
	}
	if total > math.MaxUint64/pl {
		return math.MaxInt64
	}
	total *= pl
	if total > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(total)
}

func sortedPorts(cfg Config) []int {
	ports := append([]int(nil), cfg.Ports...)
	sort.Ints(ports)
	return ports
}

// streamIPs lazily emits unique IPv4 addresses from CIDRs and ranges.
func streamIPs(ctx context.Context, cfg Config, out chan<- string) {
	defer close(out)
	seen := make(map[uint32]struct{}, 4096)

	emit := func(ipStr string) bool {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return true
		}
		key := ipToU32(ip)
		if _, dup := seen[key]; dup {
			return true
		}
		seen[key] = struct{}{}
		select {
		case out <- ipStr:
			return true
		case <-ctx.Done():
			return false
		}
	}

	for _, cidr := range cfg.CIDRList {
		cidr = strings.TrimSpace(cidr)
		if strings.Contains(cidr, ":") {
			continue
		}
		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil || ip.To4() == nil {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		if ones < 8 {
			continue
		}
		start := uint64(ipToU32(ip.Mask(ipnet.Mask)))
		hosts := uint64(1) << uint(32-ones)
		end := start + hosts - 1
		for i := start; i <= end; i++ {
			if ones <= 30 && (i == start || i == end) {
				if i == end {
					break
				}
				continue
			}
			if !emit(u32ToIP(uint32(i)).String()) {
				return
			}
			if i == end {
				break
			}
		}
	}

	for _, r := range cfg.IPRanges {
		parts := strings.Split(r, "-")
		if len(parts) == 2 {
			s := net.ParseIP(strings.TrimSpace(parts[0]))
			e := net.ParseIP(strings.TrimSpace(parts[1]))
			if s == nil || e == nil || s.To4() == nil || e.To4() == nil {
				continue
			}
			si, ei := uint64(ipToU32(s)), uint64(ipToU32(e))
			if si > ei {
				si, ei = ei, si
			}
			for i := si; i <= ei; i++ {
				if !emit(u32ToIP(uint32(i)).String()) {
					return
				}
				if i == ei {
					break
				}
			}
		} else if p := net.ParseIP(strings.TrimSpace(r)); p != nil && p.To4() != nil {
			emit(p.String())
		}
	}
}
