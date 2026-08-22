package ip

import (
	"fmt"
	"net/netip"
)

type prefixNode[T any] struct {
	children [2]*prefixNode[T]
	values   []T
}

type prefixIndex[T any] struct {
	v4 *prefixNode[T]
	v6 *prefixNode[T]
}

func canonicalPrefix(prefix netip.Prefix) (netip.Prefix, error) {
	addr := prefix.Addr()
	bits := prefix.Bits()
	if addr.Is4In6() {
		// /96 is the entire IPv4 address space after unmapping. Reject it and
		// broader prefixes so mapped notation cannot silently become 0.0.0.0/0.
		if bits <= 96 {
			return netip.Prefix{}, fmt.Errorf("IPv4-mapped IPv6 prefix length %d must be greater than 96", bits)
		}
		return netip.PrefixFrom(addr.Unmap(), bits-96).Masked(), nil
	}
	return prefix.Masked(), nil
}

func (i *prefixIndex[T]) add(prefix netip.Prefix, value T) {
	prefix = prefix.Masked()
	addr := prefix.Addr().Unmap()
	root := &i.v6
	if addr.Is4() {
		root = &i.v4
	}
	if *root == nil {
		*root = &prefixNode[T]{}
	}
	node := *root
	for bit := 0; bit < prefix.Bits(); bit++ {
		direction := addressBit(addr, bit)
		if node.children[direction] == nil {
			node.children[direction] = &prefixNode[T]{}
		}
		node = node.children[direction]
	}
	node.values = append(node.values, value)
}

func (i *prefixIndex[T]) match(addr netip.Addr) []T {
	addr = addr.Unmap()
	node := i.v6
	if addr.Is4() {
		node = i.v4
	}
	if node == nil {
		return nil
	}
	out := append([]T(nil), node.values...)
	for bit := 0; bit < addr.BitLen(); bit++ {
		node = node.children[addressBit(addr, bit)]
		if node == nil {
			break
		}
		out = append(out, node.values...)
	}
	return out
}

func addressBit(addr netip.Addr, bit int) int {
	if addr.Is4() {
		bytes := addr.As4()
		return int((bytes[bit/8] >> (7 - uint(bit%8))) & 1)
	}
	bytes := addr.As16()
	return int((bytes[bit/8] >> (7 - uint(bit%8))) & 1)
}
