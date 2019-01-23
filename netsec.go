package netsec

import (
	"fmt"
	"net"
)

// CIR is like net.ParseDIR but panics if the input is invalid. This function
// is useful to initialize lists of CIDRs without having to check errors.
func CIDR(cidr string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return ipnet
}

// IPAddressOf extracts the IP address of addr, or returns nil if none were
// found.
func IPAddressOf(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	case *net.IPAddr:
		return a.IP
	default:
		return nil
	}
}

var (
	// PrivateIPNetworks lists standard IP networks used for private networks.
	PrivateIPNetworks = []*net.IPNet{
		CIDR("0.0.0.0/32"),
		CIDR("10.0.0.0/8"),
		CIDR("100.64.0.0/10"),
		CIDR("127.0.0.0/8"),
		CIDR("169.254.0.0/16"),
		CIDR("172.16.0.0/12"),
		CIDR("192.168.0.0/16"),
		CIDR("fc00::/7"),
		CIDR("fd00::/8"),
		CIDR("fe80::/10"),
		CIDR("::1/128"),
	}
)

// AddrCheck is an interface used to abstract the logic of validating network
// addresses.
//
// Implementations of AddrCheck must be safe to use concurrently from multiple
// goroutines.
type AddrCheck interface {
	// Check validates the address passed as argument, returning a non-nil error
	// if it did not pass.
	Check(net.Addr) error
}

// Whitelist is an implementation of the AddrCheck interface which verifies that
// addresses belong to one of the IP networks it contains.
type Whitelist []*net.IPNet

// Check satisfies the AddrCheck interface.
func (ipNetList Whitelist) Check(addr net.Addr) error {
	ip := IPAddressOf(addr)

	for _, ipNet := range ipNetList {
		if ipNet.Contains(ip) {
			return nil
		}
	}

	return fmt.Errorf("unauthorized attempt to connect to an address which isn't in any whitelisted networks (%s)", addr)
}

// Blacklist is an implementation of the AddrCheck interface which verifies that
// addresses don't belong to one of the IP networks it contains.
type Blacklist []*net.IPNet

// Check satisfies the AddrCheck interface.
func (ipNetList Blacklist) Check(addr net.Addr) error {
	ip := IPAddressOf(addr)

	for _, ipNet := range ipNetList {
		if ipNet.Contains(ip) {
			return fmt.Errorf("unauthorized attempt to connect to an address is a blacklisted network (%s)", addr)
		}
	}

	return nil
}
