package netsec

import (
	"context"
	"net"
)

// DialFunc is an alias for the signature of the functions used to establish
// network connections.
type DialFunc = func(context.Context, string, string) (net.Conn, error)

// RestrictedDialer
type RestrictedDialer struct {
	// The dial function used to establish network connections.
	DialFunc func(context.Context, string, string) (net.Conn, error)

	// List of checks that the dialer is going to apply to the network
	// addresses that it's attempting to connect to.
	Checks []AddrCheck

	// The resolver used to translate host names into network addresses.
	//
	// If nil, net.DefaultResolver is used.
	Resolver interface {
		LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
	}
}

// Dial resolves the address and applies the list of checks before delegating to
// the dial function configured on d.
func (d *RestrictedDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var ipAddr *net.IPAddr
	if ip := net.ParseIP(host); ip != nil {
		ipAddr = &net.IPAddr{IP: ip}
	} else {
		addrs, err := d.lookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(addrs) == 0 {
			// I'm not sure this could ever happen but the net package
			// documentation does not ensure that the list of addresses will
			// never be empty if the the error is nil.
			return nil, &net.OpError{
				Op:  "lookup",
				Net: network,
				Err: &net.DNSError{
					Err:  "No addresses returned by the DNS resolver",
					Name: host,
				},
			}
		}
		ipAddr = &addrs[0]
	}

	bypass := HasRestrictedNetworkBypass(ctx)
	for _, check := range d.Checks {
		if err := check.Check(ipAddr); err != nil && !bypass {
			return nil, &net.OpError{
				Op:   "dial",
				Net:  network,
				Addr: ipAddr,
				Err: &net.AddrError{
					Err:  err.Error(),
					Addr: address,
				},
			}
		}
	}

	address = net.JoinHostPort(ipAddr.String(), port)
	return d.DialFunc(ctx, network, address)
}

func (d *RestrictedDialer) lookupIPAddr(ctx context.Context, name string) ([]net.IPAddr, error) {
	r := d.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	return r.LookupIPAddr(ctx, name)
}

// RestrictedDial constructs a dial function which validates the address that it
// establishes connections to.
//
// A typical use case for this function is to pass checks that either allowlists
// or denylists IP networks, to prevent access to private networks for example:
//
//	transport := http.DefaultTransport.(*http.Transport)
//	transport.DialContext = netsec.RestrictedDial(transport.DialContext,
//		netsec.Denylist(netset.PrivateIPAddresses),
//	)
//
// The implementation protects the program from DNS rebinding attacks because it
// calls the underlying dial function with the address that it validated, not
// the address that the program originally dialed.
func RestrictedDial(dial DialFunc, checks ...AddrCheck) DialFunc {
	if dial == nil {
		panic("cannot restrict a nil dial function")
	}

	for _, check := range checks {
		if check == nil {
			panic("cannot create a restricted dial function with a nil check")
		}
	}

	dialer := RestrictedDialer{DialFunc: dial, Checks: make([]AddrCheck, len(checks))}
	copy(dialer.Checks, checks)
	return dialer.Dial
}
