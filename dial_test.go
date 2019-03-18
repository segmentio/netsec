package netsec

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestRestrictedDial(t *testing.T) {
	pass := [...]string{
		"segment.com:443",
	}

	fail := [...]string{
		"0.0.0.0:443",
		"10.10.10.10:443",
		"100.64.0.1:443",
		"127.0.0.1:443",
		"169.254.169.255:443",
		"172.16.42.1:443",
		"192.168.0.1:443",
		"[::1]:443",
		"[fc00::1]:443",
		"[fe80::1]:443",
	}

	for _, addr := range pass {
		t.Run("trying to connect to "+addr+" must pass", testRestrictedDialPass(context.Background(), addr))
	}

	for _, addr := range fail {
		t.Run("trying to connect to "+addr+" must fail", testRestrictedDialFail(context.Background(), addr))
	}

	for _, addr := range fail {
		ctx := WithRestrictedNetworkBypass(context.Background())
		t.Run("trying to connect to "+addr+" must pass", testRestrictedDialFail(ctx, addr))
	}
}

var restrictedDial = RestrictedDial(
	(&net.Dialer{}).DialContext,
	Blacklist(PrivateIPNetworks),
)

func testRestrictedDialPass(ctx context.Context, address string) func(*testing.T) {
	return func(t *testing.T) {
		c, err := restrictedDial(ctx, "tcp", address)
		if err != nil {
			t.Error(err)
		} else {
			c.Close()
		}
	}
}

func testRestrictedDialFail(ctx context.Context, address string) func(*testing.T) {
	return func(t *testing.T) {
		c, err := restrictedDial(ctx, "tcp", address)

		switch e := err.(type) {
		case nil:
			t.Error("connecting to", address, "succeeded, connection established to", c.RemoteAddr())
			c.Close()

		case *net.OpError:
			if e.Op != "dial" {
				t.Error("invalid operation in net.OpError:", e.Op)
			}

			if e.Net != "tcp" {
				t.Error("invalid network in net.OpError:", e.Net)
			}

			switch addrErr, _ := e.Err.(*net.AddrError); {
			case addrErr == nil:
				t.Error("invalid sub-error:", err)
			case addrErr.Addr != address:
				t.Error("invalid host name in net.AddrError:", addrErr.Addr)
			case !strings.HasPrefix(addrErr.Err, "unauthorized "):
				t.Error("the error message must start with 'unauthorized ':", addrErr.Err)
			}

		default:
			t.Error("unexpected error returned when trying to connect:", e)
		}
	}
}
