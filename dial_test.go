package netsec

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRestrictedDial(t *testing.T) {
	pass := [...]string{
		"segment.com:443",
		"[2600:1901:0:94b6::]:443",
		"[2600:1f16:59e:b200:9824:7fb2:162:d476]:443",
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

	t.Run("trying to connect to local address with bypass must pass", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		addr := srv.URL[6:] // srv.URL includes the http:// prefix, strip it!

		ctx := WithRestrictedNetworkBypass(context.Background())
		testRestrictedDialPass(ctx, addr)
	})
}

type mockConn struct {
	laddr net.Addr
	raddr net.Addr
}

func (c mockConn) LocalAddr() net.Addr              { return c.laddr }
func (c mockConn) RemoteAddr() net.Addr             { return c.raddr }
func (c mockConn) Read(b []byte) (int, error)       { return 0, io.EOF }
func (c mockConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c mockConn) Close() error                     { return nil }
func (c mockConn) SetDeadline(time.Time) error      { return nil }
func (c mockConn) SetReadDeadline(time.Time) error  { return nil }
func (c mockConn) SetWriteDeadline(time.Time) error { return nil }

var restrictedDial = RestrictedDial(
	func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		p, err := strconv.Atoi(port)
		if err != nil {
			return nil, err

		}
		laddr := &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 12345,
		}
		raddr := &net.TCPAddr{
			IP:   net.ParseIP(host),
			Port: p,
		}
		return mockConn{laddr: laddr, raddr: raddr}, nil
	},
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
