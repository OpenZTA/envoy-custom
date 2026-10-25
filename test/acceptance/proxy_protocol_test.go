package acceptance

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// Match the real NAC adapter's listener-port resource map. A client-supplied
// destination in PROXY protocol must not authorize the fixed upstream as a
// different, allowed resource, either initially or during an idle recheck.
func TestTCPProxyProtocolCannotSelectAnUnrelatedResourcePolicy(t *testing.T) {
	g := newGateway(t, func(config map[string]any) {
		for _, value := range config["static_resources"].(map[string]any)["listeners"].([]any) {
			listener := value.(map[string]any)
			if listener["name"] == "tcp" {
				listener["listener_filters"] = []any{map[string]any{
					"name":         "envoy.filters.listener.proxy_protocol",
					"typed_config": map[string]any{"@type": "type.googleapis.com/envoy.extensions.filters.listener.proxy_protocol.v3.ProxyProtocol"},
				}}
			}
		}
	})
	g.policy.mu.Lock()
	g.policy.tcpPortResources = map[uint32]string{8444: "restricted-listener", 443: "unrelated-allowed"}
	g.policy.mu.Unlock()
	for _, version := range []string{"v1", "v2"} {
		t.Run(version, func(t *testing.T) {
			dial := func(expectDenied bool) *tls.Conn {
				raw, err := net.DialTimeout("tcp", g.tcpAddr, 3*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				_ = raw.SetDeadline(time.Now().Add(4 * time.Second))
				var header []byte
				if version == "v1" {
					header = []byte("PROXY TCP4 127.0.0.1 127.0.0.1 12345 443\r\n")
				} else {
					header = append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x11, 0, 12)
					header = append(header, 127, 0, 0, 1, 127, 0, 0, 1)
					header = binary.BigEndian.AppendUint16(header, 12345)
					header = binary.BigEndian.AppendUint16(header, 443)
				}
				if _, err = raw.Write(header); err != nil {
					_ = raw.Close()
					t.Fatal(err)
				}
				conn := tls.Client(raw, g.tls.Clone())
				if err = conn.Handshake(); err != nil {
					_ = conn.Close()
					if expectDenied {
						if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
							t.Fatal("denied PROXY connection stalled during its TLS handshake")
						}
						return nil
					}
					t.Fatal(err)
				}
				return conn
			}
			g.policy.set("restricted-listener", false)
			conn := dial(false)
			defer conn.Close()
			reader := bufio.NewReader(conn)
			if line, err := reader.ReadString('\n'); err != nil || line != "READY\n" {
				t.Fatalf("valid PROXY + mTLS session: %q %v", line, err)
			}
			g.policy.mu.Lock()
			port := g.policy.lastTCPPort
			g.policy.mu.Unlock()
			if port != 8444 {
				t.Fatalf("client PROXY destination selected authorization port %d; expected actual listener 8444", port)
			}
			payload := []byte("real listener policy binding")
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			body := make([]byte, len(payload))
			if _, err := io.ReadFull(reader, body); err != nil || !bytes.Equal(body, payload) {
				t.Fatalf("PROXY echo: %q %v", body, err)
			}
			g.policy.mu.Lock()
			checksBefore := g.policy.checks["restricted-listener"]
			g.policy.mu.Unlock()
			g.policy.set("restricted-listener", true)
			_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
			if _, err := reader.ReadByte(); err == nil {
				t.Fatal("forged destination kept an existing denied listener session open")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("idle PROXY session was not closed by its listener policy")
			}
			g.policy.mu.Lock()
			checksAfter := g.policy.checks["restricted-listener"]
			g.policy.mu.Unlock()
			if checksAfter <= checksBefore {
				t.Fatal("session closed without a recheck of its actual listener resource")
			}
			_ = conn.Close()
			before := g.accepted.Load()
			denied := dial(true)
			if denied != nil {
				defer denied.Close()
				_ = denied.SetReadDeadline(time.Now().Add(3 * time.Second))
				if _, err := bufio.NewReader(denied).ReadByte(); err == nil {
					t.Fatal("unrelated allowed destination bypassed the denied listener")
				} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatal("new denied PROXY connection did not close")
				}
			}
			if count := g.accepted.Load(); count != before {
				t.Fatalf("denied listener reached its private upstream: %d -> %d", before, count)
			}
		})
	}
}
