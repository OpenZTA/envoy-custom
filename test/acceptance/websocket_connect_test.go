package acceptance

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestWebSocketExtendedConnectWithoutLegacyChallenge(t *testing.T) {
	g := newGateway(t, func(config map[string]any) {
		h := config["static_resources"].(map[string]any)["listeners"].([]any)[0].(map[string]any)["filter_chains"].([]any)[0].(map[string]any)["filters"].([]any)[0].(map[string]any)["typed_config"].(map[string]any)
		h["http2_protocol_options"] = map[string]any{"allow_connect": true}
	}, withQUIC, func(config map[string]any) {
		for _, v := range config["static_resources"].(map[string]any)["listeners"].([]any) {
			l := v.(map[string]any)
			if l["name"] == "quic" {
				l["filter_chains"].([]any)[0].(map[string]any)["filters"].([]any)[0].(map[string]any)["typed_config"].(map[string]any)["http3_protocol_options"].(map[string]any)["allow_extended_connect"] = true
			}
		}
	})
	for _, version := range []int{2, 3} {
		t.Run(fmt.Sprintf("HTTP%d", version), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			pr, pw := io.Pipe()
			defer pr.Close()
			defer pw.Close()
			req, _ := http.NewRequestWithContext(ctx, "CONNECT", "https://localhost/ws", pr)
			req.Header.Set("Sec-WebSocket-Version", "13")
			var client *http.Client
			if version == 3 {
				req.Proto = "websocket"
				client = g.quicClient(t, g.tls.Clone())
			} else {
				req.Header.Set(":protocol", "websocket")
				transport := &http2.Transport{TLSClientConfig: g.tls.Clone(), DialTLSContext: func(ctx context.Context, network, address string, tc *tls.Config) (net.Conn, error) {
					return (&tls.Dialer{Config: tc}).DialContext(ctx, network, g.addr)
				}}
				defer transport.CloseIdleConnections()
				client = &http.Client{Transport: transport, Timeout: 10 * time.Second}
			}
			// An RFC 8441/9220 client does not send Sec-WebSocket-Key.
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != 200 || response.ProtoMajor != version {
				t.Fatalf("extended WebSocket handshake: %s %s", response.Proto, response.Status)
			}
			if response.Header.Get("Sec-WebSocket-Accept") != "" {
				t.Fatal("legacy challenge response leaked into extended CONNECT")
			}
			payload := []byte{0, 1, 2, 255}
			mask := []byte{11, 22, 33, 44}
			frame := []byte{0x82, 0x84}
			frame = append(frame, mask...)
			for i, b := range payload {
				frame = append(frame, b^mask[i%4])
			}
			if _, err = pw.Write(frame); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 2+len(payload))
			if _, err = io.ReadFull(response.Body, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, append([]byte{0x82, 4}, payload...)) {
				t.Fatalf("WebSocket frame changed: %x", got)
			}
			g.policy.set("fixture.default", true)
			defer g.policy.set("fixture.default", false)
			done := make(chan error, 1)
			go func() { var b [1]byte; _, err := response.Body.Read(b[:]); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("revoked extended WebSocket stayed open")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("idle extended WebSocket survived revocation")
			}
			waitForActiveUpstreams(t, &g.activeWS, 0, "extended WebSocket")
		})
	}
}
