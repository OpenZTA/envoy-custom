package acceptance

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestHTTP2ConnectFixedTargetAndIdleRevocation(t *testing.T) {
	g := newGateway(t, func(config map[string]any) {
		listener := config["static_resources"].(map[string]any)["listeners"].([]any)[0].(map[string]any)
		hcm := listener["filter_chains"].([]any)[0].(map[string]any)["filters"].([]any)[0].(map[string]any)["typed_config"].(map[string]any)
		hcm["http2_protocol_options"] = map[string]any{"allow_connect": true}
		hcm["upgrade_configs"] = append(hcm["upgrade_configs"].([]any), map[string]any{"upgrade_type": "CONNECT"})
		host := hcm["route_config"].(map[string]any)["virtual_hosts"].([]any)[0].(map[string]any)
		host["routes"] = append([]any{
			map[string]any{"match": map[string]any{"connect_matcher": map[string]any{}, "headers": []any{map[string]any{"name": ":authority", "string_match": map[string]any{"exact": "lab-tcp:9004"}}}}, "route": map[string]any{"cluster": "tcp", "timeout": "0s", "idle_timeout": "0s", "upgrade_configs": []any{map[string]any{"upgrade_type": "CONNECT", "connect_config": map[string]any{}}}}},
			map[string]any{"match": map[string]any{"connect_matcher": map[string]any{}}, "direct_response": map[string]any{"status": 403}},
		}, host["routes"].([]any)...)
	})
	client := g.client(true)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	request, _ := http.NewRequestWithContext(ctx, "CONNECT", "https://"+g.addr, reader)
	request.Host = "lab-tcp:9004"
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != 200 {
		t.Fatalf("%s %s", response.Proto, response.Status)
	}
	ready := make([]byte, 6)
	if _, err = io.ReadFull(response.Body, ready); err != nil || string(ready) != "READY\n" {
		t.Fatalf("server-first data %q: %v", ready, err)
	}
	payload := []byte("CONNECT\x00\xffpayload")
	if _, err = writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, len(payload))
	if _, err = io.ReadFull(response.Body, echoed); err != nil || !bytes.Equal(echoed, payload) {
		t.Fatalf("echo %x: %v", echoed, err)
	}
	denied, _ := http.NewRequestWithContext(ctx, "CONNECT", "https://"+g.addr, nil)
	denied.Host = "forbidden.invalid:443"
	rejection, err := client.Do(denied)
	if err != nil {
		t.Fatal(err)
	}
	rejection.Body.Close()
	if rejection.StatusCode != 403 {
		t.Fatalf("arbitrary destination: %s", rejection.Status)
	}
	g.policy.set("fixture.default", true)
	done := make(chan error, 1)
	go func() { _, err := response.Body.Read(make([]byte, 1)); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revoked tunnel continued")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("quiet CONNECT survived denial")
	}
	waitForActiveUpstreams(t, &g.activeTCP, 0, "HTTP/2 CONNECT")
}
