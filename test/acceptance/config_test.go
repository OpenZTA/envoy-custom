package acceptance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionFiltersRejectAuthorizationBypasses(t *testing.T) {
	image := os.Getenv("OPENZTA_ENVOY_IMAGE")
	if image == "" {
		t.Skip("set OPENZTA_ENVOY_IMAGE to validate the native production factories")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	_, ca, cert, key := testPKI(t, dir)
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	find := func(config map[string]any, kind string) map[string]any {
		t.Helper()
		var walk func(any) map[string]any
		walk = func(value any) map[string]any {
			switch value := value.(type) {
			case map[string]any:
				if value["@type"] == "type.googleapis.com/openzta.extensions.filters.continuous_authz.v1."+kind+"ContinuousAuthz" {
					return value
				}
				for _, child := range value {
					if found := walk(child); found != nil {
						return found
					}
				}
			case []any:
				for _, child := range value {
					if found := walk(child); found != nil {
						return found
					}
				}
			}
			return nil
		}
		found := walk(config)
		if found == nil {
			t.Fatalf("missing %s authorization factory", kind)
		}
		return found
	}
	tests := []struct {
		name   string
		kind   string
		change func(map[string]any)
	}{
		{"valid", "Http", func(map[string]any) {}},
		{"missing-resource-binding", "Http", func(c map[string]any) { delete(c, "resource_host") }},
		{"invalid-resource-binding", "Http", func(c map[string]any) { c["resource_host"] = "app.example/other" }},
		{"route-cache-clearing", "Http", func(c map[string]any) { c["authorization"].(map[string]any)["clear_route_cache"] = true }},
		{"reserved-host-override", "Http", func(c map[string]any) {
			c["authorization"].(map[string]any)["http_service"].(map[string]any)["authorization_request"] = map[string]any{"headers_to_add": []any{map[string]any{"key": "X-Original-Host", "value": "%REQ(:AUTHORITY)%"}}}
		}},
		{"http-fail-open", "Http", func(c map[string]any) { c["authorization"].(map[string]any)["failure_mode_allow"] = true }},
		{"network-fail-open", "Network", func(c map[string]any) { c["authorization"].(map[string]any)["failure_mode_allow"] = true }},
		{"http-body-buffering", "Http", func(c map[string]any) {
			c["authorization"].(map[string]any)["with_request_body"] = map[string]any{"max_request_bytes": 1024}
		}},
		{"http-raw-headers", "Http", func(c map[string]any) { c["authorization"].(map[string]any)["encode_raw_headers"] = true }},
		{"http-runtime-bypass", "Http", func(c map[string]any) {
			c["authorization"].(map[string]any)["filter_enabled"] = map[string]any{"default_value": map[string]any{"numerator": 100, "denominator": "HUNDRED"}}
		}},
		{"http-zero-recheck", "Http", func(c map[string]any) { c["recheck"].(map[string]any)["interval"] = "0s" }},
		{"network-zero-recheck", "Network", func(c map[string]any) { c["recheck"].(map[string]any)["interval"] = "0s" }},
		{"negative-jitter", "Http", func(c map[string]any) { c["recheck"].(map[string]any)["jitter"] = "-1s" }},
		{"submillisecond-negative-jitter", "Http", func(c map[string]any) { c["recheck"].(map[string]any)["jitter"] = "-0.000000001s" }},
		{"negative-lifetime", "Network", func(c map[string]any) { c["recheck"].(map[string]any)["max_session_duration"] = "-1s" }},
		{"submillisecond-lifetime", "Network", func(c map[string]any) { c["recheck"].(map[string]any)["max_session_duration"] = "0.000000001s" }},
		{"malformed-authorization-path", "Http", func(c map[string]any) {
			c["authorization"].(map[string]any)["http_service"].(map[string]any)["path_prefix"] = "not-an-absolute-path"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := gatewayConfig(9, 9, 9, 9, 9, filepath.Base(ca), filepath.Base(cert), filepath.Base(key))
			test.change(find(config, test.kind))
			data, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "validate.json"), data, 0644); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("docker", "run", "--rm", "--add-host", "host.docker.internal:host-gateway", "-v", dir+":/test:ro", image, "--mode", "validate", "--concurrency", "1", "-c", "/test/validate.json")
			output, err := command.CombinedOutput()
			if test.name == "valid" {
				if err != nil {
					t.Fatalf("valid production factory configuration failed: %v\n%s", err, output)
				}
				return
			}
			if err == nil {
				t.Fatalf("authorization bypass was accepted: %s", test.name)
			}
			if !strings.Contains(strings.ToLower(string(output)), "continuous_authz") && !strings.Contains(strings.ToLower(string(output)), "validation") {
				t.Fatalf("validation failed for an unrelated reason: %v\n%s", err, output)
			}
		})
	}
}
