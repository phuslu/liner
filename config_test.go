package main

import (
	"encoding/json"
	"testing"

	"github.com/goccy/go-yaml"
)

func TestHTTPConfigTcpNotsentLowat(t *testing.T) {
	var fromYAML HTTPConfig
	if err := yaml.Unmarshal([]byte("forward:\n  tcp_notsent_lowat: 65536\n"), &fromYAML); err != nil {
		t.Fatal(err)
	}
	if got := fromYAML.Forward.TcpNotsentLowat; got != 65536 {
		t.Fatalf("yaml tcp_notsent_lowat = %d, want 65536", got)
	}

	var fromJSON HTTPConfig
	if err := json.Unmarshal([]byte(`{"forward":{"tcp_notsent_lowat":65536}}`), &fromJSON); err != nil {
		t.Fatal(err)
	}
	if got := fromJSON.Forward.TcpNotsentLowat; got != 65536 {
		t.Fatalf("json tcp_notsent_lowat = %d, want 65536", got)
	}
}
