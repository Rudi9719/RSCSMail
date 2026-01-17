package main

import "testing"

func TestResolveNode(t *testing.T) {
	originalConfig := config
	defer func() { config = originalConfig }()

	config = Config{
		Server: ServerConfig{
			Domain: "example.org",
		},
		Routing: RoutingConfig{
			RSCSNode: "EXAMPLE",
		},
	}

	tests := []struct {
		domain       string
		expectedNode string
	}{
		{"example.org", "EXAMPLE"},
		{"EXAMPLE.ORG", "EXAMPLE"},
		{"other.com", ""},
		{"unknown.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if got := resolveNode(tt.domain); got != tt.expectedNode {
				t.Errorf("resolveNode(%q) = %q; want %q", tt.domain, got, tt.expectedNode)
			}
		})
	}
}
