package main

import "testing"

func TestIsGarbage(t *testing.T) {
	tests := []struct {
		line     string
		expected bool
	}{
		{"Hello World", false},
		{"Just a normal line of text.", false},
		{string([]byte{0x00, 0x01, 0x02, 0x03}), true}, // Control chars
		{"DKIM Testing string with \x01", false},
	}

	for _, tt := range tests {
		if got := isGarbage(tt.line); got != tt.expected {
			t.Errorf("isGarbage(%q) = %v; want %v", tt.line, got, tt.expected)
		}
	}
}
