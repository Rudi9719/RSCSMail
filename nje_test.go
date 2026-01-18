package main

import "testing"

func TestParseAddress(t *testing.T) {
	tests := []struct {
		input        string
		expectedUser string
		expectedNode string
	}{
		{"user@node", "user", "node"},
		{"user", "user", ""},
		{"user@node@extra", "user", "node"},
		{"", "", ""},
	}

	for _, tt := range tests {
		u, n := parseAddress(tt.input)
		if u != tt.expectedUser || n != tt.expectedNode {
			t.Errorf("parseAddress(%q) = %q, %q; want %q, %q", tt.input, u, n, tt.expectedUser, tt.expectedNode)
		}
	}
}

func TestDeriveNJEFilename(t *testing.T) {
	tests := []struct {
		email      string
		expectedFn string
		expectedFt string
	}{
		{"user@node.com", "USER", "NODE"},
		{"longusername@node.com", "LONGUSER", "NODE"},
		{"short@node.com", "SHORT", "NODE"},
		{"us#er@no-de.com", "USER", "NODE"},
		{"user@long-and-ugly-domain.com", "USER", "LONGANDU"},
	}

	for _, tt := range tests {
		fn, ft := deriveNJEFilename(tt.email)
		if fn != tt.expectedFn || ft != tt.expectedFt {
			t.Errorf("deriveNJEFilename(%q) = %q, %q; want %q, %q", tt.email, fn, ft, tt.expectedFn, tt.expectedFt)
		}
	}
}

func TestIsValidCMSUser(t *testing.T) {
	tests := []struct {
		user     string
		expected bool
	}{
		{"user", true},
		{"USER", true},
		{"u123", true},
		{"root", false},
		{"operator", false},
		{"system", false},
		{"toolongusername", false},
		{"inv@lid", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := isValidCMSUser(tt.user); got != tt.expected {
			t.Errorf("isValidCMSUser(%q) = %v; want %v", tt.user, got, tt.expected)
		}
	}
}
