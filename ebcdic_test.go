package main

import (
	"bytes"
	"testing"
)

func TestToEbcdic(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{"A", []byte{0xC1}},
		{"1", []byte{0xF1}},
		{" ", []byte{0x40}},
		{"ABC", []byte{0xC1, 0xC2, 0xC3}},
	}

	for _, tt := range tests {
		result := toEbcdic(tt.input)
		if !bytes.Equal(result, tt.expected) {
			t.Errorf("toEbcdic(%q) = %X; want %X", tt.input, result, tt.expected)
		}
	}
}

func TestWriteEbcdicRecord(t *testing.T) {
	var buf bytes.Buffer
	control := []byte{0x40}
	content := "TEST"

	writeEbcdicRecord(&buf, control, content)

	if buf.Len() != 80 {
		t.Errorf("Expected buffer length 80, got %d", buf.Len())
	}

	bytes := buf.Bytes()
	if bytes[0] != 0x40 {
		t.Errorf("Expected control byte 0x40, got 0x%X", bytes[0])
	}
	expectedContent := []byte{0xE3, 0xC5, 0xE2, 0xE3}
	if !bytesEqual(bytes[1:5], expectedContent) {
		t.Errorf("Content mismatch. Got %X", bytes[1:5])
	}

	buf.Reset()
	longContent := ""
	for i := 0; i < 80; i++ {
		longContent += "A"
	}

	writeEbcdicRecord(&buf, control, longContent)

	if buf.Len() != 160 {
		t.Errorf("Expected buffer length 160, got %d", buf.Len())
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
