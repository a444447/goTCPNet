package ipv4

import (
	"net"
	"testing"
)

func TestParseIPv4Header(t *testing.T) {
	// Mock IPv4 header data
	data := []byte{
		0x45,       // Version: 4, IHL: 5 (20 bytes header, no options)
		0x00,       // DSCP: 0, ECN: 0
		0x00, 0x3C, // Total Length: 60 bytes (including header)
		0x12, 0x34, // Identification: 0x1234
		0x40, 0x00, // Flags: Don't Fragment, Fragment Offset: 0
		0x40,       // TTL: 64
		0x06,       // Protocol: TCP (6)
		0xAB, 0xCD, // Header Checksum: 0xABCD (mock value, not calculated)
		192, 168, 1, 1, // Source IP: 192.168.1.1
		192, 168, 1, 100, // Destination IP: 192.168.1.100
	}
	header, err := ParseIPv4Header(data)
	if err != nil {
		t.Fatalf("Failed to Parse IPv4: %v", err)
	}

	// Check the Version
	if header.Version != 4 {
		t.Errorf("Expected Version 4, got %d", header.Version)
	}

	// Check the IHL
	if header.IHL != 5 { // assuming no options, so IHL should be 5
		t.Errorf("Expected IHL 5, got %d", header.IHL)
	}

	// Check the Length
	if header.Length != 60 {
		t.Errorf("Expected TOS 60, got %d", header.TOS)
	}

	// Check the Source IP
	expectedSrcIP := net.IPv4(192, 168, 1, 1) // replace with the expected IP from your sample data
	if !header.SrcIP.Equal(expectedSrcIP) {
		t.Errorf("Expected SrcIP %v, got %v", expectedSrcIP, header.SrcIP)
	}
}
