package tcp

import "testing"

func TestParseTCPHeader(t *testing.T) {
	//mock tcp header
	data := []byte{
		0x04, 0x57, // Source Port: 1111
		0x00, 0x50, // Destination Port: 80 (HTTP)
		0x12, 0x34, 0x56, 0x78, // Sequence Number: 305419896
		0x00, 0x00, 0x00, 0x00, // Acknowledgment Number: 0 (assuming SYN packet)
		0x50,       // Data Offset (5 words or 20 bytes) + Reserved (upper 3 bits of the second nibble)
		0x02,       // Flags: SYN set
		0xFF, 0xFF, // Window Size: 65535
		0xAB, 0xCD, // Checksum: arbitrary value
		0x00, 0x00, // Urgent Pointer: 0
		// Options and padding would follow, if present
	}
	header, err := ParseTCPHeader(data)
	if err != nil {
		t.Fatalf("Failed to Parse TCP: %v", err)
	}
	//Check the Source Port
	if header.SourcePort != 1111 {
		t.Fatalf("Expected Source Port 1111, got %d", header.SourcePort)
	}
	//Check the FLags
	if header.Flags != 0x02 {
		t.Fatalf("Expected Flags 0x02, got %d", header.Flags)
	}
	//Check the Window Size
	if header.WindowSize != 65535 {
		t.Fatalf("Expected Window Size 65535, got %d", header.WindowSize)
	}

}
