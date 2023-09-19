package tcp

import (
	"encoding/binary"
	"fmt"
)

type TCPHeader struct {
	SourcePort           uint16
	DestinationPort      uint16
	SequenceNumber       uint32
	AcknowledgmentNumber uint32
	DataOffset           uint8 // Only the upper 4 bits
	Reserved             uint8 // Only the upper 3 bits
	Flags                uint8 // Only the lower 9 bits
	WindowSize           uint16
	Checksum             uint16
	UrgentPointer        uint16
	Options              []byte // Variable length
	Padding              []byte // padding用0填充。因为options是不确定的，为了保证tcp header是32位(4字节）的倍数，因此需要padding
}

func ParseTCPHeader(data []byte) (*TCPHeader, error) {
	if len(data) < 20 { //TCP header的最小长度为20bytes
		return nil, fmt.Errorf("TCP header长度未达到要求")
	}
	header := &TCPHeader{
		SourcePort:           uint16(data[0])<<8 | uint16(data[1]),
		DestinationPort:      uint16(data[2])<<8 | uint16(data[3]),
		SequenceNumber:       binary.BigEndian.Uint32(data[4:8]),
		AcknowledgmentNumber: binary.BigEndian.Uint32(data[8:12]),
		DataOffset:           data[12] >> 4,
		Reserved:             data[12] & 0x0F,
		Flags:                data[13],
		WindowSize:           uint16(data[14])<<8 | uint16(data[15]),
		Checksum:             uint16(data[16])<<8 | uint16(data[17]),
		UrgentPointer:        uint16(data[18])<<8 | uint16(data[19]),
	}
	headerLength := int(header.DataOffset) * 4
	if headerLength > 20 {
		header.Options = data[20:headerLength]
	}
	return header, nil

}

func (t *TCPHeader) Serialize() ([]byte, error) {
	return nil, nil
}
