package ipv4

import "fmt"

func ParseIPv4Packet(data []byte) error {

	if checksum(data) {
		return fmt.Errorf("failed to pass the checksum test")
	}

	header, err := ParseIPv4Header(data)
	if err != nil {
		return err
	}
	headerLength := int(header.IHL) * 4
	payload := data[headerLength:]

	switch header.Protocol {
	case ProtocolTCP:
		//tcpHeader, err := tcp.ParseTCPHeader(payload)
	case ProtocolUDP:

	case ProtocolICMP:
	}

	fmt.Println(header)
	fmt.Println(payload)
	return nil
}
