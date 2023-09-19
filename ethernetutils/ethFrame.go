package ethernetutils

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type EthernetFrame struct {
	DestinationMAC [6]byte
	SourceMAC      [6]byte
	Type           uint16
	Payload        []byte
}

func (e *EthernetFrame) ParseEthernetFrame(data []byte) (*EthernetFrame, error) {
	//最小长度不能小于14
	if len(data) < 4 {
		return nil, fmt.Errorf("长度过小的以太帧")
	}
	frame := &EthernetFrame{
		DestinationMAC: [6]byte{data[0], data[1], data[2], data[3], data[4], data[5]},
		SourceMAC:      [6]byte{data[6], data[7], data[8], data[9], data[10], data[11]},
		Type:           uint16(data[12])<<8 | uint16(data[13]),
		Payload:        data[14:],
	}
	return frame, nil
}

func (e *EthernetFrame) IsEtherTypeIPv4() bool {
	if e.Type == 0x0800 {
		return true
	}
	return false
}

func ConvertEthLayerToEthFrame(ethLayer gopacket.Layer) (*EthernetFrame, error) {

	eth, ok := ethLayer.(*layers.Ethernet)
	if !ok {
		return nil, fmt.Errorf("not an Ethernet layer")
	}
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buffer, options, eth); err != nil {
		return nil, fmt.Errorf("error serializing ethernet layer: %v", err)
	}
	ethFrame := &EthernetFrame{}
	return ethFrame.ParseEthernetFrame(buffer.Bytes())
}
