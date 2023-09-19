package ethernetutils

import (
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"testing"
)

func TestEthernetFrame_ParseEthernetFrame(t *testing.T) {
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packet, _ := packetSource.NextPacket()
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	eth, _ := ethLayer.(*layers.Ethernet)

	frame, _ := ConvertEthLayerToEthFrame(ethLayer)

	// Comparing SourceMAC
	if !bytes.Equal(frame.SourceMAC[:], eth.SrcMAC) {
		t.Errorf("SourceMAC mismatch. ParseEthernetFrame: %v, gopacket: %v", frame.SourceMAC, eth.SrcMAC)
	}

	// Comparing DestinationMAC
	if !bytes.Equal(frame.DestinationMAC[:], eth.DstMAC) {
		t.Errorf("DestinationMAC mismatch. ParseEthernetFrame: %v, gopacket: %v", frame.DestinationMAC, eth.DstMAC)
	}

	// Comparing Type
	if frame.Type != uint16(eth.EthernetType) {
		t.Errorf("Type mismatch. ParseEthernetFrame: %v, gopacket: %v", frame.Type, eth.EthernetType)
	}
}
