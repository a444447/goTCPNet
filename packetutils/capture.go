package packetutils

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gotcpNet/ethernetutils"
	"log"
)

func CapturePacket(packetNumber int) {
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for i := 0; i < packetNumber; i++ {
		packet, err := packetSource.NextPacket()
		fmt.Println(packet)
		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			ethFrame, _ := ethernetutils.ConvertEthLayerToEthFrame(ethLayer)
			fmt.Println(ethFrame.DestinationMAC)
		}
		if err != nil {
			log.Println("Error capturing packet:", err)
			continue
		}
		//fmt.Println(packet)
	}
}
