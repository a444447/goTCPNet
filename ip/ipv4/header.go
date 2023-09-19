package ipv4

import (
	"errors"
	"fmt"
	"net"
)

const (
	ProtocolICMP = 1
	ProtocolTCP  = 6
	ProtocolUDP  = 17
)

type IPv4Header struct {
	Version  uint8  //4bit
	IHL      uint8  //表示头部的长度 4bit
	TOS      uint8  //Type of Service 8bits
	Length   uint16 // 16bits
	ID       uint16 // 16bits
	FLags    uint8  // 3bits
	Offset   uint16 //13bits
	TTL      uint8  //8bits
	Protocol uint8  //8bits
	Checksum uint16 //16 bits
	SrcIP    net.IP //32 bits
	DescIP   net.IP //32 bits
	Options  []byte
}

func ParseIPv4Header(data []byte) (*IPv4Header, error) {
	//将[]byte反序列化为ipv4header结构
	//一个ipv4头部，除去options部分之外，至少需要160bits,也就是160/8=20bytes
	if len(data) < 20 {
		return nil, fmt.Errorf("IPv4头部不能小于20字节")
	}

	header := &IPv4Header{
		Version:  data[0] >> 4,   //实际的version是 4bits，我们在序列化的过程中，将version << 4 | IHL
		IHL:      data[0] & 0x0F, //将data[0]与00001111作与操作，使得前4位 置0，后4位不变
		TOS:      data[1],
		Length:   uint16(data[2])<<8 | uint16(data[3]),
		ID:       uint16(data[4])<<8 | uint16(data[5]),
		FLags:    data[6] >> 5,
		Offset:   uint16(data[6])<<8 | uint16(data[7])&0x1FFF, // &00011111 11111111
		TTL:      data[8],
		Protocol: data[9],
		Checksum: uint16(data[10])<<8 | uint16(data[11]),
		SrcIP:    net.IP(data[12:16]),
		DescIP:   net.IP(data[16:20]),
	}

	headerLength := int(header.IHL) * 4 //IHL的单位是32bits，比如说IHL=5,表示是5 * 32bits,也就是5 * 4bytes
	if headerLength > 20 {
		if len(data) < headerLength {
			return nil, errors.New("IPv4头部太短")
		}
		header.Options = data[20:headerLength]
	}

	return header, nil
}

/*
我们知道IPv4的报头的长度一般为20bytes，而checksum的长度为16bits（2bytes）。下面我用一个例子来讲解计算过程：
假设某个IPv4数据包报头为：E3 4F 23 96 44 27 99 F3 [00 00]，注意，用中括号括起来的就是checksum

checksum的初始值自动被设置为0
然后，以16bit为单位，两两相加，对于该例子，即为：E34F + 2396 + 4427 + 99F3 = 1E4FF
若计算结果大于0xFFFF，则将，高16位加到低16位上，对于该例子，即为，0xE4FF + 0x0001 = E500
然后，将该值取反，即为~(E500)=1AFF
此时，发送包已经计算完毕，下面，我们再来计算接收方的信息

若数据包正常，那么，它的报头应该是这样 ，E3 4F 23 96 44 27 99 F3 1A FF
此时，前18bytes的内容不变，等于E500，然后，将E500与刚刚计算的校验和1AFF相加
若计算结果为0xFFFF，那么，该数据包正常，没有错误
*/

func checksum(data []byte) bool {
	sum := uint32(0)
	//16bits为单位，两两相加
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			sum += uint32(data[i])<<8 | uint32(data[i+1])
		} else {
			sum += uint32(data[i]) << 8
		}
	}
	//若计算结果大于0xFFFF，则将，高16位加到低16位上
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	res := uint16(^sum)
	return res == 0xFFFF
}

func (i *IPv4Header) isFragmented(header *IPv4Header) bool {
	return (header.FLags&1<<1) != 0 || header.Offset != 0 //
}

func (i *IPv4Header) Serialize() ([]byte, error) {

	return nil, nil
}
