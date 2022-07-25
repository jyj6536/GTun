package icmputil

import (
	"net"

	"github.com/sirupsen/logrus"
)

var (
	Request    uint8 = 8
	Reply      uint8 = 0
	IcmpHLen   int   = 8
	ConnServer net.PacketConn
)

type ICMP struct {
	Type       uint8
	Code       uint8
	CheckSum   uint16
	Identifier uint16
	SeqNum     uint16
	Data       []byte
}

type IcmpData struct {
	Addr       net.Addr //remote addr to send
	IcmpPacket []byte   //well-formed icmp packet to send
}

var C chan *IcmpData = make(chan *IcmpData, 100)

func (icmp *ICMP) Construct(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	icmp.Type = data[0]
	icmp.Code = data[1]
	icmp.CheckSum = uint16(data[2])<<8 + uint16(data[3])
	icmp.Identifier = uint16(data[4])<<8 + uint16(data[5])
	icmp.SeqNum = uint16(data[6])<<8 + uint16(data[7])
	icmp.Data = append([]byte{}, data[IcmpHLen:]...)
	return true
}

func (icmp *ICMP) Create(_type uint8, code uint8, identifier uint16, seqNum uint16, data []byte) []byte {
	buf := make([]byte, IcmpHLen)
	buf[0] = _type
	buf[1] = code
	buf[4], buf[5] = byte(identifier>>8), byte(identifier&0x00ff)
	buf[6], buf[7] = byte(seqNum>>8), byte(seqNum&0x00ff)
	buf = append(buf, data...)
	checkSum := icmp.checkSum(buf)
	buf[2], buf[3] = byte(checkSum&0x00ff), byte(checkSum>>8)
	return buf
}

func (icmp *ICMP) checkSum(msg []byte) uint16 {
	csumcv := len(msg) - 1
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(msg[i+1])<<8 | uint32(msg[i])
	}
	if csumcv&1 == 0 {
		s += uint32(msg[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
}

func IcmpWrite(conn net.PacketConn, addr net.Addr, data []byte, dataLen int) error {
	for currLen := 0; currLen < dataLen; {
		n, err := conn.WriteTo(data[currLen:dataLen], addr)
		if err != nil {
			return err
		}
		currLen += n
	}
	return nil
}

func IcmpWriteClient(conn *net.IPConn, data []byte, dataLen int) error {
	for currLen := 0; currLen < dataLen; {
		n, err := conn.Write(data[currLen:dataLen])
		if err != nil {
			return err
		}
		currLen += n
	}
	return nil
}

func IcmpRead(conn net.PacketConn, buf []byte) (int, net.Addr, error) {
	return conn.ReadFrom(buf)
}

func WriteToConnServer() {
	for icmpData := range C {
		err := IcmpWrite(ConnServer, icmpData.Addr, icmpData.IcmpPacket, len(icmpData.IcmpPacket))
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Addr":  icmpData.Addr,
				"Error": err,
			}).Errorln("Icmp Write Error.")
		}
	}
}
