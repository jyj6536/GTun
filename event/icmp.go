package event

import (
	"net"
	"syscall"
)

var (
	Request  uint8 = 8
	Reply    uint8 = 0
	IcmpHLen int   = 8
)

type ICMP struct {
	Type       uint8
	Code       uint8
	CheckSum   uint16
	Identifier uint16
	SeqNum     uint16
	Data       []byte
}

func IcmpCreate(_type uint8, code uint8, identifier uint16, seqNum uint16, data []byte) []byte {
	buf := make([]byte, IcmpHLen)
	buf[0] = _type
	buf[1] = code
	buf[4], buf[5] = byte(identifier>>8), byte(identifier&0x00ff)
	buf[6], buf[7] = byte(seqNum>>8), byte(seqNum&0x00ff)
	buf = append(buf, data...)
	checkSum := checkSum(buf)
	buf[2], buf[3] = byte(checkSum&0x00ff), byte(checkSum>>8)
	return buf
}

func IcmpConstruct(data []byte) *ICMP {
	ipHeadLen := int(uint8(data[0]) & 0x0f * 4)
	data = data[ipHeadLen:]
	icmp := &ICMP{}
	if len(data) < 8 {
		return nil
	}
	icmp.Type = data[0]
	icmp.Code = data[1]
	icmp.CheckSum = uint16(data[2])<<8 + uint16(data[3])
	icmp.Identifier = uint16(data[4])<<8 + uint16(data[5])
	icmp.SeqNum = uint16(data[6])<<8 + uint16(data[7])
	icmp.Data = append([]byte{}, data[IcmpHLen:]...)
	return icmp
}

func checkSum(msg []byte) uint16 {
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

func IcmpListenerInit(ip string) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return err
	}

	addr := syscall.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], net.ParseIP(ip))

	err = syscall.Bind(fd, &addr)
	if err != nil {
		return err
	}

	return AddFileEvent(int32(fd), icmpReadHandler, nil, nil, syscall.EPOLLIN, IcmpIndex)
}

func icmpReadHandler(fd int32) {
	fe, exist := FdProcs[fd]
	if !exist {
		return
	}
	fe.RBuf = make([]byte, RBufMaxLen)
	n, addr, err := syscall.Recvfrom(int(fd), fe.RBuf, 0)
	if err != nil {
		return
	}
	fe.RLen = n
	fe.Addr = addr
	if readCallback[fe.CallbackIndex] != nil {
		readCallback[fe.CallbackIndex](fe, fd)
	}
	fe.RLen = 0
	fe.RBuf = nil
}
