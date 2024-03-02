package event

import (
	"net"
	"syscall"
)

func UdpListenerInit(ip string, port int) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return err
	}

	addr := syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], net.ParseIP(ip))

	err = syscall.Bind(fd, &addr)
	if err != nil {
		return err
	}

	return AddFileEvent(int32(fd), udpReadHandler, nil, nil, syscall.EPOLLIN, UdpIndex)
}

func udpReadHandler(fd int32) {
	fe, exist := FdProcs[fd]
	if !exist {
		return
	}
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
}
