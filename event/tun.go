package event

import (
	"os"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
)

const (
	TUN         = 0
	TAP         = 1
	DevPoolSize = 10
)

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

type devState struct {
	InUse   bool
	DevType int
	Devname string
	Addr    *netlink.Addr
}

var devPool map[int]*devState = map[int]*devState{}

/*
devType: TUN or TAP
ifName: name of TUN/TAP device
network: cidr like 192.168.0.1/24
block: whether fd will be blocked
*/
func CreateTun(devType int, ifName, network string, block bool) (fd int, err error) {
	var link netlink.Link
	var addr *netlink.Addr
	var errno syscall.Errno
	var ifReq ifReq
	var ds *devState
	var openOpt int

	addr, err = netlink.ParseAddr(network)
	if err != nil {
		goto Error
	}

	for fd, ds = range devPool {
		if !ds.InUse && ds.DevType == devType {
			err = syscall.SetNonblock(fd, !block)
			if err != nil {
				continue
			}
			link, err = netlink.LinkByName(ds.Devname)
			if err != nil {
				continue
			}
			err = netlink.AddrAdd(link, addr)
			if err != nil {
				continue
			}
			ds.Addr = addr
			err = netlink.LinkSetName(link, ifName)
			if err != nil {
				continue
			}
			ds.Devname = ifName
			err = netlink.LinkSetUp(link)
			if err != nil {
				continue
			}
			ds.InUse = true
			return
		}
	}

	openOpt = syscall.O_RDWR
	if !block {
		openOpt |= syscall.O_NONBLOCK
	}
	if fd, err = syscall.Open(
		"/dev/net/tun", openOpt, 0); err != nil {
		goto Error
	}

	ifReq.Flags |= syscall.IFF_NO_PI
	if devType == TUN {
		ifReq.Flags |= syscall.IFF_TUN
	} else {
		ifReq.Flags |= syscall.IFF_TAP
	}
	copy(ifReq.Name[:], ifName)

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TUNSETIFF, uintptr(unsafe.Pointer(&ifReq)))
	if errno != 0 {
		err = os.NewSyscallError("ioctl", errno)
		goto Error
	}

	link, err = netlink.LinkByName(ifName)
	if err != nil {
		goto Error
	}

	addr, err = netlink.ParseAddr(network)
	if err != nil {
		goto Error
	}

	err = netlink.AddrAdd(link, addr)
	if err != nil {
		goto Error
	}

	err = netlink.LinkSetUp(link)
	if err == nil {
		devPool[fd] = &devState{InUse: true, DevType: devType, Devname: ifName, Addr: addr}
		return
	}
Error:
	syscall.Close(fd)
	return
}

func CloseTun(fd int) {
	if len(devPool) >= DevPoolSize {
		syscall.Close(fd)
		return
	}
	ds := devPool[fd]
	link, err := netlink.LinkByName(ds.Devname)
	if err != nil {
		goto Error
	}
	err = netlink.AddrDel(link, ds.Addr)
	if err != nil {
		goto Error
	}
	err = netlink.LinkSetDown(link)
	if err != nil {
		goto Error
	}
	ds.InUse = false
	return
Error:
	delete(devPool, fd)
	syscall.Close(fd)
}

func AddTunToEpoll(fd int32) error {
	return AddFileEvent(fd, tunReadHandler, nil, nil, syscall.EPOLLIN, TunIndex)
}

func tunReadHandler(fd int32) {
	fe, exist := FdProcs[fd]
	if !exist || fe.Err {
		return
	}
	fe.RBuf = make([]byte, RBufMaxLen)
	n, err := syscall.Read(int(fd), fe.RBuf)
	if err != nil {
		fe.Err = true
		return
	}
	fe.RLen = n
	if readCallback[fe.CallbackIndex] != nil {
		readCallback[fe.CallbackIndex](fe, fd)
	}
	fe.RLen = 0
	fe.RBuf = nil
}
