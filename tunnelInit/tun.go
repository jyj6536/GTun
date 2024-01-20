package tunnelInit

import (
	"syscall"
	"tunproject/cfgUtil"
	"tunproject/event"
)

func init() {
	rCallback[event.TunIndex] = tunReceive
}

func tunReceive(fe *event.FileEvent, fd int32) {
	tInfo := cfgUtil.TtoN[fd]
	if tInfo.Addr != nil { //for connectionless protocol like icmp and udp
		p := cfgUtil.PacketEncode(tInfo.TuName, fe.RBuf[:fe.RLen])
		if p == nil {
			return
		}
		if tInfo.IcmpSrc != nil {
			p = event.IcmpCreate(event.Reply, 0, tInfo.IcmpSrc.Identifier, tInfo.IcmpSrc.SeqNum, p)
		}
		syscall.Sendto(int(tInfo.Nfd), p, 0, tInfo.Addr)
		return
	}
	//for tcp and unix
	rb := cfgUtil.DataTransfer[tInfo.TuName]
	rb.Write(fe.RBuf[:fe.RLen])
	event.EnableEpollout(tInfo.Nfd)
}
