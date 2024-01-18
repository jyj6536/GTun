package tunnelInit

import (
	"net"
	"strconv"
	"syscall"
	"tunproject/cfgUtil"
	"tunproject/event"
	"tunproject/helper"
)

func init() {
	rCallback[event.IcmpIndex] = icmpReceive
}

func icmpReceive(fe *event.FileEvent, fd int32) {
	icmp := event.IcmpConstruct(fe.RBuf[:fe.RLen])
	if icmp == nil || icmp.Type != event.Request {
		return
	}
	p := cfgUtil.PacketDecode(icmp.Data)
	if p == nil || cfgUtil.TunExist(p.TuName) == nil {
		rsp := event.IcmpCreate(event.Reply, 0, icmp.Identifier, icmp.SeqNum, icmp.Data)
		syscall.Sendto(int(fd), rsp, 0, fe.Addr)
		return
	}
	addr := net.IP(fe.Addr.(*syscall.SockaddrInet4).Addr[:]).String()
	key := addr + "+" + strconv.FormatUint(uint64(icmp.Identifier), 10) + p.TuName
	nInfo, exist := cfgUtil.AtoT[key]
	if !exist {
		tCfg := cfgUtil.TunExist(p.TuName)
		if _, exist := cfgUtil.DataTransfer[p.TuName]; exist {
			return
		}
		var deviceType int
		if tCfg.DeviceType == "tun" {
			deviceType = event.TUN
		} else {
			deviceType = event.TAP
		}
		tfd, err := event.CreateTun(deviceType, tCfg.DeviceName, tCfg.Network, false)
		if err != nil {
			return
		}
		err = event.AddTunToEpoll(int32(tfd))
		if err != nil {
			return
		}
		nInfo.Tfd = int32(tfd)
		nInfo.TuName = p.TuName
		nInfo.Te = event.AddTimeEvent(int64(cfgUtil.SCfg.ICMP.BreakTime), tfd, timeoutHandler)
		cfgUtil.AtoT[key] = nInfo
		cfgUtil.TtoN[int32(tfd)] = cfgUtil.TfdInfo{Nfd: fd, TuName: p.TuName, Addr: fe.Addr, IcmpSrc: icmp}
		cfgUtil.DataTransfer[p.TuName] = &helper.RingBuffer[[]byte]{}
	}
	if len(p.Frame) == 0 {
		rsp := event.IcmpCreate(event.Reply, 0, icmp.Identifier, icmp.SeqNum, icmp.Data)
		syscall.Sendto(int(fd), rsp, 0, fe.Addr)
	}
	nInfo.Te.When = event.GetCurrentTime() + int64(cfgUtil.SCfg.ICMP.BreakTime)*1000
	syscall.Write(int(nInfo.Tfd), p.Frame)
}

func timeoutHandler(v interface{}) {
	tfd := v.(int)
	tInfo := cfgUtil.TtoN[int32(tfd)]
	addr := net.IP(tInfo.Addr.(*syscall.SockaddrInet4).Addr[:]).String()
	key := addr + "+" + strconv.FormatUint(uint64(tInfo.IcmpSrc.Identifier), 10) + tInfo.TuName
	delete(cfgUtil.TtoN, int32(tfd))
	delete(cfgUtil.AtoT, key)
	delete(cfgUtil.DataTransfer, tInfo.TuName)
	event.DelFileEvent(int32(tfd))
	event.CloseTun(tfd)
}
