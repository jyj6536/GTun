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
	rCallback[event.UdpIndex] = udpReceive
}

func udpReceive(fe *event.FileEvent, fd int32) {
	p := cfgUtil.PacketDecode(fe.RBuf[:fe.RLen])
	if p == nil || cfgUtil.TunExist(p.TuName) == nil {
		return
	}
	addr := net.IP(fe.Addr.(*syscall.SockaddrInet4).Addr[:]).String() + ":" + strconv.Itoa(fe.Addr.(*syscall.SockaddrInet4).Port)
	key := addr + "+" + p.TuName
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
		nInfo.Te = event.AddTimeEvent(int64(cfgUtil.SCfg.UDP.BreakTime), tfd, udpTimeout)
		cfgUtil.AtoT[key] = nInfo
		cfgUtil.TtoN[int32(tfd)] = cfgUtil.TfdInfo{Nfd: fd, TuName: p.TuName, Addr: fe.Addr}
		cfgUtil.DataTransfer[p.TuName] = &helper.RingBuffer[[]byte]{}
	}
	nInfo.Te.When = event.GetCurrentTime() + int64(cfgUtil.SCfg.UDP.BreakTime)*1000
	if len(p.Frame) == 0 {
		syscall.Sendto(int(fd), fe.RBuf[:fe.RLen], 0, fe.Addr)
		return
	}
	syscall.Write(int(nInfo.Tfd), p.Frame)
}

func udpTimeout(v interface{}) {
	tfd := v.(int)
	tInfo := cfgUtil.TtoN[int32(tfd)]
	addr := net.IP(tInfo.Addr.(*syscall.SockaddrInet4).Addr[:]).String() + ":" + strconv.Itoa(tInfo.Addr.(*syscall.SockaddrInet4).Port)
	key := addr + "+" + tInfo.TuName
	delete(cfgUtil.TtoN, int32(tfd))
	delete(cfgUtil.AtoT, key)
	delete(cfgUtil.DataTransfer, tInfo.TuName)
	event.DelFileEvent(int32(tfd))
	event.CloseTun(tfd)
}
