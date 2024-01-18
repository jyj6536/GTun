package tunnelInit

import (
	"syscall"
	"tunproject/cfgUtil"
	"tunproject/event"
	"tunproject/helper"
)

func init() {
	rCallback[event.TcpIndex] = tcpRceive
	wCallback[event.TcpIndex] = tcpSend
	eCallback[event.TcpIndex] = tcpError
}

func tcpRceive(fe *event.FileEvent, fd int32) {
	p := cfgUtil.PacketDecode(fe.RBuf)
	if p == nil {
		fe.Err = true
		return
	}
	var exist bool
	var nInfo cfgUtil.NfdInfo
	var tCfg *cfgUtil.TunnelCfg
	nInfo, exist = cfgUtil.NtoT[fd]
	if !exist {
		tCfg = cfgUtil.TunExist(p.TuName)
		if tCfg == nil {
			fe.Err = true
			return
		}
		if _, exist := cfgUtil.DataTransfer[p.TuName]; exist {
			fe.Err = true
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
			fe.Err = true
			return
		}
		nInfo.Tfd = int32(tfd)
		nInfo.TuName = p.TuName
		cfgUtil.NtoT[fd] = nInfo
		cfgUtil.TtoN[int32(tfd)] = cfgUtil.TfdInfo{Nfd: fd, TuName: p.TuName}
		cfgUtil.DataTransfer[p.TuName] = helper.RingBufferCreate[[]byte](1000)
		err = event.AddTunToEpoll(int32(tfd))
		if err != nil {
			fe.Err = true
			return
		}
	}
	if len(p.Frame) == 0 {
		return
	}
	_, err := syscall.Write(int(nInfo.Tfd), p.Frame)
	if err != nil && err != syscall.EAGAIN {
		fe.Err = true
	}
}

func tcpSend(fe *event.FileEvent, fd int32) {
	nInfo := cfgUtil.NtoT[fd]
	rb := cfgUtil.DataTransfer[nInfo.TuName]
	if !rb.IsEmpty() {
		if fe.WBuf != nil {
			fe.MoreToSend = true
			return
		}
		frame, _ := rb.Read()
		p := cfgUtil.PacketEncode(nInfo.TuName, frame)
		fe.WBuf = p
		if !rb.IsEmpty() {
			fe.MoreToSend = true
		}
	}
}

func tcpError(fe *event.FileEvent, fd int32) {
	tInfo, exist := cfgUtil.NtoT[fd]
	if exist {
		event.DelFileEvent(tInfo.Tfd)
		event.CloseTun(int(tInfo.Tfd))
		delete(cfgUtil.TtoN, tInfo.Tfd)
		delete(cfgUtil.DataTransfer, tInfo.TuName)
		delete(cfgUtil.NtoT, fd)
	}
	event.DelFileEvent(fd)
	syscall.Close(int(fd))
}
