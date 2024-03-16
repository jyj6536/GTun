package tunnelInit

import (
	"syscall"
	"tunproject/cfgUtil"
	"tunproject/event"
	"tunproject/helper"

	"github.com/sirupsen/logrus"
)

func init() {
	rCallback[event.UnixIndex] = unixReceive
	wCallback[event.UnixIndex] = unixSend
	eCallback[event.UnixIndex] = unixError
}

func unixReceive(fe *event.FileEvent, fd int32) {
	p := cfgUtil.PacketDecode(fe.RBuf[:fe.RLen])
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
		nInfo.Te = event.AddTimeEvent(int64(cfgUtil.SCfg.QUIC.BreakTime), tfd, unixTimeout)
		cfgUtil.NtoT[fd] = nInfo
		cfgUtil.TtoN[int32(tfd)] = cfgUtil.TfdInfo{Nfd: fd, TuName: p.TuName}
		cfgUtil.DataTransfer[p.TuName] = helper.RingBufferCreate[[]byte](1000)
		err = event.AddTunToEpoll(int32(tfd))
		if err != nil {
			fe.Err = true
			return
		}
		logrus.WithFields(logrus.Fields{
			"TuName": nInfo.TuName,
		}).Infoln("Tunnel Created.")
	}
	nInfo.Te.When = event.GetCurrentTime() + int64(cfgUtil.SCfg.QUIC.BreakTime)*1000
	if len(p.Frame) == 0 {
		return
	}
	_, err := syscall.Write(int(nInfo.Tfd), p.Frame)
	if err != nil && err != syscall.EAGAIN {
		fe.Err = true
	}
}

func unixSend(fe *event.FileEvent, fd int32) {
	nInfo := cfgUtil.NtoT[fd]
	rb := cfgUtil.DataTransfer[nInfo.TuName]
	if !rb.IsEmpty() {
		frame, _ := rb.Read()
		p := cfgUtil.PacketEncode(nInfo.TuName, frame)
		fe.WBuf = p
		if !rb.IsEmpty() {
			fe.MoreToSend = true
		} else {
			fe.MoreToSend = false
		}
	}
}

func unixError(fe *event.FileEvent, fd int32) {
	nInfo, exist := cfgUtil.NtoT[fd]
	if exist {
		event.DelFileEvent(nInfo.Tfd)
		event.CloseTun(int(nInfo.Tfd))
		delete(cfgUtil.TtoN, nInfo.Tfd)
		delete(cfgUtil.DataTransfer, nInfo.TuName)
		delete(cfgUtil.NtoT, fd)
	}
	event.DelFileEvent(fd)
	syscall.Close(int(fd))
}

func unixTimeout(v interface{}) {
	tfd := v.(int)
	tInfo := cfgUtil.TtoN[int32(tfd)]
	delete(cfgUtil.TtoN, int32(tfd))
	delete(cfgUtil.NtoT, tInfo.Nfd)
	delete(cfgUtil.DataTransfer, tInfo.TuName)
	event.DelFileEvent(int32(tfd))
	event.CloseTun(tfd)
	logrus.WithFields(logrus.Fields{
		"TuName": tInfo.TuName,
	}).Infoln("Tunnel has been closed because of timeout.")
}
