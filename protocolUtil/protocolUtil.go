package protocolutil

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"tunproject/cfgUtil"
	icmputil "tunproject/protocolUtil/icmpUtil"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

func ReadTunToTcp(conn *net.TCPConn, iface *water.Interface, tuName string, timeout int) {
	defer func() {
		conn.Close()
		iface.Close()
	}()

	buf := make([]byte, 65536)
	var err error
	var n int
	for {
		n, err = iface.Read(buf)
		if err != nil {
			goto Stop
		}

		err = conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
		if err != nil {
			goto Stop
		}
		err = TcpWrite(*conn, buf, n)
		if err != nil {
			goto Stop
		}
	}
Stop:
	logrus.WithFields(logrus.Fields{
		"TuName": tuName,
		"Error":  err,
	}).Errorln("ReadTunToTcp Error.")
}

func ReadTcpToTun(conn *net.TCPConn, iface *water.Interface, tuName string) {
	defer func() {
		conn.Close()
		iface.Close()
		value, ok := cfgUtil.TunStsMap.Load(tuName)
		if !ok {
			return
		}
		tuSts := value.(*cfgUtil.TunnelSts)
		atomic.AddInt32(&tuSts.ActiveConn, -1)
		if atomic.LoadInt32(&tuSts.ActiveConn) == 0 {
			//tunutil.DelTun(tuSts.TunInfo.DeviceName) device will be removed after all of ifaces were closed
			cfgUtil.TunStsMap.Delete(tuName)
			logrus.WithFields(logrus.Fields{
				"Tuname": tuName,
			}).Debugln("Tunnel Finished.")
		}
	}()

	buf := make([]byte, 65536)
	var err error
	var n int
	for {
		n, err = TcpRead(*conn, buf)
		if err != nil {
			goto Stop
		}

		_, err = iface.Write(buf[:n])
		if err != nil {
			goto Stop
		}
	}
Stop:
	logrus.WithFields(logrus.Fields{
		"TuName": tuName,
		"Error":  err,
	}).Errorln("ReadTcpToTun Error.")
}

func ReadTunToTcpClient(conn *net.TCPConn, iface *water.Interface, timeout int) {
	defer func() {
		conn.Close()
		iface.Close()
	}()

	buf := make([]byte, 65536)
	var err error
	var n int
	for {
		n, err = iface.Read(buf)
		if err != nil {
			goto Stop
		}

		err = conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
		if err != nil {
			goto Stop
		}
		err = TcpWrite(*conn, buf, n)
		if err != nil {
			goto Stop
		}
	}
Stop:
	logrus.WithFields(logrus.Fields{
		"Error": err,
	}).Errorln("ReadTunToTcpClient Error.")
}

func ReadTcpToTunClient(conn *net.TCPConn, iface *water.Interface) {
	defer func() {
		conn.Close()
		iface.Close()
		atomic.AddInt32(&cfgUtil.TunStsClient.ActiveConn, -1)
		if cfgUtil.TunStsClient.ActiveConn == 0 {
			logrus.Debugln("Tunnel Finished.")
			syscall.Kill(os.Getpid(), syscall.SIGINT)
		}
	}()

	buf := make([]byte, 65536)
	var err error
	var n int
	for {
		n, err = TcpRead(*conn, buf)
		if err != nil {
			goto Stop
		}

		_, err = iface.Write(buf[:n])
		if err != nil {
			goto Stop
		}
	}
Stop:
	logrus.WithFields(logrus.Fields{
		"Error": err,
	}).Errorln("ReadTcpToTunClient Error.")
}

func ReadIcmpToTun(conn *net.IPConn, iface *water.Interface) {
	buf := make([]byte, 65536)
	icmp := &icmputil.ICMP{}

	for {
		n, err := conn.Read(buf)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("Read Icmp Error.")
			continue
		}
		ipHeadLen := int(uint8(buf[0]) & 0x0f * 4)
		if !icmp.Construct(buf[ipHeadLen:n]) {
			err = errors.New("bad icmp packet")
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("Bad Response.")
			continue
		}
		if icmp.Type != icmputil.Reply {
			continue
		}
		if len(icmp.Data) == 0 {
			continue
		}
		if icmp.Data[0] == 0x04 {
			value, ok := cfgUtil.IcmpTunStsCtrl.Load("ClientIcmpTimeoutCtrl")
			if ok {
				v := value.(*cfgUtil.IcmpTunCtrl)
				v.Time = time.Now()
			}
			continue
		}
		if icmp.Data[0] != 0x03 {
			continue
		}
		_, err = iface.Write(icmp.Data[1:])
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("Write Tun Error.")
			continue
		}
	}
}

func ReadTunToIcmp(conn *net.IPConn, iface *water.Interface, icmp *icmputil.ICMP, keepalive int) {
	buf := make([]byte, 65536)

	mutex := sync.Mutex{}

	go func() { //this go routine send 0x04 to server periodicity to keep alive
		ticker := time.NewTicker(time.Second * time.Duration(keepalive))
		for range ticker.C {
			mutex.Lock()
			data := icmp.Create(icmputil.Request, 0, icmp.Identifier, icmp.SeqNum, []byte{0x04})
			_, err := conn.Write(data)
			mutex.Unlock()
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"Error": err,
				}).Errorln("Write Icmp Error.")
				continue
			}
		}
	}()

	for {
		n, err := iface.Read(buf)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("Read Tun Errror.")
			continue
		}
		data := icmp.Create(icmputil.Request, 0, icmp.Identifier, icmp.SeqNum, append([]byte{0x03}, buf[:n]...))
		mutex.Lock()
		_, err = conn.Write(data)
		mutex.Unlock()
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("Write Icmp Error.")
			continue
		}
	}
}

func TcpRead(conn net.TCPConn, data []byte) (int, error) {
	dataLen := make([]byte, 4)
	len := 4
	currLen := 0
	for currLen < len {
		n, err := conn.Read(dataLen[currLen:4])
		if err != nil {
			return 0, err
		}
		currLen += n
	}
	len = int(binary.LittleEndian.Uint32(dataLen))
	currLen = 0
	for currLen < len {
		n, err := conn.Read(data[currLen:len])
		if err != nil {
			return 0, err
		}
		currLen += n
	}
	return len, nil
}

func TcpWrite(conn net.TCPConn, data []byte, dataLen int) error {
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(dataLen))
	len := 4
	currLen := 0
	for currLen < len {
		n, err := conn.Write(lenBuf[currLen:])
		if err != nil {
			return err
		}
		currLen += n
	}
	len = dataLen
	currLen = 0
	for currLen < len {
		n, err := conn.Write(data[currLen:len])
		if err != nil {
			return err
		}
		currLen += n
	}
	return nil
}

func SetTcpKeepalive(keepalive int, conn *net.TCPConn) error {
	err := conn.SetKeepAlive(true)
	if err != nil {
		return err
	}
	err = conn.SetKeepAlivePeriod(time.Second * time.Duration(keepalive))
	return err
}
