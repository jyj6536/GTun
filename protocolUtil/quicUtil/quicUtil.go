package quicutil

import (
	"crypto/tls"
	"encoding/binary"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"tunproject/cfgUtil"

	"github.com/lucas-clemente/quic-go"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

func GenerateTlsConfig(certPath, keyPath string) (*tls.Config, error) {
	cer, err := tls.LoadX509KeyPair(certPath, keyPath)
	return &tls.Config{Certificates: []tls.Certificate{cer}, NextProtos: []string{"quic-tunproject"}}, err
}

func ReadQUIC(stream quic.Stream, data []byte) (int, error) {
	dataLen := make([]byte, 4)
	len := 4
	currLen := 0
	for currLen < len {
		n, err := stream.Read(dataLen[currLen:4])
		if err != nil {
			return 0, err
		}
		currLen += n
	}
	len = int(binary.LittleEndian.Uint32(dataLen))
	currLen = 0
	for currLen < len {
		n, err := stream.Read(data[currLen:len])
		if err != nil {
			return 0, err
		}
		currLen += n
	}
	return len, nil
}

func WriteQUIC(stream quic.Stream, data []byte, dataLen int) error {
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(dataLen))
	len := 4
	currLen := 0
	for currLen < len {
		n, err := stream.Write(lenBuf[currLen:])
		if err != nil {
			return err
		}
		currLen += n
	}
	len = dataLen
	currLen = 0
	for currLen < len {
		n, err := stream.Write(data[currLen:len])
		if err != nil {
			return err
		}
		currLen += n
	}
	return nil
}

func ReadTunToQUIC(stream quic.Stream, iface *water.Interface, tuName string) {
	defer func() {
		stream.Close()
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
		err = stream.SetWriteDeadline(time.Now().Add(time.Second * 5))
		if err != nil {
			goto Stop
		}
		err = WriteQUIC(stream, buf, n)
		if err != nil {
			goto Stop
		}
	}
Stop:
	logrus.WithFields(logrus.Fields{
		"TuName": tuName,
		"Error":  err,
	}).Errorln("ReadTunToQUIC Error.")
}

func ReadQUICToTun(stream quic.Stream, iface *water.Interface, tuName string) {
	defer func() {
		stream.Close()
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
		err = stream.SetReadDeadline(time.Now().Add(time.Second * 5))
		if err != nil {
			goto Stop
		}
		n, err = ReadQUIC(stream, buf)
		if err != nil {
			if strings.Contains(err.Error(), "deadline exceeded") {
				continue
			}
			goto Stop
		}
		_, err := iface.Write(buf[:n])
		if err != nil {
			goto Stop
		}
	}
Stop:
	logrus.WithFields(logrus.Fields{
		"TuName": tuName,
		"Error":  err,
	}).Errorln("ReadQUICToTun Error.")
}

func ReadQUICToTunClient(stream quic.Stream, iface *water.Interface,timeout int) {
	defer func() {
		stream.Close()
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
		err = stream.SetReadDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
		if err != nil {
			goto Stop
		}
		n, err = ReadQUIC(stream, buf)
		if err != nil {
			if strings.Contains(err.Error(), "deadline exceeded") {
				continue
			}
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
	}).Errorln("ReadQUICToTunClient Error.")
}

func ReadTunToQUICClient(stream quic.Stream, iface *water.Interface,timeout int) {
	defer func() {
		stream.Close()
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

		err = stream.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
		if err != nil {
			goto Stop
		}
		err = WriteQUIC(stream, buf, n)
		if err != nil {
			goto Stop
		}
	}
Stop:
	logrus.WithFields(logrus.Fields{
		"Error": err,
	}).Errorln("ReadTunToQUICClient Error.")
}
