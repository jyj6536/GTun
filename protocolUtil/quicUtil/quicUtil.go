package quicutil

import (
	"crypto/tls"
	"encoding/binary"
	"strings"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

func GenerateTlsConfig(certPath, keyPath string) (*tls.Config, error) {
	cer, err := tls.LoadX509KeyPair(certPath, keyPath)
	return &tls.Config{Certificates: []tls.Certificate{cer}, NextProtos: []string{"quic-tunproject"}}, err
}

func ReadQUIC(stream quic.Stream, data []byte, timeout int) (int, error) {
	dataLen := make([]byte, 4)
	len := 4
	currLen := 0
	for currLen < len {
		if timeout > 0 {
			err := stream.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
			if err != nil {
				return 0, err
			}
		}
		n, err := stream.Read(dataLen[currLen:4])
		if err != nil {
			return 0, err
		}
		currLen += n
	}
	len = int(binary.LittleEndian.Uint32(dataLen))
	currLen = 0
	for currLen < len {
		if timeout > 0 {
			err := stream.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
			if err != nil {
				return 0, err
			}
		}
		n, err := stream.Read(data[currLen:len])
		if err != nil {
			return 0, err
		}
		currLen += n
	}

	//reset readdeadline for quic stream
	if timeout > 0 {
		err := stream.SetReadDeadline(time.Time{})
		if err != nil {
			return 0, err
		}
	}
	return len, nil
}

func WriteQUIC(stream quic.Stream, data []byte, dataLen int, timeout int) error {
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(dataLen))
	len := 4
	currLen := 0
	for currLen < len {
		if timeout > 0 {
			err := stream.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
			if err != nil {
				return err
			}
		}
		n, err := stream.Write(lenBuf[currLen:])
		if err != nil {
			return err
		}
		currLen += n
	}
	len = dataLen
	currLen = 0
	for currLen < len {
		if timeout > 0 {
			err := stream.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
			if err != nil {
				return err
			}
		}
		n, err := stream.Write(data[currLen:len])
		if err != nil {
			return err
		}
		currLen += n
	}

	//reset writedeadline for quic stream
	if timeout > 0 {
		err := stream.SetWriteDeadline(time.Time{})
		if err != nil {
			return err
		}
	}
	return nil
}

func ReadTunToQUIC(stream quic.Stream, iface *water.Interface, tuName string, timeout int) {
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
		err = WriteQUIC(stream, buf, n, timeout)
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

func ReadQUICToTun(stream quic.Stream, iface *water.Interface, tuName string, timeout int) {
	defer func() {
		stream.Close()
		iface.Close()
	}()

	buf := make([]byte, 65536)
	var err error
	var n int
	for {
		n, err = ReadQUIC(stream, buf, timeout)
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

func ReadQUICToTunClient(stream quic.Stream, iface *water.Interface, timeout int) {
	defer func() {
		stream.Close()
		iface.Close()
	}()

	buf := make([]byte, 65536)
	var err error
	var n int
	for {
		n, err = ReadQUIC(stream, buf, timeout)
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

func ReadTunToQUICClient(stream quic.Stream, iface *water.Interface, timeout int) {
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

		err = WriteQUIC(stream, buf, n, timeout)
		if err != nil {
			goto Stop
		}
	}
Stop:
	logrus.WithFields(logrus.Fields{
		"Error": err,
	}).Errorln("ReadTunToQUICClient Error.")
}
