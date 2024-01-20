package tunnelInit

import (
	"crypto/tls"
	"encoding/binary"
	"time"

	"github.com/quic-go/quic-go"
)

func GenerateTlsConfig(certPath, keyPath string) (*tls.Config, error) {
	cer, err := tls.LoadX509KeyPair(certPath, keyPath)
	return &tls.Config{Certificates: []tls.Certificate{cer}, NextProtos: []string{"quic-tunproject"}}, err
}

func QuicRead(stream quic.Stream, data []byte, timeout int) (int, error) {
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

func QuicWrite(stream quic.Stream, data []byte, timeout int) error {
	dataLen := len(data)
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
