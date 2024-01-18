package authutil

import (
	"context"
	"crypto/tls"
	"errors"
	"math/rand"
	"net"
	"strconv"
	"time"
	"tunproject/authUtil/cipherUtil"
	"tunproject/cfgUtil"
	quicutil "tunproject/protocolUtil/quicUtil"
	tunutil "tunproject/tunUtil"

	"github.com/quic-go/quic-go"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

func Auth(ctx context.Context, dataChan chan []byte, serverCfg *cfgUtil.ServerCfg) {
	var tuName string
	var retInfo string
	var retBytes []byte
	var tunInfo *cfgUtil.TunnelCfg
	var ag *cipherUtil.AesGcm
	var rand64 int64
	var err error
	for {
		select {
		case <-ctx.Done():
			logrus.WithFields(logrus.Fields{
				"TuName": tuName,
			}).Debugln("Auth Finished.")
			return
		case data := <-dataChan:
			if len(data) < 1 {
				retInfo = "Bad Request."
				retBytes = []byte{0x10}
				goto Error
			}
			switch data[0] {
			case 0x01:
				tuName = string(data[1:])
				tunInfo = cfgUtil.TunExist(tuName)
				if tunInfo == nil {
					logrus.WithFields(logrus.Fields{
						"TuName": tuName,
						"Step":   "0x01",
					}).Errorln("Tunnel doesn't Exist.")
					retInfo = "Tunnel doesn't Exist."
					retBytes = []byte{0x01}
					goto Error
				}

				ag = &cipherUtil.AesGcm{}
				err = ag.Init(tunInfo.Passwd)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"TuName": tuName,
						"Error":  err,
						"Step":   "0x01",
					}).Errorln("Cipher Init Failed.")
					retInfo = "Cipher Init Failed."
					retBytes = []byte{0x01}
					goto Error
				}

				rand.Seed(time.Now().UnixNano())
				rand64 = rand.Int63()
				data, err = ag.Encrypt([]byte(strconv.FormatInt(rand64, 10)))
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"TuName": tuName,
						"Error":  err,
						"Step":   "0x01",
					}).Errorln("Encrypt Failed.")
					retInfo = "Encrypt Failed."
					retBytes = []byte{0x01}
					goto Error
				}

				retBytes = []byte{0x02}
				retBytes = append(retBytes, data...)
				dataChan <- retBytes
			case 0x02:
				if tuName == "" { //we should send 0x01 firstly
					retInfo = "Bad Request."
					retBytes = []byte{0x10}
					goto Error
				}

				data, err = ag.Decrypt(data[1:])
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"TuName": tuName,
						"Error":  err,
						"Step":   "0x02",
					}).Errorln("Decrypt Failed.")
					retInfo = "Invalid Password."
					retBytes = []byte{0x02}
					goto Error
				}

				token64, err := strconv.ParseInt(string(data), 10, 64)
				if err != nil || token64 != rand64+1 {
					//cfgUtil.TunCtrlMap.Delete(tuName)
					if err == nil {
						err = errors.New("received wrong token64")
					}
					logrus.WithFields(logrus.Fields{
						"TuName": tuName,
						"Error":  err,
						"Step":   "0x02",
					}).Errorln("Token Verified Failed.")
					retInfo = "Bad Token."
					retBytes = []byte{0x02}
					goto Error
				}

				logrus.WithFields(logrus.Fields{
					"TuName": tuName,
					"Step":   "0x02",
				}).Debugln("Verification Completed.")

				retBytes = []byte{0x03, 'o', 'k'}
				dataChan <- retBytes
			default:
				retInfo = "Bad Request."
				retBytes = []byte{0x10}
				goto Error
			}
		}
	}

Error:
	retBytes = append(retBytes, []byte(retInfo)...)
	dataChan <- retBytes
}

func TokenInc(data []byte, clientCfg *cfgUtil.ClientCfg, ag *cipherUtil.AesGcm) ([]byte, error) {
	var token64 int64
	var err error

	data, err = ag.Decrypt(data[1:])
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  err,
			"Step":   "0x02",
		}).Errorln("Decrypt Failed.")
		return nil, err
	}

	token64, err = strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  err,
			"Step":   "0x02",
		}).Errorln("ParseInt Failed.")
		return nil, err
	}

	token64 += 1

	data, err = ag.Encrypt([]byte(strconv.FormatInt(token64, 10)))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  err,
			"Step":   "0x02",
		}).Errorln("Encrypt Failed.")
		return nil, err
	}

	return append([]byte{0x02}, data...), err
}

func QUICVerify(stream quic.Stream, serverCfg *cfgUtil.ServerCfg) {
	var tuName string
	var data []byte
	var dataChan chan []byte
	var n int
	var ctx context.Context
	var cancelFunc context.CancelFunc
	var ccfg *cfgUtil.ClientCfg
	var tunInfo *cfgUtil.TunnelCfg
	var iface *water.Interface
	var timeout int
	var err error

	timeout = serverCfg.QUIC.Timeout
	data = make([]byte, 65536)
	n, err = quicutil.ReadQUIC(stream, data, timeout)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("QUIC Communication Error.")
		goto Error
	}

	ctx, cancelFunc = context.WithCancel(context.Background())
	dataChan = make(chan []byte)
	go Auth(ctx, dataChan, serverCfg)

	tuName = string(data[1:n])
	dataChan <- data[:n]
	data = <-dataChan
	err = quicutil.WriteQUIC(stream, data, len(data), timeout)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": tuName,
			"Error":  err,
		}).Errorln("QUIC Communication Error.")
		goto Error
	}
	if len(data) < 1 || data[0] != 0x02 {
		goto Error
	}

	data = make([]byte, 65536)
	n, err = quicutil.ReadQUIC(stream, data, timeout)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": tuName,
			"Error":  err,
		}).Errorln("QUIC Communication Error.")
		goto Error
	}

	dataChan <- data[:n]
	data = <-dataChan
	err = quicutil.WriteQUIC(stream, data, len(data), timeout)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": tuName,
			"Error":  err,
		}).Errorln("QUIC Communication Error.")
		goto Error
	}
	if len(data) < 1 || data[0] != 0x03 {
		goto Error
	}

	cancelFunc()
	cancelFunc = nil
	//Verification completed
	tunInfo = cfgUtil.TunExist(tuName)
	ccfg = &cfgUtil.ClientCfg{DeviceType: tunInfo.DeviceType, DeviceName: tunInfo.DeviceName, Network: tunInfo.Network}

	iface, err = tunutil.NewTun(ccfg)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": tuName,
			"Error":  err,
		}).Errorln("Creating Tap/Tun Device Error.")
		goto Error
	}

	go quicutil.ReadQUICToTun(stream, iface, tuName, timeout)
	go quicutil.ReadTunToQUIC(stream, iface, tuName, timeout)

	return
Error:
	if cancelFunc != nil {
		cancelFunc()
	}
	stream.Close()
}

func QUICClientVerify(clientCfg *cfgUtil.ClientCfg) {
	tlsConfig := &tls.Config{InsecureSkipVerify: clientCfg.QUIC.AllowInSecure, NextProtos: []string{"quic-tunproject"}}
	addrStr := ""
	ag := &cipherUtil.AesGcm{}
	timeout := clientCfg.QUIC.Timeout
	qConfig := &quic.Config{KeepAlivePeriod: time.Duration(clientCfg.QUIC.Keepalive), HandshakeIdleTimeout: time.Second * time.Duration(clientCfg.QUIC.ShakeTime), MaxIdleTimeout: time.Second * time.Duration(clientCfg.QUIC.IdleTime)}

	if clientCfg.QUIC.QuicUrl != "" {
		addrStr = clientCfg.QUIC.QuicUrl + ":" + strconv.Itoa(clientCfg.QUIC.Port)
	} else {
		addr := net.UDPAddr{IP: net.ParseIP(clientCfg.QUIC.Ip), Port: clientCfg.QUIC.Port}
		addrStr = addr.String()
	}

	err := ag.Init(clientCfg.Passwd)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("Auth failed.")
		return
	}

	conn, err := quic.DialAddr(context.Background(), addrStr, tlsConfig, qConfig)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"RemoteAddr": addrStr,
			"Error":      err,
		}).Errorln("Connect to RemoteAddr Failed.")
		return
	}

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("QUIC Accept Stream failed.")
		return
	}

	tunNameBuf := []byte(clientCfg.TunnelName)
	data := append([]byte{0x01}, tunNameBuf...)
	err = quicutil.WriteQUIC(stream, data, len(data), timeout)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  err,
			"Step":   "0x01",
		}).Errorln("QUIC Communication Error.")
		stream.Close()
		return
	}

	data = make([]byte, 65536)
	n, err := quicutil.ReadQUIC(stream, data, timeout)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  err,
			"Step":   "0x01",
		}).Errorln("QUIC Communication Error.")
		stream.Close()
		return
	}

	if len(data) < 1 || data[0] != 0x02 {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  errors.New("bad response"),
			"Step":   "0x01",
		}).Errorln("Bad Response.")
		stream.Close()
		return
	}

	data, err = TokenInc(data[:n], clientCfg, ag)
	if err != nil {
		stream.Close()
		return
	}
	err = quicutil.WriteQUIC(stream, data, len(data), timeout)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  err,
			"Step":   "0x02",
		}).Errorln("QUIC Communication Error.")
		stream.Close()
		return
	}

	data = make([]byte, 65536)
	n, err = quicutil.ReadQUIC(stream, data, timeout)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  err,
			"Step":   "0x02",
		}).Errorln("QUIC Communication Error.")
		stream.Close()
		return
	}

	data = data[:n]
	if len(data) < 1 {
		err = errors.New("empty response")
	} else if data[0] != 0x03 {
		err = errors.New(string(data[1:]))
	}
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  err,
			"Step":   "0x02",
		}).Errorln("Verification Failed.")
		stream.Close()
		return
	}
	//Verification completed
	iface, err := tunutil.NewTun(clientCfg)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  err,
		}).Errorln("Creating Tap/Tun Device Error.")
		stream.Close()
		return
	}

	go quicutil.ReadQUICToTunClient(stream, iface, timeout)
	go quicutil.ReadTunToQUICClient(stream, iface, timeout)
}
