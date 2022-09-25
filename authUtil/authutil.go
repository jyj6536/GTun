package authutil

import (
	"context"
	"crypto/tls"
	"errors"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
	"tunproject/authUtil/cipherUtil"
	"tunproject/cfgUtil"
	protocolutil "tunproject/protocolUtil"
	icmputil "tunproject/protocolUtil/icmpUtil"
	quicutil "tunproject/protocolUtil/quicUtil"
	tunutil "tunproject/tunUtil"

	"github.com/lucas-clemente/quic-go"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

func IcmpTunnelStart(tunCtrl *cfgUtil.TunCtrl, icmp *icmputil.ICMP, addr net.Addr, key string) error {

	value, _ := cfgUtil.IcmpTunStsCtrl.Load(key)
	icmpTunCtrl := value.(*cfgUtil.IcmpTunCtrl)

	ccfg := &cfgUtil.ClientCfg{DeviceType: tunCtrl.TunInfo.DeviceType, DeviceName: tunCtrl.TunInfo.DeviceName, Network: tunCtrl.TunInfo.Network}

	iface, err := tunutil.NewTun(ccfg)
	if err != nil {
		return err
	}

	icmpTunCtrl.Iface = iface
	ctx, cancelFunc := context.WithCancel(context.Background())
	icmpTunCtrl.Time = time.Now()
	icmpTunCtrl.CancelFunc = cancelFunc

	go func(iface *water.Interface, icmp *icmputil.ICMP, addr net.Addr, ctx context.Context, tunCtrl *cfgUtil.TunCtrl) { //read tun to icmp
		defer func() {
			iface.Close()
			logrus.WithFields(logrus.Fields{
				"DeviceName": ccfg.DeviceName,
			}).Debugln("Tun Closed.")
		}()

		buf := make([]byte, 65536)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, err := iface.Read(buf)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"DeviceName": ccfg.DeviceName,
						"Error":      err,
					}).Errorln("Tun Read Error.")
					continue
				}
				retIcmp := icmp.Create(icmputil.Reply, 0, icmp.Identifier, icmp.SeqNum, append([]byte{0x03}, buf[:n]...))
				icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}
			}
		}
	}(iface, icmp, addr, ctx, tunCtrl)

	return err
}

func IcmpVerify(icmp *icmputil.ICMP, addr net.Addr, serverCfg *cfgUtil.ServerCfg) {
	data := icmp.Data
	switch data[0] {
	case 0x01:
		tuName := string(data[1:])
		tunInfo := cfgUtil.TunExist(tuName, serverCfg)
		if tunInfo == nil {
			logrus.WithFields(logrus.Fields{
				"TuName": tuName,
				"Step":   "0x01",
			}).Errorln("Tunnel doesn't Exist.")
			retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, []byte{0x01, '!', 'o', 'k'})
			icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}
			return
		}
		value, ok := cfgUtil.TunCtrlMap.Load(tuName)
		if ok {
			tunCtrl := value.(*cfgUtil.TunCtrl)
			if tunCtrl.TokenInt != 0 && tunCtrl.Sts == "0x01" {
				intEnc, err := tunCtrl.AesCipher.Encrypt([]byte(strconv.FormatInt(tunCtrl.TokenInt, 10)))
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"TuName": tuName,
						"Error":  err,
						"Step":   "0x01",
					}).Errorln("Step1 Failed.")
					retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, []byte{0x01, '!', 'o', 'k'})
					icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}
					return
				}
				retInfo := append([]byte{0x02}, intEnc...)
				retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, retInfo)
				icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}
				return
			} else {
				retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, []byte{0x01, '!', 'o', 'k'})
				icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}
				return
			}
		} else {
			rand.Seed(time.Now().UnixNano())
			rand64 := rand.Int63()

			ag := &cipherUtil.AesGcm{}
			err := ag.Init(tunInfo.Passwd)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"TuName": tuName,
					"Error":  err,
					"Step":   "Step1",
				}).Errorln("Step1 Failed.")
				retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, []byte{0x01, '!', 'o', 'k'})
				icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}
				return
			}

			tunCtrl := &cfgUtil.TunCtrl{TunInfo: tunInfo, TokenInt: rand64, Sts: "0x01", AesCipher: ag}

			intEnc, err := ag.Encrypt([]byte(strconv.FormatInt(tunCtrl.TokenInt, 10)))
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"TuName": tuName,
					"Error":  err,
					"Step":   "0x01",
				}).Errorln("Step1 Failed.")
				retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, []byte{0x01, '!', 'o', 'k'})
				icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}
				return
			}

			retInfo := append([]byte{0x02}, intEnc...)
			retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, retInfo)
			icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}

			key := addr.String() + "+" + strconv.FormatUint(uint64(icmp.Identifier), 10)
			cfgUtil.TunCtrlMap.Store(tuName, tunCtrl)
			cfgUtil.IcmpTunStsCtrl.Store(key, &cfgUtil.IcmpTunCtrl{Time: time.Now(), TuName: tuName, TunCtrl: tunCtrl})

			return
		}
	case 0x02:
		key := addr.String() + "+" + strconv.FormatUint(uint64(icmp.Identifier), 10)
		value, ok := cfgUtil.IcmpTunStsCtrl.Load(key)
		if !ok {
			retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, []byte{0x02, '!', 'o', 'k'})
			icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}
			return
		}

		icmpTunCtrl := value.(*cfgUtil.IcmpTunCtrl)
		tuName := icmpTunCtrl.TuName
		tunCtrl := icmpTunCtrl.TunCtrl

		if tunCtrl.Sts == "0x01" {
			intDec, err := tunCtrl.AesCipher.Decrypt(data[1:])
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"TuName": tuName,
					"Error":  err,
					"Step":   "Step2",
				}).Errorln("Step2 Failed.")
				retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, []byte{0x02, '!', 'o', 'k'})
				icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}
				return
			}

			rand64, err := strconv.ParseInt(string(intDec), 10, 64)
			if err != nil || rand64 != tunCtrl.TokenInt+1 {
				retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, []byte{0x02, '!', 'o', 'k'})
				icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}
				return
			}
		}
		err := IcmpTunnelStart(tunCtrl, icmp, addr, key)
		if err != nil {
			retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, []byte{0x02, '!', 'o', 'k'})
			icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}
			return
		}
		tunCtrl.Sts = "0x02"
		retIcmp := icmp.Create(icmputil.Reply, 0, icmp.Identifier, icmp.SeqNum, []byte{0x03, 'o', 'k'})
		icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}

	default:
		return
	}
}

func IcmpClientVerify(clientCfg *cfgUtil.ClientCfg) (*net.IPConn, *icmputil.ICMP, error) {
	ag := &cipherUtil.AesGcm{}
	err := ag.Init(clientCfg.Passwd)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("Create AesCipher failed.")
		return nil, nil, err
	}

	addr, err := net.ResolveIPAddr("ip", clientCfg.ICMP.Ip)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("Addr Resolve failed.")
		return nil, nil, err
	}
	conn, err := net.DialIP("ip:icmp", nil, addr)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("Create Socket failed.")
		return nil, nil, err
	}
	tunNameBuf := []byte(clientCfg.TunnelName)
	//step1
	data := append([]byte{0x01}, tunNameBuf...)
	identifier := uint16(clientCfg.ICMP.Identifier)
	icmp := &icmputil.ICMP{}
	data = icmp.Create(icmputil.Request, 0, identifier, identifier, data)

	retryTimes := clientCfg.ICMP.RetryTimes
	i := 0

	for i = 0; i < retryTimes; i++ {
		err := icmputil.IcmpWriteClient(conn, data, len(data))
		if err != nil {
			continue
		}
		t := time.Now()
		err = conn.SetReadDeadline(t.Add(time.Second * time.Duration(clientCfg.ICMP.Timeout))) //timeout after clientCfg.ICMP.Timeout seconds
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Step":  "Step1",
				"Error": err,
			}).Errorln("Set ReadDeadline failed.")
			conn.Close()
			return nil, nil, err
		}
		buf := make([]byte, 65536)
		n, err := conn.Read(buf)
		if err != nil {
			if strings.Contains(err.Error(), "timeout") {
				logrus.WithFields(logrus.Fields{
					"Step":  "Step1",
					"Error": err,
				}).Debugln("Read Timeout.")
				continue
			} else {
				logrus.WithFields(logrus.Fields{
					"Step":  "Step1",
					"Error": err,
				}).Errorln("Read failed.")
				conn.Close()
				return nil, nil, err
			}
		}
		ipHeadLen := int(uint8(buf[0]) & 0x0f * 4)
		if !icmp.Construct(buf[ipHeadLen:n]) {
			err = errors.New("bad icmp packet")
			logrus.WithFields(logrus.Fields{
				"Step":  "Step1",
				"Error": err,
			}).Errorln("Bad Response.")
			conn.Close()
			return nil, nil, err
		}
		if icmp.Data[0] != 0x02 {
			err = errors.New(string(icmp.Data[1:]))
			logrus.WithFields(logrus.Fields{
				"Step":  "Step1",
				"Error": err,
			}).Errorln("Auth Failed.")
			conn.Close()
			return nil, nil, err
		}
		break
	}

	if i == retryTimes {
		err := errors.New("cann't connect to server : retry failed")
		logrus.WithFields(logrus.Fields{
			"Step":  "Step1",
			"Error": err,
		}).Errorln("Retry failed.")
		conn.Close()
		return nil, nil, err
	}

	//Step2
	intDec, err := ag.Decrypt(icmp.Data[1:])
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Step":  "Step2",
			"Error": err,
		}).Errorln("Auth failed.")
		conn.Close()
		return nil, nil, err
	}
	rand64, err := strconv.ParseInt(string(intDec), 10, 64)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Step":  "Step2",
			"Error": err,
		}).Errorln("Auth failed.")
		conn.Close()
		return nil, nil, err
	}
	rand64 += 1
	intEnc, err := ag.Encrypt([]byte(strconv.FormatInt(rand64, 10)))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Step":  "Step2",
			"Error": err,
		}).Errorln("Auth failed.")
		conn.Close()
		return nil, nil, err
	}
	for i = 0; i < retryTimes; i++ {
		data = append([]byte{0x02}, intEnc...) //0x02,rand64+1
		data = icmp.Create(icmputil.Request, 0, identifier, identifier, data)
		err = icmputil.IcmpWriteClient(conn, data, len(data))
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Step":  "Step2",
				"Error": err,
			}).Errorln("Auth failed.")
			conn.Close()
			return nil, nil, err
		}

		t := time.Now()
		err = conn.SetReadDeadline(t.Add(time.Second * 5))
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Step":  "Step2",
				"Error": err,
			}).Errorln("Set ReadDeadline failed.")
			conn.Close()
			return nil, nil, err
		}

		buf := make([]byte, 65536)
		n, err := conn.Read(buf)
		if err != nil {
			if strings.Contains(err.Error(), "timeout") {
				logrus.WithFields(logrus.Fields{
					"Step":  "Step2",
					"Error": err,
				}).Debugln("Read Timeout.")
				continue
			} else {
				logrus.WithFields(logrus.Fields{
					"Step":  "Step2",
					"Error": err,
				}).Errorln("Read failed.")
				conn.Close()
				return nil, nil, err
			}
		}
		ipHeadLen := int(uint8(buf[0]) & 0x0f * 4)
		if !icmp.Construct(buf[ipHeadLen:n]) {
			err = errors.New("bad icmp packet")
			logrus.WithFields(logrus.Fields{
				"Step":  "Step2",
				"Error": err,
			}).Errorln("Bad Response.")
			conn.Close()
			return nil, nil, err
		}
		if icmp.Data[0] != 0x03 {
			err = errors.New(string(icmp.Data[1:]))
			logrus.WithFields(logrus.Fields{
				"Step":  "Step2",
				"Error": err,
			}).Errorln("Auth Failed.")
			conn.Close()
			return nil, nil, err
		}
		break
	}
	if i == retryTimes {
		err := errors.New("cann't connect to server : retry failed")
		logrus.WithFields(logrus.Fields{
			"Step":  "Step2",
			"Error": err,
		}).Errorln("Retry failed.")
		conn.Close()
		return nil, nil, err
	}

	err = conn.SetReadDeadline(time.Time{})
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("Cancel Deadline failed.")
		return nil, nil, err
	}
	return conn, icmp, nil
}

func Auth(ctx context.Context, dataChan chan []byte, serverCfg *cfgUtil.ServerCfg) {
	var tuName string
	var retInfo string
	var retBytes []byte
	var tunInfo *cfgUtil.TunnelCfg
	var ag *cipherUtil.AesGcm
	var tunCtrl *cfgUtil.TunCtrl
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
				tunInfo = cfgUtil.TunExist(tuName, serverCfg)
				if tunInfo == nil {
					logrus.WithFields(logrus.Fields{
						"TuName": tuName,
						"Step":   "0x01",
					}).Errorln("Tunnel doesn't Exist.")
					retInfo = "Tunnel doesn't Exist."
					retBytes = []byte{0x01}
					goto Error
				}

				value, ok := cfgUtil.TunCtrlMap.Load(tuName)
				if !ok {
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

					tunCtrl = &cfgUtil.TunCtrl{TunInfo: tunInfo, AesCipher: ag}
					cfgUtil.TunCtrlMap.Store(tuName, tunCtrl)
				} else {
					tunCtrl = value.(*cfgUtil.TunCtrl)
				}

				if ag == nil {
					ag = tunCtrl.AesCipher
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
				if _, ok := cfgUtil.TunCtrlMap.Load(tuName); !ok {
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
					cfgUtil.TunCtrlMap.Delete(tuName)
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

func TcpVerify(conn *net.TCPConn, serverCfg *cfgUtil.ServerCfg) {
	var tuName string
	var data []byte
	var dataChan chan []byte
	var n int
	var ctx context.Context
	var cancelFunc context.CancelFunc
	var ccfg *cfgUtil.ClientCfg
	var tunInfo *cfgUtil.TunnelCfg
	var iface *water.Interface
	var err error

	data = make([]byte, 65536)
	n, err = protocolutil.TcpRead(*conn, data)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("Tcp Communication Error.")
		goto Error
	}

	ctx, cancelFunc = context.WithCancel(context.Background())
	dataChan = make(chan []byte)
	go Auth(ctx, dataChan, serverCfg)

	tuName = string(data[1:n])
	dataChan <- data[:n]
	data = <-dataChan
	err = protocolutil.TcpWrite(*conn, data, len(data))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": tuName,
			"Error":  err,
		}).Errorln("Tcp Communication Error.")
		goto Error
	}
	if len(data) < 1 || data[0] != 0x02 {
		goto Error
	}

	data = make([]byte, 65536)
	n, err = protocolutil.TcpRead(*conn, data)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": tuName,
			"Error":  err,
		}).Errorln("Tcp Communication Error.")
		goto Error
	}

	dataChan <- data[:n]
	data = <-dataChan
	err = protocolutil.TcpWrite(*conn, data, len(data))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": tuName,
			"Error":  err,
		}).Errorln("Tcp Communication Error.")
		goto Error
	}
	if len(data) < 1 || data[0] != 0x03 {
		goto Error
	}

	cancelFunc()
	cancelFunc = nil
	//Verification completed
	tunInfo = cfgUtil.TunExist(tuName, serverCfg)
	ccfg = &cfgUtil.ClientCfg{DeviceType: tunInfo.DeviceType, DeviceName: tunInfo.DeviceName, Network: tunInfo.Network}

	iface, err = tunutil.NewTun(ccfg)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": tuName,
			"Error":  err,
		}).Errorln("Creating Tap/Tun Device Error.")
		goto Error
	}

	go protocolutil.ReadTcpToTun(conn, iface, tuName)
	go protocolutil.ReadTunToTcp(conn, iface, tuName, serverCfg.TCP.Timeout)

	return
Error:
	if cancelFunc != nil {
		cancelFunc()
	}
	conn.Close()
}

func TcpClientVerify(clientCfg *cfgUtil.ClientCfg) {
	addr := &net.TCPAddr{Port: clientCfg.TCP.Port, IP: net.ParseIP(clientCfg.TCP.Ip)}

	ag := &cipherUtil.AesGcm{}
	err := ag.Init(clientCfg.Passwd)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  err,
		}).Errorln("Create AesCipher Failed.")
		return
	}

	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName":      clientCfg.TunnelName,
			"Server Addr": addr,
			"Error":       err,
		}).Errorln("Cann't connect to server.")
		return
	}

	tunNameBuf := []byte(clientCfg.TunnelName)
	data := append([]byte{0x01}, tunNameBuf...)
	err = protocolutil.TcpWrite(*conn, data, len(data))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  err,
			"Step":   "0x01",
		}).Errorln("Tcp Communication Error.")
		conn.Close()
		return
	}

	data = make([]byte, 65536)
	n, err := protocolutil.TcpRead(*conn, data)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  err,
			"Step":   "0x01",
		}).Errorln("Tcp Communication Error.")
		conn.Close()
		return
	}

	if len(data) < 1 || data[0] != 0x02 {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  errors.New("bad response"),
			"Step":   "0x01",
		}).Errorln("Bad Response.")
		conn.Close()
		return
	}

	data, err = TokenInc(data[:n], clientCfg, ag)
	if err != nil {
		conn.Close()
		return
	}
	err = protocolutil.TcpWrite(*conn, data, len(data))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  err,
			"Step":   "0x02",
		}).Errorln("Tcp Communication Error.")
		conn.Close()
		return
	}

	data = make([]byte, 65536)
	n, err = protocolutil.TcpRead(*conn, data)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  err,
			"Step":   "0x02",
		}).Errorln("Tcp Communication Error.")
		conn.Close()
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
		conn.Close()
		return
	}
	//Verification completed
	if clientCfg.TCP.KeepaLvie > 0 { //use tcp keepalive to keep tcp nat session
		logrus.WithFields(logrus.Fields{
			"Keepalive": clientCfg.TCP.KeepaLvie,
		}).Debugln("Set Keepalive for Tcp Conn.")
		err = protocolutil.SetTcpKeepalive(clientCfg.TCP.KeepaLvie, conn)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Infoln("Set Keepavlive failed.")
		}
	}

	iface, err := tunutil.NewTun(clientCfg)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": clientCfg.TunnelName,
			"Error":  err,
		}).Errorln("Creating Tap/Tun Device Error.")
		conn.Close()
		return
	}

	go protocolutil.ReadTcpToTunClient(conn, iface)
	go protocolutil.ReadTunToTcpClient(conn, iface, clientCfg.TCP.Timeout)
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
	tunInfo = cfgUtil.TunExist(tuName, serverCfg)
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
	qConfig := &quic.Config{KeepAlive: true, HandshakeIdleTimeout: time.Second * time.Duration(clientCfg.QUIC.ShakeTime), MaxIdleTimeout: time.Second * time.Duration(clientCfg.QUIC.IdleTime)}

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

	conn, err := quic.DialAddr(addrStr, tlsConfig, qConfig)
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
