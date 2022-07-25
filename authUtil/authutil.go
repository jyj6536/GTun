package authutil

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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

func Auth(conn *net.TCPConn, serverCfg *cfgUtil.ServerCfg) {
	var tuName string
	var tuSts *cfgUtil.TunnelSts
	var ag *cipherUtil.AesGcm
	for {
		data := make([]byte, 65536)
		n, err := protocolutil.TcpRead(*conn, data)
		if err != nil {
			logrus.Errorln("Auth Failed.")
			conn.Close()
			return
		}
		// client create main conn
		// client send 0x01,tunnelName
		// server send 0x02,randInt64 rd64
		// client send 0x02,rd64+1
		// server send 0x03,randInt64 rd64_2
		// client get rd64_2,this int for subsequent connect
		/*subsequent connect*/
		// loop(for queue in multiqueue)
		// client send 0x03,tunnelName
		// server send 0x04,ok
		// client send 0x04,rd64_2+1
		// server send 0x05,ok
		// goto loop
		// client use main conn send 0x06,done
		switch data[0] {
		case 0x01: //start auth, actions according to the first byte of data
			tuName = string(data[1:n])
			tunInfo := cfgUtil.TunExist(tuName, serverCfg)
			if tunInfo == nil {
				logrus.WithFields(logrus.Fields{
					"TuName": tuName,
					"Step":   "Step1",
				}).Errorln("Tunnel doesn't Exist.")
				retInfo := []byte{0x01, '!', 'o', 'k'}
				protocolutil.TcpWrite(*conn, retInfo, len(retInfo))
				conn.Close()
				return
			}
			_, ok := cfgUtil.TunStsMap.Load(tuName)
			if ok {
				logrus.WithFields(logrus.Fields{
					"TuName": tuName,
					"Step":   "Step1",
				}).Errorln("Tunnel already in Auth.")
				retInfo := []byte{0x01, '!', 'o', 'k'}
				protocolutil.TcpWrite(*conn, retInfo, len(retInfo))
				conn.Close()
				return
			}

			rand.Seed(time.Now().UnixNano())
			rand64 := rand.Int63()

			tuSts = &cfgUtil.TunnelSts{TunInfo: tunInfo, TokenInt: rand64, Sts: "Step1"}

			ag = &cipherUtil.AesGcm{}
			err = ag.Init(tunInfo.Passwd)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"TuName": tuName,
					"Error":  err,
					"Step":   "Step1",
				}).Errorln("Step1 Failed.")
				retInfo := []byte{0x01, '!', 'o', 'k'}
				protocolutil.TcpWrite(*conn, retInfo, len(retInfo))
				conn.Close()
				return
			}
			tuSts.AesCipher = ag

			data, err = ag.Encrypt([]byte(strconv.FormatInt(rand64, 10)))
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"TuName": tuName,
					"Error":  err,
					"Step":   "Step1",
				}).Errorln("Step1 Failed.")
				retInfo := []byte{0x01, '!', 'o', 'k'}
				protocolutil.TcpWrite(*conn, retInfo, len(retInfo))
				conn.Close()
				return
			}

			retInfo := append([]byte{0x02}, data...) //0x02,a random Int64 number

			err = protocolutil.TcpWrite(*conn, retInfo, len(retInfo))

			if err != nil {
				logrus.WithFields(logrus.Fields{
					"TuName": tuName,
					"Step":   "Step1",
					"Error":  err,
				}).Errorln("Step1 Failed.")
				retInfo := []byte{0x01, '!', 'o', 'k'}
				protocolutil.TcpWrite(*conn, retInfo, len(retInfo))
				conn.Close()
				return
			}

			cfgUtil.TunStsMap.Store(tuName, tuSts)
		case 0x02:
			if tuSts.Sts != "Step1" {
				cfgUtil.TunStsMap.Delete(tuName)
				logrus.WithFields(logrus.Fields{
					"Error":  errors.New("wrong stage"),
					"TuName": tuName,
					"Step":   tuSts.Sts,
				}).Errorln("Step2 Failed.")
				retInfo := []byte{0x02, '!', 'o', 'k'}
				protocolutil.TcpWrite(*conn, retInfo, len(retInfo))
				conn.Close()
				return
			}

			data, err = ag.Decrypt(data[1:n])
			if err != nil {
				cfgUtil.TunStsMap.Delete(tuName)
				logrus.WithFields(logrus.Fields{
					"Step":   "Step2",
					"TuName": tuName,
					"Error":  err,
				}).Errorln("Step2 Failed.")
				retInfo := []byte{0x02, '!', 'o', 'k'}
				protocolutil.TcpWrite(*conn, retInfo, len(retInfo))
				conn.Close()
				return
			}

			rand64, err := strconv.ParseInt(string(data), 10, 64)
			if err != nil || rand64 != tuSts.TokenInt+1 {
				cfgUtil.TunStsMap.Delete(tuName)
				if err == nil {
					err = errors.New("received wrong TokenInt")
				}
				logrus.WithFields(logrus.Fields{
					"Error":  err,
					"TuName": tuName,
					"Step":   "Step2",
				}).Errorln("Step2 Failed.")
				retInfo := []byte{0x02, '!', 'o', 'k'}
				protocolutil.TcpWrite(*conn, retInfo, len(retInfo))
				conn.Close()
				return
			}

			tuSts.Sts = "Step2"

			rand64 = rand.Int63()

			tuSts.TokenInt = rand64

			data, err = ag.Encrypt([]byte(strconv.FormatInt(rand64, 10)))
			if err != nil {
				cfgUtil.TunStsMap.Delete(tuName)
				logrus.WithFields(logrus.Fields{
					"TuName": tuName,
					"Error":  err,
					"Step":   "Step2",
				}).Errorln("Step2 failed.")
				retInfo := []byte{0x02, '!', 'o', 'k'}
				protocolutil.TcpWrite(*conn, retInfo, len(retInfo))
				conn.Close()
				return
			}

			retInfo := append([]byte{0x03}, data...) //0x03,a random Int64 number

			err = protocolutil.TcpWrite(*conn, retInfo, len(retInfo))

			if err != nil {
				cfgUtil.TunStsMap.Delete(tuName)
				logrus.WithFields(logrus.Fields{
					"TuName": tuName,
					"Step":   "Step2",
					"Error":  err,
				}).Errorln("Auth Failed.")
				retInfo := []byte{0x02, '!', 'o', 'k'}
				protocolutil.TcpWrite(*conn, retInfo, len(retInfo))
				conn.Close()
			}
		case 0x03:
			tuName = string(data[1:n])
			value, ok := cfgUtil.TunStsMap.Load(tuName)
			if !ok {
				logrus.WithFields(logrus.Fields{
					"TuName": tuName,
					"Step":   "Step3",
					"Error":  errors.New("tuName dosen't exist"),
				}).Errorln("Step3 failed.")
				retInfo := []byte{0x03, '!', 'o', 'k'}
				protocolutil.TcpWrite(*conn, retInfo, len(retInfo))
				conn.Close()
				return
			}

			tuSts = value.(*cfgUtil.TunnelSts)

			if tuSts.Sts != "Step2" {
				logrus.WithFields(logrus.Fields{
					"Error":  errors.New("wrong stage"),
					"Step":   "Step3",
					"TuName": tuName,
				}).Errorln("Step3 Failed.")
				conn.Close()
				return
			}

			ag = tuSts.AesCipher

			retInfo := []byte{0x04, 'o', 'k'}
			err = protocolutil.TcpWrite(*conn, retInfo, len(retInfo))
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"TuName": tuName,
					"Step":   "Step3",
					"Error":  err,
				}).Errorln("Step3 failed.")
				conn.Close()
				return
			}
		case 0x04:
			data, err = ag.Decrypt(data[1:n])
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"Step":   "Step4",
					"TuName": tuName,
					"Error":  err,
				}).Errorln("Step4 failed.")
				retInfo := []byte{0x04, '!', 'o', 'k'}
				protocolutil.TcpWrite(*conn, retInfo, len(retInfo))
				conn.Close()
				return
			}
			rand64, err := strconv.ParseInt(string(data), 10, 64)
			if err != nil || rand64 != tuSts.TokenInt+1 {
				if err == nil {
					err = errors.New("received wrong TokenInt")
				}
				logrus.WithFields(logrus.Fields{
					"Error":  err,
					"TuName": tuName,
					"Step":   "Step4",
				}).Errorln("Step4 failed.")
				retInfo := []byte{0x04, '!', 'o', 'k'}
				protocolutil.TcpWrite(*conn, retInfo, len(retInfo))
				conn.Close()
				return
			}

			retInfo := []byte{0x05, 'o', 'k'}
			protocolutil.TcpWrite(*conn, retInfo, len(retInfo))
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"TuName": tuName,
					"Step":   "Step4",
					"Error":  err,
				}).Errorln("Step4 failed.")
				conn.Close()
				return
			}

			tuSts.TcpConn = append(tuSts.TcpConn, conn)

			tuSts.TokenInt += 1

			logrus.WithFields(logrus.Fields{
				"TuName":      tuName,
				"Client Addr": conn.RemoteAddr(),
			}).Debugln("Create tcp connect with client.")
			return
		case 0x06:
			sts := string(data[1:n])
			if sts != "done" {
				cfgUtil.TunStsMap.Delete(tuName)
				logrus.WithFields(logrus.Fields{
					"Error":  sts,
					"TuName": tuName,
					"Step":   "Step6",
				}).Errorln("Step6 failed.")
				conn.Close()
				return
			}
			tuSts.TcpConn = append(tuSts.TcpConn, conn)
			tuSts.Sts = "Step6"
			tuSts.ActiveConn = int32(len(tuSts.TcpConn))
			logrus.WithFields(logrus.Fields{
				"TuName": tuName,
			}).Debugln("Connect Complete.")

			TcpTunnelStart(tuSts)

			return

		default:
			logrus.Errorln("Bad Request.")
			conn.Close()
			return
		}
	}
}

func TcpTunnelStart(tuSts *cfgUtil.TunnelSts) error {
	ccfg := &cfgUtil.ClientCfg{}
	ccfg.DeviceType = tuSts.TunInfo.DeviceType
	ccfg.DeviceName = tuSts.TunInfo.DeviceName
	ccfg.Network = tuSts.TunInfo.Network
	ccfg.MutilQueue = len(tuSts.TcpConn)

	ifaceSet, err := tunutil.NewTun(ccfg)
	if err != nil {
		return err
	}

	connSet := tuSts.TcpConn

	for i := 0; i < len(connSet); i++ {
		go protocolutil.ReadTunToTcp(connSet[i], ifaceSet[i], tuSts.TunInfo.TunnelName)
		go protocolutil.ReadTcpToTun(connSet[i], ifaceSet[i], tuSts.TunInfo.TunnelName)
	}

	return err
}

func IcmpTunnelStart(tuSts *cfgUtil.TunnelSts, icmp *icmputil.ICMP, addr net.Addr, key string) error {

	value, _ := cfgUtil.IcmpTunStsCtrl.Load(key)
	icmpTunCtrl := value.(*cfgUtil.IcmpTunCtrl)

	ccfg := &cfgUtil.ClientCfg{}
	ccfg.DeviceType = tuSts.TunInfo.DeviceType
	ccfg.DeviceName = tuSts.TunInfo.DeviceName
	ccfg.Network = tuSts.TunInfo.Network
	ccfg.MutilQueue = 1 //for icmp tunnel, we don't use MutilQueue

	ifaceSet, err := tunutil.NewTun(ccfg)
	if err != nil {
		return err
	}

	icmpTunCtrl.Iface = ifaceSet[0]
	ctx, cancelFunc := context.WithCancel(context.Background())
	icmpTunCtrl.Time = time.Now()
	icmpTunCtrl.CancelFunc = cancelFunc

	go func(iface *water.Interface, icmp *icmputil.ICMP, addr net.Addr, ctx context.Context, tuSts *cfgUtil.TunnelSts) { //read tun to icmp
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
	}(ifaceSet[0], icmp, addr, ctx, tuSts)

	return err
}

func QUICTUnnelStart(tuSts *cfgUtil.TunnelSts) error {
	ccfg := &cfgUtil.ClientCfg{}
	ccfg.DeviceType = tuSts.TunInfo.DeviceType
	ccfg.DeviceName = tuSts.TunInfo.DeviceName
	ccfg.Network = tuSts.TunInfo.Network
	ccfg.MutilQueue = len(tuSts.QUICStream)

	ifaceSet, err := tunutil.NewTun(ccfg)
	if err != nil {
		return err
	}

	streamSet := tuSts.QUICStream
	for i := 0; i < len(streamSet); i++ {
		go quicutil.ReadTunToQUIC(streamSet[i], ifaceSet[i], tuSts.TunInfo.TunnelName)
		go quicutil.ReadQUICToTun(streamSet[i], ifaceSet[i], tuSts.TunInfo.TunnelName)
	}
	return err
}

func AuthClient(clientCfg *cfgUtil.ClientCfg) ([]*net.TCPConn, error) {
	addr := &net.TCPAddr{Port: clientCfg.Protocol.Port, IP: net.ParseIP(clientCfg.Protocol.Ip)}

	ag := &cipherUtil.AesGcm{}
	err := ag.Init(clientCfg.Passwd)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("Create AesCipher failed.")
		return nil, err
	}

	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Server Addr": addr,
			"Error":       err,
		}).Errorln("Cann't connect to server.")
		return nil, err
	}

	tunNameBuf := []byte(clientCfg.TunnelName)
	//step1
	data := append([]byte{0x01}, tunNameBuf...)
	err = protocolutil.TcpWrite(*conn, data, len(data))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Step":  "Step1",
			"Error": err,
		}).Errorln("Auth Failed.")
		conn.Close()
		return nil, err
	}

	data = make([]byte, 65536)
	n, err := protocolutil.TcpRead(*conn, data)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Step":  "Step1",
			"Error": err,
		}).Errorln("Auth Failed.")
		conn.Close()
		return nil, err
	}
	//setp2
	if data[0] != 0x02 {
		err = errors.New(string(data[1:n]))
		logrus.WithFields(logrus.Fields{
			"Step":  "Step2",
			"Error": err,
		}).Errorln("Auth Failed.")
		conn.Close()
		return nil, err
	}
	// get rand64
	data, err = ag.Decrypt(data[1:n])
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Step":  "Step2",
			"Error": err,
		}).Errorln("Decrypt failed.")
		conn.Close()
		return nil, err
	}
	rand64, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
			"Step":  "Step2",
		}).Errorln("Auth Failed.")
		conn.Close()
		return nil, err
	}
	// rand64 = rand64+1
	rand64 += 1

	data, err = ag.Encrypt([]byte(strconv.FormatInt(rand64, 10)))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Step":  "Step2",
			"Error": err,
		}).Errorln("Encrypt failed.")
		conn.Close()
		return nil, err
	}
	data = append([]byte{0x02}, data...)
	// send rand64 to server
	err = protocolutil.TcpWrite(*conn, data, len(data))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
			"Step":  "Step2",
		}).Errorln("Auth Failed.")
		conn.Close()
		return nil, err
	}
	//step3
	data = make([]byte, 65536)
	n, err = protocolutil.TcpRead(*conn, data)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if data[0] != 0x03 {
		err = errors.New(string(data[1:n]))
		logrus.WithFields(logrus.Fields{
			"Step":  "Step2",
			"Error": err,
		}).Errorln("Auth Failed.")
		conn.Close()
		return nil, err
	}
	// get rand64 for subsequent connect
	data, err = ag.Decrypt(data[1:n])
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
			"Step":  "Step3",
		}).Errorln("Decrypt Failed.")
		conn.Close()
		return nil, err
	}
	rand64, err = strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Step":  "Step3",
			"Error": err,
		}).Errorln("Auth Failed")
		conn.Close()
		return nil, err
	}

	var connSet []*net.TCPConn
	if clientCfg.Protocol.Proto == "tcp" {
		connSet = AuthTcp(rand64, clientCfg, addr, ag)
		connSet = append(connSet, conn)
	}

	data = append([]byte{0x06}, []byte{'d', 'o', 'n', 'e'}...)
	err = protocolutil.TcpWrite(*conn, []byte{0x06, 'd', 'o', 'n', 'e'}, len(data))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Step":  "Step6",
			"Error": err,
		}).Errorln("Auth Failed")
		conn.Close()
		return nil, err
	}
	connSet = append(connSet, conn)
	return connSet, nil
}

func AuthTcp(rand64 int64, clientCfg *cfgUtil.ClientCfg, addr *net.TCPAddr, ag *cipherUtil.AesGcm) []*net.TCPConn {
	var data []byte
	var n int
	var connSet []*net.TCPConn
	tunNameBuf := []byte(clientCfg.TunnelName)

	for i := 0; i < clientCfg.MutilQueue-1; i++ {
		conn, err := net.DialTCP("tcp", nil, addr)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Server Addr": addr,
				"Error":       err,
			}).Errorln("Cann't connect to server.")
			conn.Close()
			continue
		}

		data = append([]byte{0x03}, tunNameBuf...)
		err = protocolutil.TcpWrite(*conn, data, len(data))
		if err != nil {
			conn.Close()
			continue
		}

		data = make([]byte, 65536)
		n, err = protocolutil.TcpRead(*conn, data)
		if err != nil {
			conn.Close()
			continue
		}

		if data[0] != 0x04 {
			logrus.WithFields(logrus.Fields{
				"Step":  "Step3",
				"Error": string(data[1:n]),
			}).Errorln("Auth Failed.")
			conn.Close()
			continue
		}

		data, err = ag.Encrypt([]byte(strconv.FormatInt(rand64+1, 10)))
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Step":  "Step4",
				"Error": err,
			}).Errorln("Auth Failed.")
			conn.Close()
			continue
		}
		data = append([]byte{0x04}, data...)
		err = protocolutil.TcpWrite(*conn, data, len(data))
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Step":  "Step3",
				"Error": err,
			}).Errorln("Auth Failed.")
			conn.Close()
			continue
		}

		data = make([]byte, 65536)
		n, err = protocolutil.TcpRead(*conn, data)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Step":  "Step4",
				"Error": err,
			}).Errorln("Auth Failed.")
			conn.Close()
			continue
		}
		if data[0] != 0x05 {
			logrus.WithFields(logrus.Fields{
				"Step":  "Step4",
				"Error": string(data[1:n]),
			}).Errorln("Auth Failed.")
			conn.Close()
			continue
		}

		connSet = append(connSet, conn)

		rand64 += 1
	}
	return connSet
}

func AuthIcmp(icmp *icmputil.ICMP, addr net.Addr, serverCfg *cfgUtil.ServerCfg) {
	data := icmp.Data
	switch data[0] {
	case 0x01:
		tuName := string(data[1:])
		tunInfo := cfgUtil.TunExist(tuName, serverCfg)
		if tunInfo == nil {
			logrus.WithFields(logrus.Fields{
				"TuName": tuName,
				"Step":   "Step1",
			}).Errorln("Tunnel doesn't Exist.")
			retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, []byte{0x01, '!', 'o', 'k'})
			icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}
			return
		}
		value, ok := cfgUtil.TunStsMap.Load(tuName)
		if ok {
			tuSts := value.(*cfgUtil.TunnelSts)
			if tuSts.TokenInt != 0 && tuSts.Sts == "Step1" {
				intEnc, err := tuSts.AesCipher.Encrypt([]byte(strconv.FormatInt(tuSts.TokenInt, 10)))
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

			tuSts := &cfgUtil.TunnelSts{TunInfo: tunInfo, TokenInt: rand64, Sts: "Step1", AesCipher: ag}

			intEnc, err := ag.Encrypt([]byte(strconv.FormatInt(tuSts.TokenInt, 10)))
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

			retInfo := append([]byte{0x02}, intEnc...)
			retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, retInfo)
			icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}

			key := addr.String() + "+" + strconv.FormatUint(uint64(icmp.Identifier), 10)
			cfgUtil.TunStsMap.Store(tuName, tuSts)
			cfgUtil.IcmpTunStsCtrl.Store(key, &cfgUtil.IcmpTunCtrl{Time: time.Now(), TuName: tuName, TuSts: tuSts})

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
		tuSts := icmpTunCtrl.TuSts

		if tuSts.Sts == "Step1" {
			intDec, err := tuSts.AesCipher.Decrypt(data[1:])
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"Step":   "Step2",
					"TuName": tuName,
					"Error":  err,
				}).Errorln("Step2 Failed.")
				retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, []byte{0x02, '!', 'o', 'k'})
				icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}
				return
			}

			rand64, err := strconv.ParseInt(string(intDec), 10, 64)
			if err != nil || rand64 != tuSts.TokenInt+1 {
				retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, []byte{0x02, '!', 'o', 'k'})
				icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}
				return
			}
		}
		err := IcmpTunnelStart(tuSts, icmp, addr, key)
		if err != nil {
			retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, []byte{0x02, '!', 'o', 'k'})
			icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}
			return
		}
		tuSts.Sts = "Step2"
		retIcmp := icmp.Create(icmputil.Reply, 0, icmp.Identifier, icmp.SeqNum, []byte{0x03, 'o', 'k'})
		icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}

	default:
		return
	}
}

func AuthlClientIcmp(clientCfg *cfgUtil.ClientCfg) (*net.IPConn, *icmputil.ICMP, error) {
	ag := &cipherUtil.AesGcm{}
	err := ag.Init(clientCfg.Passwd)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("Create AesCipher failed.")
		return nil, nil, err
	}

	addr, err := net.ResolveIPAddr("ip", clientCfg.Protocol.Ip)
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
	identifier := uint16(clientCfg.Protocol.Port)
	icmp := &icmputil.ICMP{}
	data = icmp.Create(icmputil.Request, 0, identifier, identifier, data)

	retryTimes := 5
	i := 0

	for i = 0; i < retryTimes; i++ {
		err := icmputil.IcmpWriteClient(conn, data, len(data))
		if err != nil {
			continue
		}
		t := time.Now()
		err = conn.SetReadDeadline(t.Add(time.Second * 5)) //timeout after 5 seconds
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

func AuthQUIC(stream quic.Stream, serverCfg *cfgUtil.ServerCfg) {
	buf := make([]byte, 65536)
	n, err := quicutil.ReadQUIC(stream, buf)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("Auth failed.")
		stream.Close()
		return
	}
	tuName := string(buf[:n])
	tunInfo := cfgUtil.TunExist(tuName, serverCfg)
	if tunInfo == nil {
		logrus.WithFields(logrus.Fields{
			"TuName": tuName,
			"Error":  err,
		}).Errorln("Tunnel dosen't Exists.")
		retInfo := []byte{'!', 'o', 'k'}
		quicutil.WriteQUIC(stream, retInfo, len(retInfo))
		stream.Close()
		return
	}
	ag := &cipherUtil.AesGcm{}
	err = ag.Init(tunInfo.Passwd)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": tuName,
			"Error":  err,
		}).Errorln("Auth failed.")
		retInfo := []byte{'!', 'o', 'k'}
		quicutil.WriteQUIC(stream, retInfo, len(retInfo))
		stream.Close()
		return
	}
	n, err = quicutil.ReadQUIC(stream, buf)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": tuName,
			"Error":  err,
		}).Errorln("Auth failed.")
		retInfo := []byte{'!', 'o', 'k'}
		quicutil.WriteQUIC(stream, retInfo, len(retInfo))
		stream.Close()
		return
	}
	stampDec, err := ag.Decrypt(buf[:n])
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": tuName,
			"Error":  err,
		}).Errorln("Auth failed.")
		retInfo := []byte{'!', 'o', 'k'}
		quicutil.WriteQUIC(stream, retInfo, len(retInfo))
		stream.Close()
		return
	}
	stamp, err := strconv.ParseInt(string(stampDec), 10, 64)
	var localStamp, stampDiff int64
	if err == nil {
		localStamp = time.Now().UTC().Unix()
		stampDiff = localStamp - stamp
	}
	if err != nil || !(stampDiff >= -5 && stampDiff <= 5) { //stampDiff should be less than 5 seconds
		if err == nil {
			err = fmt.Errorf("stampDiff is %ds, more than 5 seconds", stampDiff)
		}
		logrus.WithFields(logrus.Fields{
			"TuName": tuName,
			"Error":  err,
		}).Errorln("Auth failed.")
		retInfo := []byte{'!', 'o', 'k'}
		quicutil.WriteQUIC(stream, retInfo, len(retInfo))
		stream.Close()
		return
	}
	cfgUtil.MutexQUIC.Lock()
	value, ok := cfgUtil.TunStsMap.Load(tuName)
	var tuSts *cfgUtil.TunnelSts
	if !ok {
		tuSts = &cfgUtil.TunnelSts{TunInfo: tunInfo, AesCipher: ag}
		cfgUtil.TunStsMap.Store(tuName, tuSts)
		cfgUtil.MutexQUIC.Unlock()

		go func(stream quic.Stream, tuSts *cfgUtil.TunnelSts, tuName string) {
			buf := make([]byte, 65536)
			err := stream.SetReadDeadline(time.Now().Add(time.Second * 50))
			if err != nil {
				cfgUtil.TunStsMap.Delete(tuName)
				logrus.WithFields(logrus.Fields{
					"TuName": tuName,
					"Error":  err,
				}).Errorln("Auth failed.")
				return
			}
			_, err = quicutil.ReadQUIC(stream, buf) //wait for acknowledgement from client to start Tunnel
			if err != nil {
				cfgUtil.TunStsMap.Delete(tuName)
				logrus.WithFields(logrus.Fields{
					"TuName": tuName,
					"Error":  err,
				}).Errorln("Auth failed.")
				return
			}
			tuSts.ActiveConn = int32(len(tuSts.QUICStream))
			tuSts.Sts = "Step1"
			logrus.WithFields(logrus.Fields{
				"TuName": tuName,
			}).Debugln("Connect Complete.")
			err = QUICTUnnelStart(tuSts)
			if err != nil {
				cfgUtil.TunStsMap.Delete(tuName)
			}
		}(stream, tuSts, tuName)

	} else {
		cfgUtil.MutexQUIC.Unlock()
		tuSts = value.(*cfgUtil.TunnelSts)
		if tuSts.Sts == "Step1" {
			retInfo := []byte{'!', 'o', 'k'}
			quicutil.WriteQUIC(stream, retInfo, len(retInfo))
			logrus.WithFields(logrus.Fields{
				"TuName": tuName,
			}).Errorln("Tunnel is in use.")
			stream.Close()
			return
		}
	}
	retInfo := []byte{'o', 'k'}
	err = quicutil.WriteQUIC(stream, retInfo, len(retInfo))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": tuName,
			"Error":  err,
		}).Errorln("Auth failed.")
		stream.Close()
		return
	}

	tuSts.QUICStream = append(tuSts.QUICStream, stream)
}

func AuthQUICClient(clientCfg *cfgUtil.ClientCfg) ([]quic.Stream, error) {
	tunNameBuf := []byte(clientCfg.TunnelName)
	tlsConfig := &tls.Config{InsecureSkipVerify: clientCfg.Protocol.AllowInSecure, NextProtos: []string{"quic-tunproject"}}
	addrStr := ""
	streamSet := make([]quic.Stream, 0)
	ag := &cipherUtil.AesGcm{}
	buf := make([]byte, 65536)
	qConfig := &quic.Config{KeepAlive: true, HandshakeIdleTimeout: time.Second * time.Duration(clientCfg.Timeout), MaxIdleTimeout: time.Second * time.Duration(clientCfg.Timeout)}

	if clientCfg.Protocol.QuicUrl != "" {
		addrStr = clientCfg.Protocol.QuicUrl + ":" + strconv.Itoa(clientCfg.Protocol.Port)
	} else {
		addr := net.UDPAddr{IP: net.ParseIP(clientCfg.Protocol.Ip), Port: clientCfg.Protocol.Port}
		addrStr = addr.String()
	}

	err := ag.Init(clientCfg.Passwd)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("Auth failed.")
		return nil, err
	}

	for i := 0; i < clientCfg.MutilQueue; i++ {
		conn, err := quic.DialAddr(addrStr, tlsConfig, qConfig)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"RemoteAddr": addrStr,
				"Error":      err,
			}).Errorln("Connect to RemoteAddr failed.")
			return nil, err
		}
		stream, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("QUIC Accept Stream failed.")
			return nil, err
		}
		err = quicutil.WriteQUIC(stream, tunNameBuf, len(tunNameBuf))
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("Auth failed.")
			return nil, err
		}
		stamp := time.Now().UTC().Unix()
		stampEnc, err := ag.Encrypt([]byte(strconv.FormatInt(stamp, 10)))
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("Auth failed.")
			return nil, err
		}
		err = quicutil.WriteQUIC(stream, stampEnc, len(stampEnc))
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("Auth failed.")
			stream.Close()
			return nil, err
		}
		n, err := quicutil.ReadQUIC(stream, buf)
		if err != nil || string(buf[:n]) != "ok" {
			if err == nil {
				err = errors.New(string(buf[:n]))
			}
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("Auth failed.")
			stream.Close()
			return nil, err
		}
		streamSet = append(streamSet, stream)
	}
	return streamSet, nil
}
