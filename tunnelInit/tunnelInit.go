package tunnelInit

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
	authutil "tunproject/authUtil"
	"tunproject/cfgUtil"
	protocolutil "tunproject/protocolUtil"
	icmputil "tunproject/protocolUtil/icmpUtil"
	quicutil "tunproject/protocolUtil/quicUtil"
	tunutil "tunproject/tunUtil"

	"github.com/lucas-clemente/quic-go"
	"github.com/sirupsen/logrus"
)

func ClientInit(clientCfg *cfgUtil.ClientCfg) error {
	logrus.Debugln("Start Initializing Client.")

	if clientCfg.Protocol == "icmp" {
		clientCfg.MutilQueue = 1
	}

	ifaceSet, err := tunutil.NewTun(clientCfg)
	if err != nil {
		return err
	}

	if clientCfg.Protocol == "tcp" {
		connSet, err := authutil.AuthClient(clientCfg)
		if err != nil {
			return err
		}
		if clientCfg.TCP.KeepaLvie > 0 { //use tcp keepalive to keep tcp nat session
			if clientCfg.TCP.KeepaLvie < 5 {
				clientCfg.TCP.KeepaLvie = 5
			}
			logrus.WithFields(logrus.Fields{
				"Keepalive": clientCfg.TCP.KeepaLvie,
			}).Debugln("Set keepalive for tcp conn.")
			for _, conn := range connSet {
				err = protocolutil.SetTcpKeepalive(clientCfg.TCP.KeepaLvie, conn)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"Error": err,
					}).Infoln("Set Keepavlive failed.")
				}
			}
		}

		cfgUtil.TunStsClient.ActiveConn = int32(len(connSet))

		for i := 0; i < int(cfgUtil.TunStsClient.ActiveConn); i++ {
			go protocolutil.ReadTunToTcpClient(connSet[i], ifaceSet[i])
			go protocolutil.ReadTcpToTunClient(connSet[i], ifaceSet[i])
		}
	} else if clientCfg.Protocol == "icmp" {
		conn, icmp, err := authutil.AuthlClientIcmp(clientCfg)
		if err != nil {
			return err
		}

		cfgUtil.IcmpTunStsCtrl.Store("ClientIcmpTimeoutCtrl", &cfgUtil.IcmpTunCtrl{Time: time.Now()})

		go func() { //this goroutine scan cfgUtil.IcmpIface periodicity to check whether server is available or not, if not, stop client iteself
			ticker := time.NewTicker(time.Second * time.Duration(clientCfg.ICMP.BreakTime))
			for range ticker.C {
				value, ok := cfgUtil.IcmpTunStsCtrl.Load("ClientIcmpTimeoutCtrl")
				if ok {
					v := value.(*cfgUtil.IcmpTunCtrl)
					if time.Since(v.Time) > time.Minute {
						syscall.Kill(os.Getpid(), syscall.SIGINT)
					}
				}
			}
		}()

		go protocolutil.ReadIcmpToTun(conn, ifaceSet[0])
		go protocolutil.ReadTunToIcmp(conn, ifaceSet[0], icmp, clientCfg.ICMP.KeepaLvie)
	} else if clientCfg.Protocol == "quic" {
		streamSet, err := authutil.AuthQUICClient(clientCfg)
		if err != nil {
			return err
		}

		err = streamSet[0].SetReadDeadline(time.Now().Add(time.Second * time.Duration(clientCfg.QUIC.Timeout)))
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("Set ReadDeadline failed.")
			return err
		}

		err = quicutil.WriteQUIC(streamSet[0], []byte{0x00}, 1)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("Write To Server failed.")
			return err
		}

		cfgUtil.TunStsClient.ActiveConn = int32(len(streamSet))

		for i := 0; i < len(streamSet); i++ {
			go quicutil.ReadTunToQUICClient(streamSet[i], ifaceSet[i], clientCfg.QUIC.Timeout)
			go quicutil.ReadQUICToTunClient(streamSet[i], ifaceSet[i], clientCfg.QUIC.Timeout)
		}
	}

	sigs := make(chan os.Signal)
	done := make(chan bool)

	signal.Notify(sigs, os.Interrupt)

	go func() {
		<-sigs
		logrus.Debugln("Get SIGINT.")
		done <- true
	}()

	<-done

	logrus.Debugln("Process Exited.")

	return err
}

func ServerInit(serverCfg *cfgUtil.ServerCfg) error {
	var err error
	if serverCfg.TCP.Enable {
		err = serverTcpListen(serverCfg)
		if err != nil {
			return err
		}
	}

	if serverCfg.ICMP.Enable {
		err = serverIcmpListen(serverCfg)
		if err != nil {
			return err
		}
	}

	if serverCfg.QUIC.Enable {
		err = serverQUICListen(serverCfg)
		if err != nil {
			return err
		}
	}

	sigs := make(chan os.Signal)
	done := make(chan bool)

	signal.Notify(sigs, os.Interrupt)

	go func() {
		<-sigs
		done <- true
	}()

	<-done
	return nil
}

func serverTcpListen(serverCfg *cfgUtil.ServerCfg) error {
	addr := &net.TCPAddr{Port: serverCfg.TCP.Port, IP: net.ParseIP(serverCfg.TCP.IP)}
	connServer, err := net.ListenTCP("tcp", addr)

	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Addr":  addr,
			"Error": err,
		}).Errorln("TcpListen failed.")
		return err
	}

	go func(connServer *net.TCPListener) {
		for {
			conn, err := connServer.AcceptTCP() //tcp port listening
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"Error": err,
				}).Errorln("Tcp Accept failed.")
				continue
			}
			go authutil.Auth(conn, serverCfg)
		}
	}(connServer)
	return err
}

func serverIcmpListen(scfg *cfgUtil.ServerCfg) error {
	var err error
	icmputil.ConnServer, err = net.ListenPacket("ip:icmp", scfg.ICMP.IP)

	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Addr":  scfg.ICMP.IP,
			"Error": err,
		}).Errorln("IcmpListen failed.")
		return err
	}

	go icmputil.WriteToConnServer() //this goroutine receive data from C and send to ConnServer

	go func() { //this goroutine scan cfgUtil.IcmpTunStsCtrl periodicity to remove icmp tunnel which is timed out
		ticker := time.NewTicker(time.Second * time.Duration(scfg.ICMP.Timeout))
		for range ticker.C { //scan periodicity per minute
			cfgUtil.IcmpTunStsCtrl.Range(func(key, value interface{}) bool {
				v := value.(*cfgUtil.IcmpTunCtrl)
				if time.Since(v.Time) > time.Minute { //no packet transfering in one minute
					if v.CancelFunc != nil {
						v.CancelFunc()
					}
					v.Iface.Close()
					tuName := v.TuName
					cfgUtil.TunStsMap.Delete(tuName)
					logrus.WithFields(logrus.Fields{
						"TuName": tuName,
					}).Debugln("Tunnel Finished.")
					cfgUtil.IcmpTunStsCtrl.Delete(key)
				}
				return true
			})
		}
	}()

	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := icmputil.ConnServer.ReadFrom(buf)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"Addr":  addr,
					"Error": err,
				}).Errorln("Icmp Read Error.")
				continue
			}
			icmp := &icmputil.ICMP{}
			if !icmp.Construct(buf[:n]) {
				logrus.WithFields(logrus.Fields{
					"Error": errors.New("bad icmp packet"),
				}).Errorln("Decode Icmp Packet failed.")
				continue
			}
			if icmp.Type == icmputil.Reply {
				continue
			}
			if len(icmp.Data) == 0 {
				continue
			}
			switch icmp.Data[0] {
			case 0x01, 0x02:
				authutil.AuthIcmp(icmp, addr, scfg)
			case 0x03:
				key := addr.String() + "+" + strconv.FormatUint(uint64(icmp.Identifier), 10)
				//value, ok := cfgUtil.IcmpIface.Load(key)
				value, ok := cfgUtil.IcmpTunStsCtrl.Load(key)
				if ok {
					icmpTunCtrl := value.(*cfgUtil.IcmpTunCtrl)
					iface := icmpTunCtrl.Iface
					_, err := iface.Write(icmp.Data[1:])
					if err != nil {
						logrus.WithFields(logrus.Fields{
							"DeviceName": iface.Name(),
							"Error":      err,
						}).Errorln("Write to Tun Error.")
					}
					icmpTunCtrl.Time = time.Now()
				}

			case 0x04: //update cfgUtil.IcmpTunStsCtrl and send keepalive reply to client
				key := addr.String() + "+" + strconv.FormatUint(uint64(icmp.Identifier), 10)
				value, ok := cfgUtil.IcmpTunStsCtrl.Load(key)
				if ok {
					icmpTunCtrl := value.(*cfgUtil.IcmpTunCtrl)
					icmpTunCtrl.Time = time.Now()
					retIcmp := icmp.Create(icmputil.Reply, icmp.Code, icmp.Identifier, icmp.SeqNum, []byte{0x04})
					icmputil.C <- &icmputil.IcmpData{Addr: addr, IcmpPacket: retIcmp}
				}
			default:
			}
		}
	}()
	return err
}

func serverQUICListen(scfg *cfgUtil.ServerCfg) error {
	tlsConfig, err := quicutil.GenerateTlsConfig(scfg.QUIC.CertPath, scfg.QUIC.KeyPath)
	qConfig := &quic.Config{HandshakeIdleTimeout: time.Second * time.Duration(scfg.QUIC.Timeout), MaxIdleTimeout: time.Second * time.Duration(scfg.QUIC.Timeout), KeepAlive: true}
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("Generate TLS Config failed.")
		return err
	}
	addr := net.UDPAddr{IP: net.ParseIP(scfg.QUIC.IP), Port: scfg.QUIC.Port}

	listener, err := quic.ListenAddr(addr.String(), tlsConfig, qConfig)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("QUIC Listen failed.")
		return err
	}

	go func(listener quic.Listener) {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"Error": err,
				}).Errorln("QUIC Accept failed.")
				continue
			}
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"Error": err,
				}).Errorln("QUIC Accept Stream failed.")
				continue
			}
			go authutil.AuthQUIC(stream, scfg)
		}
	}(listener)
	return err
}
