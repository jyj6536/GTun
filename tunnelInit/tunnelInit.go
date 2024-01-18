package tunnelInit

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	authutil "tunproject/authUtil"
	"tunproject/authUtil/cipherUtil"
	"tunproject/cfgUtil"
	"tunproject/event"
	quicutil "tunproject/protocolUtil/quicUtil"
	tunutil "tunproject/tunUtil"

	"github.com/quic-go/quic-go"
	"github.com/sirupsen/logrus"
)

func ClientInit(clientCfg *cfgUtil.ClientCfg) error {
	logrus.Debugln("Start Initializing Client.")

	if cfgUtil.CCfg.Protocol == "tcp" {
		//go verify(authutil.TcpClientVerify, clientCfg)
		addr := &net.TCPAddr{Port: cfgUtil.CCfg.TCP.Port, IP: net.ParseIP(cfgUtil.CCfg.TCP.Ip)}

		ag := &cipherUtil.AesGcm{}
		err := ag.Init(cfgUtil.CCfg.Passwd)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"TuName": cfgUtil.CCfg.TunnelName,
				"Error":  err,
			}).Errorln("Create AesCipher Failed.")
			return err
		}

		conn, err := net.DialTCP("tcp", nil, addr)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"TuName":      cfgUtil.CCfg.TunnelName,
				"Server Addr": addr,
				"Error":       err,
			}).Errorln("Cann't connect to server.")
			return err
		}

		if cfgUtil.CCfg.TCP.Keepalive > 0 {
			err = event.SetTcpKeepalive(cfgUtil.CCfg.TCP.Keepalive, conn)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"Error": err,
				}).Infoln("Set Keepavlive failed.")
			}
		}

		var deviceType int
		if cfgUtil.CCfg.DeviceType == "tun" {
			deviceType = event.TUN
		} else {
			deviceType = event.TAP
		}
		fd, err := event.CreateTun(deviceType, cfgUtil.CCfg.DeviceName, cfgUtil.CCfg.Network, true)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"TuName": cfgUtil.CCfg.TunnelName,
				"Error":  err,
			}).Errorln("Creating Tap/Tun Device Error.")
			return err
		}

		go func() {
			defer func() {
				conn.Close()
				syscall.Close(fd)
			}()
			buf := make([]byte, event.RBufMaxLen)
			var err error
			var n int
			for {
				n, err = event.TcpRead(*conn, buf, 0)
				if err != nil {
					goto Stop
				}
				p := cfgUtil.PacketDecode(buf[:n])
				_, err = syscall.Write(fd, p.Frame)
				if err != nil {
					goto Stop
				}
			}
		Stop:
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("ReadTcpToTunClient Error.")
		}()

		go func() {
			defer func() {
				conn.Close()
				syscall.Close(fd)
			}()
			buf := make([]byte, event.RBufMaxLen)
			var err error
			var n int
			for {
				n, err = syscall.Read(fd, buf)
				if err != nil {
					goto Stop
				}
				data := cfgUtil.PacketEncode(cfgUtil.CCfg.TunnelName, buf[:n])
				err = event.TcpWrite(*conn, data, cfgUtil.CCfg.TCP.Timeout)
				if err != nil {
					goto Stop
				}
			}
		Stop:
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("ReadTunToTcpClient Error.")
		}()

	} else if cfgUtil.CCfg.Protocol == "icmp" {
		ag := &cipherUtil.AesGcm{}
		err := ag.Init(cfgUtil.CCfg.Passwd)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("Create AesCipher Error.")
			return err
		}

		addr, err := net.ResolveIPAddr("ip", cfgUtil.CCfg.ICMP.Ip)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("Addr Resolve Error.")
			return err
		}
		conn, err := net.DialIP("ip:icmp", nil, addr)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("Create Socket Error.")
			return err
		}

		var deviceType int
		if cfgUtil.CCfg.DeviceType == "tun" {
			deviceType = event.TUN
		} else {
			deviceType = event.TAP
		}
		fd, err := event.CreateTun(deviceType, cfgUtil.CCfg.DeviceName, cfgUtil.CCfg.Network, false)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"TuName": cfgUtil.CCfg.TunnelName,
				"Error":  err,
			}).Errorln("Creating Tap/Tun Device Error.")
			return err
		}

		epfd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"TuName": cfgUtil.CCfg.TunnelName,
				"Error":  err,
			}).Errorln("Creating Epoll Error.")
			return err
		}
		ev := make([]syscall.EpollEvent, 1)
		ev[0].Fd = int32(fd)
		ev[0].Events = syscall.EPOLLIN
		err = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd, &ev[0])
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"TuName": cfgUtil.CCfg.TunnelName,
				"Error":  err,
			}).Errorln("Add Fd to Epoll Error.")
			return err
		}

		go func() {
			buf := make([]byte, event.RBufMaxLen)

			for {
				n, err := conn.Read(buf)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"Error": err,
					}).Errorln("Read Icmp Error.")
					continue
				}
				icmp := event.IcmpConstruct(buf[:n])
				if icmp == nil {
					err = errors.New("bad icmp packet")
					logrus.WithFields(logrus.Fields{
						"Error": err,
					}).Errorln("Bad Response.")
					continue
				}
				if icmp.Type != event.Reply {
					continue
				}
				p := cfgUtil.PacketDecode(icmp.Data)
				if p == nil {
					err = errors.New("bad icmp data")
					logrus.WithFields(logrus.Fields{
						"Error": err,
					}).Errorln("Bad Response.")
					continue
				}
				if p.TuName != cfgUtil.CCfg.TunnelName {
					continue
				}
				if len(p.Frame) == 0 { //receive probe response
					continue
				}
				_, err = syscall.Write(fd, p.Frame)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"Error": err,
					}).Errorln("Write Tun Error.")
				}
			}
		}()

		go func() {
			tuNameBuf := cfgUtil.PacketEncode(cfgUtil.CCfg.TunnelName, []byte{})
			buf := make([]byte, event.RBufMaxLen)
			timeout := cfgUtil.CCfg.ICMP.Keepalive * int(time.Second) / int(time.Millisecond)
			for {
				n, err := syscall.EpollWait(epfd, ev, timeout)
				if n > 0 {
					for {
						n, err = syscall.Read(fd, buf)
						if err == syscall.EAGAIN {
							break
						}
						if err != nil {
							logrus.WithFields(logrus.Fields{
								"Error": err,
							}).Errorln("Read Tun Errror.")
							break
						}
						data := event.IcmpCreate(event.Request, 0, cfgUtil.CCfg.ICMP.Identifier, cfgUtil.CCfg.ICMP.Identifier, cfgUtil.PacketEncode(cfgUtil.CCfg.TunnelName, buf[:n]))

						_, err = conn.Write(data)
						if err != nil {
							logrus.WithFields(logrus.Fields{
								"Error": err,
							}).Errorln("Write Icmp Error.")
						}
					}
				} else if n == 0 { //send probe packet
					data := event.IcmpCreate(event.Request, 0, cfgUtil.CCfg.ICMP.Identifier, cfgUtil.CCfg.ICMP.Identifier, tuNameBuf)

					_, err = conn.Write(data)
					if err != nil {
						logrus.WithFields(logrus.Fields{
							"Error": err,
						}).Errorln("Write Icmp Error.")
					}
				} else {
					logrus.WithFields(logrus.Fields{
						"Error": err,
					}).Errorln("EpollWait Error.")
				}
			}
		}()
	} else if clientCfg.Protocol == "quic" {
		go verify(authutil.QUICClientVerify, clientCfg)
	} else {
		logrus.WithFields(logrus.Fields{
			"Protocol": clientCfg.Protocol,
		}).Errorln("Unknown Protocol.")
		return nil
	}

	sigs := make(chan os.Signal, 1)
	done := make(chan bool)

	signal.Notify(sigs, os.Interrupt)

	go func() {
		<-sigs
		logrus.Debugln("Get SIGINT.")
		done <- true
	}()

	<-done

	logrus.Debugln("Process Exited.")
	return nil
}

func verify(f func(*cfgUtil.ClientCfg), clientCfg *cfgUtil.ClientCfg) {
	for i := 0; i < clientCfg.MutilQueue; i++ {
		f(clientCfg)
	}

	ticker := time.NewTicker(time.Second * time.Duration(10))
	failureCnt := 0
	for range ticker.C {
		if !tunutil.TunExist(clientCfg.DeviceName) {
			logrus.Debugln("Tun/Tap Device dosen't Exist.")
			failureCnt++
			logrus.WithFields(logrus.Fields{
				"failureCnt": failureCnt,
			}).Debugln("Start Verifying.")
			for i := 0; i < clientCfg.MutilQueue; i++ {
				f(clientCfg)
			}
		}
	}
}

var rCallback [event.CallbackNum]event.Callback
var wCallback [event.CallbackNum]event.Callback
var eCallback [event.CallbackNum]event.Callback

func ServerInit(serverCfg *cfgUtil.ServerCfg) error {
	var err error

	err = event.EventInit(512, rCallback, wCallback, eCallback)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("EventInit Failed.")
		return err
	}

	go event.EventRun()

	if cfgUtil.SCfg.TCP.Enable {
		// err = serverTcpListen(serverCfg)
		// if err != nil {
		// 	return err
		// }
		err = event.TcpListenerInit(cfgUtil.SCfg.TCP.IP, cfgUtil.SCfg.TCP.Port, 10)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("TcpInit Failed.")
		}
	}

	if cfgUtil.SCfg.ICMP.Enable {
		err = event.IcmpListenerInit(cfgUtil.SCfg.ICMP.IP)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("IcmpInit Failed.")
		}
	}

	if serverCfg.QUIC.Enable {
		err = serverQUICListen(serverCfg)
		if err != nil {
			return err
		}
	}

	sigs := make(chan os.Signal, 1)
	done := make(chan bool)

	signal.Notify(sigs, os.Interrupt)

	go func() {
		<-sigs
		done <- true
	}()

	<-done
	return nil
}

func serverQUICListen(scfg *cfgUtil.ServerCfg) error {
	tlsConfig, err := quicutil.GenerateTlsConfig(scfg.QUIC.CertPath, scfg.QUIC.KeyPath)
	qConfig := &quic.Config{HandshakeIdleTimeout: time.Second * time.Duration(scfg.QUIC.ShakeTime), MaxIdleTimeout: time.Second * time.Duration(scfg.QUIC.IdleTime), KeepAlivePeriod: time.Duration(scfg.QUIC.Keepavlive)}
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("Generate TLS Config Failed.")
		return err
	}
	addr := net.UDPAddr{IP: net.ParseIP(scfg.QUIC.IP), Port: scfg.QUIC.Port}

	listener, err := quic.ListenAddr(addr.String(), tlsConfig, qConfig)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("QUIC Listen Failed.")
		return err
	}

	go func(listener *quic.Listener) {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"Error": err,
				}).Errorln("QUIC Accept Failed.")
				continue
			}
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"Error": err,
				}).Errorln("QUIC Accept Stream Failed.")
				continue
			}
			go authutil.QUICVerify(stream, scfg)
		}
	}(listener)
	return err
}
