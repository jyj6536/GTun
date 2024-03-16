package tunnelInit

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
	"tunproject/cfgUtil"
	"tunproject/event"

	"github.com/quic-go/quic-go"
	"github.com/sirupsen/logrus"
)

func addTuntoEpoll(fd int) (int, []syscall.EpollEvent, error) {
	epfd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"TuName": cfgUtil.CCfg.TunnelName,
			"Error":  err,
		}).Errorln("Creating Epoll Error.")
		return 0, nil, err
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
		return 0, nil, err
	}
	return epfd, ev, err
}

func ClientInit() error {
	logrus.Debugln("Start Initializing Client.")

	if cfgUtil.CCfg.Protocol == "tcp" {
		//go verify(authutil.TcpClientVerify, clientCfg)
		addr := &net.TCPAddr{Port: cfgUtil.CCfg.TCP.Port, IP: net.ParseIP(cfgUtil.CCfg.TCP.Ip)}
		conn, err := net.DialTCP("tcp", nil, addr)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"TuName":      cfgUtil.CCfg.TunnelName,
				"Server Addr": addr,
				"Error":       err,
			}).Errorln("Cann't connect to server.")
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

		epfd, ev, err := addTuntoEpoll(fd)
		if err != nil {
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
				if err != nil && err != syscall.EAGAIN {
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
			tuNameBuf := cfgUtil.PacketEncode(cfgUtil.CCfg.TunnelName, []byte{})
			buf := make([]byte, event.RBufMaxLen)
			keepalive := cfgUtil.CCfg.TCP.Keepalive * int(time.Second) / int(time.Millisecond)
			var err error
			var n int
			for {
				n, err = syscall.EpollWait(epfd, ev, keepalive)
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
						data := cfgUtil.PacketEncode(cfgUtil.CCfg.TunnelName, buf[:n])
						err = event.TcpWrite(*conn, data, cfgUtil.CCfg.TCP.Timeout)
						if err != nil {
							goto Stop
						}
					}
				} else if n == 0 {
					err = event.TcpWrite(*conn, tuNameBuf, cfgUtil.CCfg.TCP.Timeout)
					if err != nil {
						goto Stop
					}
				} else {
					logrus.WithFields(logrus.Fields{
						"Error": err,
					}).Errorln("EpollWait Error.")
				}
			}
		Stop:
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("ReadTunToTcpClient Error.")
		}()

	} else if cfgUtil.CCfg.Protocol == "icmp" {
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

		epfd, ev, err := addTuntoEpoll(fd)
		if err != nil {
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
				if icmp.Type != event.Reply || icmp.Identifier != cfgUtil.CCfg.ICMP.Identifier {
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
			keepalive := cfgUtil.CCfg.ICMP.Keepalive * int(time.Second) / int(time.Millisecond)
			for {
				n, err := syscall.EpollWait(epfd, ev, keepalive)
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
	} else if cfgUtil.CCfg.Protocol == "udp" {
		addr, err := net.ResolveUDPAddr("udp", cfgUtil.CCfg.UDP.Ip+":"+strconv.Itoa(cfgUtil.CCfg.UDP.Port))
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("Addr Resolve Error.")
			return err
		}
		conn, err := net.DialUDP("udp", nil, addr)
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

		epfd, ev, err := addTuntoEpoll(fd)
		if err != nil {
			return err
		}

		go func() {
			buf := make([]byte, event.RBufMaxLen)

			for {
				n, err := conn.Read(buf)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"Error": err,
					}).Errorln("Read Udp Error.")
					continue
				}
				p := cfgUtil.PacketDecode(buf[:n])
				if p == nil {
					err = errors.New("bad udp data")
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
			keepalive := cfgUtil.CCfg.UDP.Keepalive * int(time.Second) / int(time.Millisecond)
			for {
				n, err := syscall.EpollWait(epfd, ev, keepalive)
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

						_, err = conn.Write(cfgUtil.PacketEncode(cfgUtil.CCfg.TunnelName, buf[:n]))
						if err != nil {
							logrus.WithFields(logrus.Fields{
								"Error": err,
							}).Errorln("Write Udp Error.")
						}
					}
				} else if n == 0 { //send probe packet
					_, err = conn.Write(tuNameBuf)
					if err != nil {
						logrus.WithFields(logrus.Fields{
							"Error": err,
						}).Errorln("Write Udp Error.")
					}
				} else {
					logrus.WithFields(logrus.Fields{
						"Error": err,
					}).Errorln("EpollWait Error.")
				}
			}
		}()
	} else if cfgUtil.CCfg.Protocol == "quic" {
		tlsConfig := &tls.Config{InsecureSkipVerify: cfgUtil.CCfg.QUIC.AllowInSecure, NextProtos: []string{"quic-tunproject"}}
		addrStr := ""
		qConfig := &quic.Config{HandshakeIdleTimeout: time.Second * time.Duration(cfgUtil.CCfg.QUIC.ShakeTime), MaxIdleTimeout: time.Second * time.Duration(cfgUtil.CCfg.QUIC.IdleTime)}

		if cfgUtil.CCfg.QUIC.QuicUrl != "" {
			addrStr = cfgUtil.CCfg.QUIC.QuicUrl + ":" + strconv.Itoa(cfgUtil.CCfg.QUIC.Port)
		} else {
			addr := net.UDPAddr{IP: net.ParseIP(cfgUtil.CCfg.QUIC.Ip), Port: cfgUtil.CCfg.QUIC.Port}
			addrStr = addr.String()
		}
		conn, err := quic.DialAddr(context.Background(), addrStr, tlsConfig, qConfig)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"RemoteAddr": addrStr,
				"Error":      err,
			}).Errorln("Connect to RemoteAddr Error.")
			return err
		}

		stream, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("QUIC Open Stream Error.")
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

		epfd, ev, err := addTuntoEpoll(fd)
		if err != nil {
			return err
		}

		go func() {
			defer func() {
				stream.Close()
				syscall.Close(fd)
			}()
			buf := make([]byte, 65536)
			var err error
			var n int
			for {
				n, err = QuicRead(stream, buf, 0)
				if err != nil {
					goto Stop
				}
				p := cfgUtil.PacketDecode(buf[:n])
				_, err = syscall.Write(fd, p.Frame)
				if err != nil && err != syscall.EAGAIN {
					goto Stop
				}
			}
		Stop:
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("ReadQuicToTunClient Error.")
		}()

		go func() {
			defer func() {
				stream.Close()
				syscall.Close(fd)
			}()
			tuNameBuf := cfgUtil.PacketEncode(cfgUtil.CCfg.TunnelName, []byte{})
			buf := make([]byte, event.RBufMaxLen)
			keepalive := cfgUtil.CCfg.QUIC.Keepalive * int(time.Second) / int(time.Millisecond)
			var err error
			var n int
			for {
				n, err = syscall.EpollWait(epfd, ev, keepalive)
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
						data := cfgUtil.PacketEncode(cfgUtil.CCfg.TunnelName, buf[:n])
						err = QuicWrite(stream, data, cfgUtil.CCfg.QUIC.Timeout)
						if err != nil {
							goto Stop
						}
					}
				} else if n == 0 {
					err = QuicWrite(stream, tuNameBuf, cfgUtil.CCfg.TCP.Timeout)
					if err != nil {
						goto Stop
					}
				} else {
					logrus.WithFields(logrus.Fields{
						"Error": err,
					}).Errorln("EpollWait Error.")
				}
			}
		Stop:
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("ReadTunToQUICClient Error.")
		}()
	} else {
		logrus.WithFields(logrus.Fields{
			"Protocol": cfgUtil.CCfg.Protocol,
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

var rCallback [event.CallbackNum]event.Callback
var wCallback [event.CallbackNum]event.Callback
var eCallback [event.CallbackNum]event.Callback

func ServerInit() error {
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
		err = event.TcpListenerInit(cfgUtil.SCfg.TCP.IP, cfgUtil.SCfg.TCP.Port, 10)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("TcpInit Failed.")
		}
	}

	if cfgUtil.SCfg.UDP.Enable {
		err = event.UdpListenerInit(cfgUtil.SCfg.UDP.IP, cfgUtil.SCfg.UDP.Port)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Error": err,
			}).Errorln("UdpInit Failed.")
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

	if cfgUtil.SCfg.QUIC.Enable {
		if cfgUtil.SCfg.UnixFile == "" {
			cfgUtil.SCfg.UnixFile = "./tun.sock"
		}

		err = event.UnixListenerInit(cfgUtil.SCfg.UnixFile, 10)
		if err != nil {
			return err
		}

		err = serverQUICListen()
		if err != nil {
			return err
		}
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
	return nil
}

func serverQUICListen() error {
	tlsConfig, err := GenerateTlsConfig(cfgUtil.SCfg.QUIC.CertPath, cfgUtil.SCfg.QUIC.KeyPath)
	qConfig := &quic.Config{HandshakeIdleTimeout: time.Second * time.Duration(cfgUtil.SCfg.QUIC.ShakeTime), MaxIdleTimeout: time.Second * time.Duration(cfgUtil.SCfg.QUIC.IdleTime)}
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("Generate TLS Config Failed.")
		return err
	}
	addr := net.UDPAddr{IP: net.ParseIP(cfgUtil.SCfg.QUIC.IP), Port: cfgUtil.SCfg.QUIC.Port}

	listener, err := quic.ListenAddr(addr.String(), tlsConfig, qConfig)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("QUIC Listen Failed.")
		return err
	}

	go func() {
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
			go func() {
				fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"Error": err,
					}).Errorln("Creating UnixSocket Error.")
					return
				}

				addr := &syscall.SockaddrUnix{Name: cfgUtil.SCfg.UnixFile}
				err = syscall.Connect(fd, addr)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"Error": err,
					}).Errorln("Creating UnixSocket Error.")
					return
				}
				go func() {
					defer func() {
						stream.Close()
						syscall.Close(fd)
					}()
					var n int
					var err error
					buf := make([]byte, event.RBufMaxLen)
					for {
						n, err = QuicRead(stream, buf, 0)
						if err != nil {
							goto Stop
						}
						_, err = syscall.Write(fd, buf[:n])
						if err != nil {
							goto Stop
						}
					}
				Stop:
					logrus.WithFields(logrus.Fields{
						"Error": err,
					}).Errorln("ReadQuicToUnix Error.")
				}()
				go func() {
					defer func() {
						stream.Close()
						syscall.Close(fd)
					}()
					buf := make([]byte, event.RBufMaxLen)
					var n int
					var err error
					for {
						n, err = syscall.Read(fd, buf)
						if err != nil {
							goto Stop
						}
						err = QuicWrite(stream, buf[:n], cfgUtil.SCfg.QUIC.Timeout)
						if err != nil {
							goto Stop
						}
					}
				Stop:
					logrus.WithFields(logrus.Fields{
						"Error": err,
					}).Errorln("ReadUnixToQuic Error.")
				}()
			}()
		}
	}()
	return err
}
