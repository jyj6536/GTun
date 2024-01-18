package cfgUtil

import (
	"encoding/json"
	"os"
	"syscall"
	"tunproject/event"
	"tunproject/helper"

	"github.com/sirupsen/logrus"
)

var CCfg *ClientCfg
var SCfg *ServerCfg

type TfdInfo struct {
	Nfd     int32
	TuName  string
	Addr    syscall.Sockaddr
	IcmpSrc *event.ICMP
}

type NfdInfo struct {
	Tfd    int32
	TuName string
	Te     *event.TimeEvent
}

var AtoT map[string]NfdInfo = map[string]NfdInfo{} //used for icmp and udp
var NtoT map[int32]NfdInfo = map[int32]NfdInfo{}   //used for tcp
var TtoN map[int32]TfdInfo = map[int32]TfdInfo{}
var DataTransfer map[string]*helper.RingBuffer[[]byte] = map[string]*helper.RingBuffer[[]byte]{}

type Tcp struct {
	Ip        string `json:"ip"`
	Port      int    `json:"port"`
	Keepalive int    `json:"keepalive"` //set keepalive_probes(count of keepalive probe packets) and keepalive_time(idle time before starting keepalive, 0 means that don't use keepalive)
	Timeout   int    `json:"timeout"`   //timeout used in send
}

type Icmp struct {
	Ip         string `json:"ip"`
	Identifier uint16 `json:"identifier"`
	Timeout    int    `json:"timeout"`    //timeout used in connecting
	Keepalive  int    `json:"keepalive"`  //interval between two probe packets(0 means default and default is 1s, should be less than breakTime)
	RetryTimes int    `json:"retryTimes"` //when connecting to server, how many times client will retry if connecting times out(minimum is 1)
	BreakTime  int    `json:"breakTime"`  //how long it will take before client abandons the tunnel when it don't receive any packet from the server(recommended minimum is 20s)
}

type QUIC struct {
	Ip            string `json:"ip"`
	QuicUrl       string `json:"quicUrl"`
	Port          int    `json:"port"`
	AllowInSecure bool   `json:"allowInSecure"`
	ShakeTime     int    `json:"shakeTime"` //ssl shakehand timeout(0 means default and default is 5s)
	IdleTime      int    `json:"idleTime"`  //maximum duration that may pass without any incoming network activity(0 means default and default is 30s, the actual value for the idle timeout is the minimum of this value and the peer's)
	Timeout       int    `json:"timeout"`   //timeout used in send or receive(recommended minimum is 5s)
	Keepalive     int    `json:"keepalive"` //time before quic to send a probe packet
}

type ClientCfg struct {
	Type       string `json:"type"`
	Protocol   string `json:"protocol"`
	PidFile    string `json:"pidfile"`
	TCP        Tcp    `json:"tcp"`
	ICMP       Icmp   `json:"icmp"`
	QUIC       QUIC   `json:"quic"`
	TunnelName string `json:"tunnelName"`
	Passwd     string `json:"passwd"`
	DeviceType string `json:"deviceType"`
	DeviceName string `json:"deviceName"`
	MutilQueue int    `json:"mutilQueue"`
	Network    string `json:"network"`
}

func LoadClientCfg(path string) (*ClientCfg, error) {
	logrus.Debugln("Start Loading Client Config File.")
	var clientCfg *ClientCfg = new(ClientCfg)
	content, err := os.ReadFile(path)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error":    err,
			"FilePath": path,
		}).Errorln("Read ClientCfg error.")
		return nil, err
	}
	err = json.Unmarshal(content, clientCfg)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("Unmarshal Client Config File error.")
		return nil, err
	}

	if clientCfg.ICMP.Keepalive == 0 {
		clientCfg.ICMP.Keepalive = 1
	}

	logrus.WithFields(logrus.Fields{
		"CfgInfo": clientCfg,
	}).Debugln("End Loading Client Config File.")
	CCfg = clientCfg
	return clientCfg, nil
}

type TunnelCfg struct {
	TunnelName string `json:"tunnelName"`
	Passwd     string `json:"passwd"`
	DeviceType string `json:"deviceType"`
	DeviceName string `json:"deviceName"`
	Network    string `json:"network"`
}

type ServerCfg struct {
	Type    string      `json:"type"` //config file type : must be server
	PidFile string      `json:"pidfile"`
	TCP     TCPCfg      `json:"tcp"`
	ICMP    ICMPCfg     `json:"icmp"`
	QUIC    QUICCfg     `json:"quic"`
	Tunnels []TunnelCfg `json:"tunnels"`
}

type TCPCfg struct {
	Enable  bool   `json:"enable"`
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Timeout int    `json:"timeout"` //timeout used in send(recommended minimum is 5s)
}

type ICMPCfg struct {
	Enable    bool   `json:"enable"`
	IP        string `json:"ip"`
	BreakTime int    `json:"breakTime"` //how long it will take before server abandons the tunnel when it don't receive any packet from the client(recommended minimum is 20s)
}

type QUICCfg struct {
	Enable     bool   `json:"enable"`
	Port       int    `json:"port"`
	IP         string `json:"ip"`
	CertPath   string `json:"certPath"`  //public key
	KeyPath    string `json:"keyPath"`   //private key
	ShakeTime  int    `json:"shakeTime"` //ssl shakehand timeout(0 means default and default is 5s)
	IdleTime   int    `json:"idleTime"`  //maximum duration that may pass without any incoming network activity(0 means default and default is  30s, the actual value for the idle timeout is the minimum of this value and the peer's)
	Timeout    int    `json:"timeout"`   //timeout used in send or receive
	Keepavlive int    `json:"keepalive"` //time before quic to send a probe packet
}

func LoadServerCfg(path string) (*ServerCfg, error) {
	logrus.Debugln("Start Loading Server Config File.")
	var serverCfg *ServerCfg = new(ServerCfg)
	content, err := os.ReadFile(path)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error":    err,
			"FilePath": path,
		}).Errorln("Read ServerCfg error.")
		return nil, err
	}
	err = json.Unmarshal(content, serverCfg)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Error": err,
		}).Errorln("Unmarshal Server Config File error.")
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"CfgInfo": serverCfg,
	}).Debugln("End Loading Server Config File.")
	SCfg = serverCfg
	return serverCfg, nil
}

func TunExist(tunName string) *TunnelCfg {
	for _, t := range SCfg.Tunnels {
		if t.TunnelName == tunName {
			return &t
		}
	}
	return nil
}

type Packet struct {
	TuName string
	Frame  []byte
}

func PacketDecode(data []byte) *Packet {
	p := &Packet{}
	n := int(data[0])
	if n+1 > len(data) {
		return nil
	}
	p.TuName = string(data[1 : n+1])
	p.Frame = data[n+1:]
	return p
}

func PacketEncode(tuName string, frame []byte) []byte {
	var data []byte
	data = append(data, byte(len(tuName)))
	data = append(data, []byte(tuName)...)
	return append(data, frame...)
}
