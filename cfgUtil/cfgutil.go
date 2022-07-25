package cfgUtil

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"sync"
	"time"
	"tunproject/authUtil/cipherUtil"

	"github.com/lucas-clemente/quic-go"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

type TunnelSts struct {
	TunInfo    *TunnelCfg
	TokenInt   int64
	Sts        string
	TcpConn    []*net.TCPConn
	QUICStream []quic.Stream
	ActiveConn int32
	AesCipher  *cipherUtil.AesGcm
}

type TunnelStsClient struct {
	ActiveConn int32
}

var TunStsClient *TunnelStsClient = &TunnelStsClient{}

var TunStsMap sync.Map //store global status of tunnels

var IcmpTunStsCtrl sync.Map //store status of icmp tunnels(key+identifier,IcmpTunCtrl)

type IcmpTunCtrl struct {
	Time       time.Time
	CancelFunc context.CancelFunc
	TuName     string
	TuSts      *TunnelSts
	Iface      *water.Interface
}

var MutexQUIC sync.Mutex //this is used in AuthQUIC

type Protocol struct {
	Proto         string `json:"proto"`
	Ip            string `json:"ip"`
	QuicUrl       string `josn:"quicUrl"`       //for quic
	AllowInSecure bool   `json:"allowInSecure"` //for quic, true allow insecure cert
	Port          int    `json:"port"`          //port for tcp; while for icmp,this is used as identifier and seqnum
}

type ClientCfg struct {
	Type       string   `json:"type"`
	Protocol   Protocol `json:"protocol"`
	TunnelName string   `json:"tunnelName"`
	Passwd     string   `json:"passwd"`
	DeviceType string   `json:"deviceType"`
	DeviceName string   `json:"deviceName"`
	KeepaLvie  int      `json:"keepalive"`
	MutilQueue int      `json:"mutilQueue"`
	Network    string   `json:"network"`
	Timeout    int      `json:"timeout"`
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
	logrus.WithFields(logrus.Fields{
		"CfgInfo": clientCfg,
	}).Debugln("End Loading Client Config File.")
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
	TCP     TCPCfg      `json:"tcp"`
	ICMP    ICMPCfg     `json:"icmp"`
	QUIC    QUICCfg     `json:"quic"`
	Tunnels []TunnelCfg `json:"tunnels"`
}

type TCPCfg struct {
	Enable bool   `json:"enable"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
}

type ICMPCfg struct {
	Enable  bool   `json:"enable"`
	IP      string `json:"ip"`
	Timeout int    `json:"timeout"`
}

type QUICCfg struct {
	Enable   bool   `json:"enable"`
	Port     int    `json:"port"`
	IP       string `json:"ip"`
	CertPath string `json:"certPath"` //public key
	KeyPath  string `json:"keyPath"`  //private key
	Timeout  int    `json:"timeout"`
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
	return serverCfg, nil
}

func TunExist(tunName string, serverCfg *ServerCfg) *TunnelCfg {
	for _, t := range serverCfg.Tunnels {
		if t.TunnelName == tunName {
			return &t
		}
	}
	return nil
}
