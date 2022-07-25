package tunutil

import (
	"errors"
	"tunproject/cfgUtil"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

func NewTun(clientCfg *cfgUtil.ClientCfg) (ifaceSet []*water.Interface, err error) {
	logrus.Debugln("Start Creating Tun/Tap Device.")

	var link netlink.Link
	_, err = netlink.LinkByName(clientCfg.DeviceName)
	if err == nil {
		logrus.WithFields(logrus.Fields{
			"DeviceName": clientCfg.DeviceName,
			"Error":      err,
		}).Errorln("Device May Exist.")
		return nil, errors.New("device may exist")
	}

	var dt water.DeviceType
	var mqueue bool = true

	if clientCfg.DeviceType == "tun" {
		dt = water.TUN
	} else {
		dt = water.TAP
	}

	if clientCfg.MutilQueue == 1 {
		mqueue = false
	} else if clientCfg.MutilQueue < 0 || clientCfg.MutilQueue > 8 {
		clientCfg.MutilQueue = 8
	}

	config := water.Config{
		DeviceType: dt,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name:       clientCfg.DeviceName,
			Persist:    false,
			MultiQueue: mqueue,
		},
	}

	for i := 0; i < clientCfg.MutilQueue; i++ {
		iface, err := water.New(config)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"DeviceName": clientCfg.DeviceName,
				"Error":      err,
			}).Errorln("Cann't Create Tun Device.")
			return nil, err
		}
		ifaceSet = append(ifaceSet, iface)
	}

	link, err = netlink.LinkByName(clientCfg.DeviceName)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"DeviceName": clientCfg.DeviceName,
			"Error":      err,
		}).Errorln("Cann't Get Device by NetLink.")
		return
	}

	var addr *netlink.Addr
	addr, err = netlink.ParseAddr(clientCfg.Network)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"NetWork": clientCfg.Network,
			"Error":   err,
		}).Errorln("Error While Parsing network.")
		return nil, err
	}

	err = netlink.AddrAdd(link, addr)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Addr":       addr,
			"DeviceName": clientCfg.DeviceName,
			"Error":      err,
		}).Errorln("Cann't Set Addr for Device.")
		return
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"DeviceName": clientCfg.DeviceName,
			"Error":      err,
		}).Errorln("Cann't Set Device up.")
		return
	}
	logrus.WithFields(logrus.Fields{
		"DeviceName": clientCfg.DeviceName,
		"Addr":       addr,
	}).Debugln("End Creating Tun/Tap Device.")

	err = nil
	return
}
