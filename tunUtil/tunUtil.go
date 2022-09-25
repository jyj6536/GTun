package tunutil

import (
	"strings"
	"tunproject/cfgUtil"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

func NewTun(clientCfg *cfgUtil.ClientCfg) (iface *water.Interface, err error) {
	logrus.WithFields(logrus.Fields{
		"DeviceName": clientCfg.DeviceName,
	}).Debugln("Start Creating Tun/Tap Device.")

	var dt water.DeviceType
	if clientCfg.DeviceType == "tun" {
		dt = water.TUN
	} else {
		dt = water.TAP
	}

	config := water.Config{
		DeviceType: dt,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name:       clientCfg.DeviceName,
			Persist:    false,
			MultiQueue: true,
		},
	}
	iface, err = water.New(config)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"DeviceName": clientCfg.DeviceName,
			"Error":      err,
		}).Errorln("Cann't Create Tun/Tap Device.")
		return
	}

	var link netlink.Link
	link, err = netlink.LinkByName(clientCfg.DeviceName)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"DeviceName": clientCfg.DeviceName,
			"Error":      err,
		}).Errorln("Cann't Get Device by NetLink.")
		return
	}

	//true means the device has been initiated
	if strings.Contains(link.Attrs().Flags.String(), "up") {
		return
	}

	var addr *netlink.Addr
	addr, err = netlink.ParseAddr(clientCfg.Network)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"NetWork": clientCfg.Network,
			"Error":   err,
		}).Errorln("Error While Parsing Network.")
		return
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

	return
}

func TunExist(name string) bool {
	_, err := netlink.LinkByName(name)
	return err == nil
}
