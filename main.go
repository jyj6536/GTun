package main

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"strconv"
	"syscall"
	"tunproject/cfgUtil"
	"tunproject/tunnelInit"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetReportCaller(true)
	logrus.SetFormatter(&logrus.JSONFormatter{
		CallerPrettyfier: func(f *runtime.Frame) (function string, file string) {
			function = f.Function
			file = path.Base(f.File) + ":" + strconv.Itoa(f.Line)
			return
		},
	})
}

var lockFile *os.File
var pidFile string

func lockPidFile(path string) error {
	var err error
	if lockFile, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644); err != nil {
		return err
	}

	if err = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return err
	}
	if err = lockFile.Truncate(0); err != nil {
		return err
	}
	pid := os.Getpid()
	_, err = lockFile.WriteString(strconv.Itoa(pid))
	return err
}

func main() {
	subCommands := []*cli.Command{
		{
			Name: "client",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "config",
					Aliases: []string{"c"},
					Usage:   "Client Config File",
					Value:   "./client.json",
				},
				&cli.StringFlag{
					Name:    "log",
					Aliases: []string{"l"},
					Usage:   "Client Log File.",
					Value:   "./client.log",
				},
			},
			Action: func(ctx *cli.Context) error {
				logHandle, err := os.OpenFile(ctx.String("log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
				if err != nil {
					return nil
				}
				logrus.SetOutput(logHandle)
				cfgFile := ctx.String("config")
				_, err = cfgUtil.LoadClientCfg(cfgFile)
				if err != nil {
					return err
				}
				if cfgUtil.CCfg.Type != "client" {
					logrus.Errorln("Type of Config File must be \"client\".")
					return nil
				}
				pidFile = cfgUtil.CCfg.PidFile
				if pidFile != "" {
					err = lockPidFile(pidFile)
					if err != nil {
						if lockFile != nil {
							lockFile.Close()
							lockFile = nil
						}
						logrus.WithFields(logrus.Fields{
							"PidFile": pidFile,
							"Error":   err,
						}).Errorln("Cann't lock pidfile.")
						return err
					}
				}
				return tunnelInit.ClientInit()
			},
		},
		{
			Name: "server",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "config",
					Aliases: []string{"c"},
					Usage:   "Server Config File",
					Value:   "./server.json",
				},
				&cli.StringFlag{
					Name:    "log",
					Aliases: []string{"l"},
					Usage:   "Server Log File",
					Value:   "./server.log",
				},
			},
			Action: func(ctx *cli.Context) error {
				logHandle, err := os.OpenFile(ctx.String("log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
				if err != nil {
					return err
				}
				logrus.SetOutput(logHandle)
				cfgFile := ctx.String("config")
				scfg, err := cfgUtil.LoadServerCfg(cfgFile)
				if err != nil {
					return nil
				}
				if scfg.Type != "server" {
					logrus.Errorln("Type of Config File must be \"server\".")
					return nil
				}
				pidFile = cfgUtil.SCfg.PidFile
				if pidFile != "" {
					err = lockPidFile(pidFile)
					if err != nil {
						if lockFile != nil {
							lockFile.Close()
							lockFile = nil
						}
						logrus.WithFields(logrus.Fields{
							"PidFile": pidFile,
							"Error":   err,
						}).Errorln("Cann't lock pidfile.")
						return err
					}
				}
				return tunnelInit.ServerInit(scfg)
			},
		},
	}

	app := cli.App{
		Name:     "tunProject",
		Commands: subCommands,
	}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Printf("%v", err)
	}
	if lockFile != nil {
		os.Remove(pidFile)
	}
}
