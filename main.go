/*
* Copyright (C) 2020 The poly network Authors
* This file is part of The poly network library.
*
* The poly network is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* The poly network is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
* You should have received a copy of the GNU Lesser General Public License
* along with The poly network . If not, see <http://www.gnu.org/licenses/>.
 */
/*
* Copyright (C) 2020 The poly network Authors
* This file is part of The poly network library.
*
* The poly network is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* The poly network is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
* You should have received a copy of the GNU Lesser General Public License
* along with The poly network . If not, see <http://www.gnu.org/licenses/>.
 */
package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/FISCO-BCOS/go-sdk/client"
	"github.com/FISCO-BCOS/go-sdk/conf"

	"github.com/polynetwork/chainsql-relayer/cmd"
	"github.com/polynetwork/chainsql-relayer/config"
	"github.com/polynetwork/chainsql-relayer/db"
	"github.com/polynetwork/chainsql-relayer/log"
	"github.com/polynetwork/chainsql-relayer/manager"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/urfave/cli"
)

var PolyStartHeight uint64
var StartHeight uint64
var StartForceHeight uint64

func setupApp() *cli.App {
	app := cli.NewApp()
	app.Usage = "chainsql relayer Service"
	app.Action = startServer
	app.Version = config.Version
	app.Copyright = "Copyright in 2022 The ChainSQL Authors"
	app.Flags = []cli.Flag{
		cmd.LogLevelFlag,
		cmd.ConfigPathFlag,
		cmd.PolyStartFlag,
		cmd.LogDir,
	}
	app.Commands = []cli.Command{}
	app.Before = func(context *cli.Context) error {
		runtime.GOMAXPROCS(runtime.NumCPU())
		return nil
	}

	return app
}

func startServer(ctx *cli.Context) {
	// get all cmd flag
	logLevel := ctx.GlobalInt(cmd.GetFlagName(cmd.LogLevelFlag))
	ld := ctx.GlobalString(cmd.GetFlagName(cmd.LogDir))
	log.InitLog(logLevel, ld, log.Stdout)

	// parse config
	ConfigPath := ctx.GlobalString(cmd.GetFlagName(cmd.ConfigPathFlag))
	StartForceHeight = 0
	chainsqlstartforce := ctx.GlobalUint64(cmd.GetFlagName(cmd.ChainsqlStartForceFlag))
	if chainsqlstartforce > 0 {
		StartForceHeight = chainsqlstartforce
		StartHeight = chainsqlstartforce
	}

	polyStart := ctx.GlobalUint64(cmd.GetFlagName(cmd.PolyStartFlag))
	if polyStart > 0 {
		PolyStartHeight = polyStart
	}

	// read config
	servConfig := config.NewServiceConfig(ConfigPath)
	if servConfig == nil {
		log.Errorf("startServer - create config failed!")
		return
	}

	// create poly sdk
	polySdk := sdk.NewPolySdk()
	err := setUpPoly(polySdk, servConfig.PolyConfig.RestURL)
	if err != nil {
		log.Errorf("startServer - failed to setup poly sdk: %v", err)
		return
	}

	// only simulator to creata a chainsql sdk
	configs, _ := conf.ParseConfigFile("chainsql.cfg")
	chainsqlsdk, err := client.Dial(&configs[0])
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("dsd")

	var boltDB *db.BoltDB
	if servConfig.BoltDbPath == "" {
		boltDB, err = db.NewBoltDB("boltdb")
	} else {
		boltDB, err = db.NewBoltDB(servConfig.BoltDbPath)
	}
	if err != nil {
		log.Fatalf("db.NewWaitingDB error:%s", err)
		return
	}

	initChainsqlServer(servConfig, polySdk, chainsqlsdk, boltDB)
	initPolyServer(servConfig, polySdk, chainsqlsdk, boltDB)

	waitToExit()
}

func setUpPoly(poly *sdk.PolySdk, RpcAddr string) error {
	poly.NewRpcClient().SetAddress(RpcAddr)
	hdr, err := poly.GetHeaderByHeight(0)
	if err != nil {
		return err
	}
	poly.SetChainId(hdr.ChainID)
	return nil
}

func initPolyServer(servConfig *config.ServiceConfig, polysdk *sdk.PolySdk, chainsqlsdk *client.Client, boltDB *db.BoltDB) {
	mgr, err := manager.NewPolyManager(servConfig, uint32(PolyStartHeight), polysdk, chainsqlsdk, boltDB)
	if err != nil {
		log.Error("initPolyServer - PolyServer service start failed: %v", err)
		return
	}

	go mgr.MonitorChain()
}

func initChainsqlServer(servConfig *config.ServiceConfig, polysdk *sdk.PolySdk, chainsqlsdk *client.Client, boltDB *db.BoltDB) {
	mgr, err := manager.NewChainsqlManager(servConfig, StartHeight, StartForceHeight, polysdk, chainsqlsdk, boltDB)
	if err != nil {
		log.Error("initFiscoServer - fisco service start err: %s", err.Error())
		return
	}
	go mgr.SubscribeBlockNumber()
}

func waitToExit() {
	exit := make(chan bool)
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sc {
			log.Infof("waitToExit - ChainSQL relayer received exit signal:%v.", sig.String())
			close(exit)
			break
		}
	}()
	<-exit
}

func main() {
	log.Infof("main - chainsql relayer staring ....")
	if err := setupApp().Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
