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
package manager

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"reflect"

	"github.com/polynetwork/chainsql-relayer/client"
	"github.com/polynetwork/chainsql-relayer/config"
	"github.com/polynetwork/chainsql-relayer/db"
	"github.com/polynetwork/chainsql-relayer/go_abi/eccm_abi"
	"github.com/polynetwork/chainsql-relayer/log"
	"github.com/polynetwork/chainsql-relayer/tools"
	"github.com/tjfoc/gmsm/pkcs12"

	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	sm2 "github.com/tjfoc/gmsm/sm2"
)

type ChainsqlManager struct {
	config        *config.ServiceConfig
	client        *client.ChainSqlNode
	currentHeight int
	forceHeight   uint64
	polySdk       *sdk.PolySdk
	polySigner    *sdk.Account
	db            *db.BoltDB
	caSet         *tools.CertTrustChain
}

func NewChainsqlManager(
	servconfig *config.ServiceConfig,
	startheight uint64,
	startforceheight uint64,
	ontsdk *sdk.PolySdk,
	client *client.ChainSqlNode,
	boltDB *db.BoltDB) (*ChainsqlManager, error) {

	var wallet *sdk.Wallet
	var err error
	if !common.FileExisted(servconfig.PolyConfig.WalletFile) {
		wallet, err = ontsdk.CreateWallet(servconfig.PolyConfig.WalletFile)
		if err != nil {
			return nil, err
		}
	} else {
		wallet, err = ontsdk.OpenWallet(servconfig.PolyConfig.WalletFile)
		if err != nil {
			log.Errorf("ChainsqlManager - wallet open error: %s", err.Error())
			return nil, err
		}
	}
	signer, err := wallet.GetDefaultAccount([]byte(servconfig.PolyConfig.WalletPwd))
	if err != nil || signer == nil {
		signer, err = wallet.NewDefaultSettingAccount([]byte(servconfig.PolyConfig.WalletPwd))
		if err != nil {
			log.Errorf("ChainsqlManager - wallet password error")
			return nil, err
		}

		err = wallet.Save()
		if err != nil {
			return nil, err
		}
	}
	log.Infof("ChainsqlManager - poly address: %s", signer.Address.ToBase58())

	caSet := &tools.CertTrustChain{
		Certs: make([]*sm2.Certificate, 2),
	}
	keysCa, err := ioutil.ReadFile(servconfig.ChainsqlConfig.AgencyPath)
	if err != nil {
		log.Errorf("ChainsqlManager - read AgencyPath failed")
		return nil, err
	}

	blkAgency, _ := pem.Decode(keysCa)
	caSet.Certs[0], err = sm2.ParseCertificate(blkAgency.Bytes)
	if err != nil {
		log.Errorf("ParseCertificate[0] error. %s", err.Error())
		return nil, err
	}
	keysCert, err := ioutil.ReadFile(servconfig.ChainsqlConfig.NodePath)
	if err != nil {
		log.Errorf("ChainsqlManager - read NodePath failed")
		return nil, err
	}

	blk, _ := pem.Decode(keysCert)
	caSet.Certs[1], err = sm2.ParseCertificate(blk.Bytes)
	if err != nil {
		log.Errorf("ParseCertificate[1] error. %s", err.Error())
		return nil, err
	}

	mgr := &ChainsqlManager{
		config:        servconfig,
		currentHeight: int(startheight),
		forceHeight:   startforceheight,
		client:        client,
		polySdk:       ontsdk,
		polySigner:    signer,
		db:            boltDB,
		caSet:         caSet,
	}
	return mgr, nil

}

/**
 * SubscribeBlockNumber
 */
func (chainsql *ChainsqlManager) SubscribeBlockNumber() {
	localCurrentHeight := chainsql.db.GetChainsqlHeight()
	if localCurrentHeight > uint64(chainsql.currentHeight) {
		chainsql.currentHeight = int(localCurrentHeight)
	}
	/**
	 *Set block height notification
	 */
	chainsql.client.SubscribeBlockNumberNotify(chainsql.NotifyBlockNumber)

	/**
	 *Get the current latest block height
	 */
	currHeight, err := chainsql.BlockNumber()
	if err != nil {
		log.Fatalf("ChainsqlManager MonitorChain - failed to get current chainsql height: %v", err)
		return
	}
	chainsql.NotifyBlockNumber(currHeight)
}

func (chainsql *ChainsqlManager) NotifyBlockNumber(blockNumber int) {
	log.Infof("MonitorChain - chainsql current height: %v", blockNumber)
	height := uint64(blockNumber)
	if height <= uint64(chainsql.currentHeight) {
		return
	}

	for uint64(chainsql.currentHeight) < height {
		if chainsql.FetchLockDepositEvents(chainsql.currentHeight + 1) {
			chainsql.currentHeight++
			if err := chainsql.db.UpdateChainsqlHeight(uint64(chainsql.currentHeight)); err != nil {
				log.Errorf(
					"ChainsqlManager MonitorChain - save new height %d to DB failed: %v",
					chainsql.currentHeight, err)
			}
		}
	}

}

func (chainsql *ChainsqlManager) BlockNumber() (int, error) {
	return chainsql.client.GetBlockNumber()
}

func (chainsql *ChainsqlManager) FetchLockDepositEvents(height int) bool {
	eccmAddress := chainsql.config.ChainsqlConfig.ECCMContractAddress
	eccmContract, err := eccm_abi.NewEthCrossChainManager(chainsql.client.Chainsql, eccmAddress)
	if err != nil {
		return false
	}
	blk := chainsql.client.GetLedgerTransactions(height)
	var blockRes map[string]interface{}
	err = json.Unmarshal([]byte(blk), &blockRes)
	if err != nil {
		log.Debugf("fetchLockDepositEvents - Unmarshal error :%s", err.Error())
		return false
	}
	result := blockRes["result"].(map[string]interface{})
	ledger := result["ledger"].(map[string]interface{})
	transactions := reflect.ValueOf(ledger["transactions"])
	for i := 0; i < transactions.Len(); i++ {
		txHash := transactions.Index(i).Interface().(string)
		contractEvents, err := eccmContract.GetCrossChainEventPastEvent(txHash, "")
		if err != nil {
			log.Errorf(
				"fetchLockDepositEvents - fetchLockDepositEvents error: (se:%d, tx:%s, %s)",
				height, txHash, err.Error())
			continue
		}

		if len(contractEvents) == 0 {
			log.Trace("fetchLockDepositEvents - contractEvents is empty")
			continue
		}

		for _, evt := range contractEvents {
			var isTarget bool
			if len(chainsql.config.TargetContracts) > 0 {
				toContractStr := evt.ProxyOrAssetContract.String()
				for k, v := range chainsql.config.TargetContracts {
					ok := k == toContractStr
					if ok {
						if len(v["outbound"]) == 0 {
							isTarget = true
							break
						}
						for _, id := range v["outbound"] {
							if id == evt.ToChainId {
								isTarget = true
								break
							}
						}
						if isTarget {
							break
						}
					}
				}
				if !isTarget {
					continue
				}
			}
			hash, err := chainsql.SendCrossChainInfoWithRaw(evt.Rawdata)
			if err != nil {
				log.Errorf("fetchLockDepositEvents - SendCrossChainInfoWithRaw error: %s", err.Error())
				continue
			}
			log.Infof("fetchLockDepositEvents - SendCrossChainInfoWithRaw successful to send cross chain info: (tx_hash: %s)",
				hash.ToHexString())
		}
	}

	return true
}

func (chainsql *ChainsqlManager) SendCrossChainInfoWithRaw(rawInfo []byte) (common.Uint256, error) {
	keys, err := ioutil.ReadFile(chainsql.config.ChainsqlConfig.KeyPath)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("failed to read chainsql key: %v", err)
	}
	blk, _ := pem.Decode(keys)

	var sig []byte
	if !chainsql.config.ChainsqlConfig.IsGM {
		hasher := sm2.SHA256.New()
		hasher.Write(rawInfo)
		raw := hasher.Sum(nil)
		key, err := pkcs12.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			log.Errorf("SendCrossChainInfoWithRaw - ParsePKCS8PrivateKey: %s", err.Error())
			return common.UINT256_EMPTY, err
		}
		priv := key.(*ecdsa.PrivateKey)
		sig, err = priv.Sign(rand.Reader, raw, nil)
		if err != nil {
			log.Errorf("SendCrossChainInfoWithRaw - Sign: %s", err.Error())
			return common.UINT256_EMPTY, err
		}
	} else {
		key, err := sm2.ParsePKCS8UnecryptedPrivateKey(blk.Bytes)
		if err != nil {
			return common.UINT256_EMPTY, fmt.Errorf("failed to ParsePKCS8UnecryptedPrivateKey: %v", err)
		}
		sig, err = key.Sign(rand.Reader, rawInfo, nil)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}

	txHash, err := chainsql.RelayCrossChainInfo(
		chainsql.config.ChainsqlConfig.SideChainId,
		sig, rawInfo, chainsql.polySigner.Address[:],
		chainsql.caSet, chainsql.polySigner)
	if err != nil {
		//TODO: if pre-execute failed, maybe should deal with that error.
		log.Fatalf("RelayCrossChainInfo err: %v", err)
		return common.UINT256_EMPTY, err
	}
	return txHash, nil
}

func (chainsql *ChainsqlManager) RelayCrossChainInfo(
	sourceChainId uint64,
	sigForInfo,
	crossChainInfo,
	relayerAddress []byte,
	certs *tools.CertTrustChain,
	signer *sdk.Account) (common.Uint256, error) {
	sink := common.NewZeroCopySink(nil)
	certs.Serialization(sink)
	return chainsql.polySdk.Native.Ccm.ImportOuterTransfer(
		sourceChainId,
		crossChainInfo,
		0,
		sigForInfo,
		relayerAddress,
		sink.Bytes(),
		signer)
}

func (chainsql *ChainsqlManager) SendCrossChainInfo(param common2.MakeTxParam) (common.Uint256, error) {
	sink := common.NewZeroCopySink(nil)
	param.Serialization(sink)
	rawInfo := sink.Bytes()

	return chainsql.SendCrossChainInfoWithRaw(rawInfo)
}
