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
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/FISCO-BCOS/go-sdk/core/types"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/polynetwork/chainsql-relayer/config"
	"github.com/polynetwork/chainsql-relayer/db"
	"github.com/polynetwork/chainsql-relayer/go_abi/eccm_abi"
	"github.com/polynetwork/chainsql-relayer/log"
	"github.com/polynetwork/chainsql-relayer/tools"
	"github.com/polynetwork/poly-io-test/chains/ont"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	"github.com/tjfoc/gmsm/pkcs12"

	"github.com/FISCO-BCOS/go-sdk/client"
	comm "github.com/ethereum/go-ethereum/common"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"github.com/tjfoc/gmsm/x509"

	"strconv"
	"unsafe"
)

type ChainsqlManager struct {
	config        *config.ServiceConfig
	client        *client.Client
	currentHeight uint64
	forceHeight   uint64
	polySdk       *sdk.PolySdk
	polySigner    *sdk.Account
	db            *db.BoltDB
	caSet         *tools.CertTrustChain
}

func NewChainsqlManager(servconfig *config.ServiceConfig, startheight uint64, startforceheight uint64, ontsdk *sdk.PolySdk, client *client.Client, boltDB *db.BoltDB) (*ChainsqlManager, error) {
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
		Certs: make([]*x509.Certificate, 2),
	}
	keysCa, err := ioutil.ReadFile(servconfig.ChainsqlConfig.AgencyPath)
	if err != nil {
		log.Errorf("ChainsqlManager - read AgencyPath failed")
		return nil, err
	}

	blkAgency, _ := pem.Decode(keysCa)
	caSet.Certs[0], err = x509.ParseCertificate(blkAgency.Bytes)
	if err != nil {
		return nil, err
	}
	keysCert, err := ioutil.ReadFile(servconfig.ChainsqlConfig.NodePath)
	if err != nil {
		log.Errorf("ChainsqlManager - read NodePath failed")
		return nil, err
	}

	blk, _ := pem.Decode(keysCert)
	caSet.Certs[1], _ = x509.ParseCertificate(blk.Bytes)

	mgr := &ChainsqlManager{
		config:        servconfig,
		currentHeight: startheight,
		forceHeight:   startforceheight,
		client:        client,
		polySdk:       ontsdk,
		polySigner:    signer,
		db:            boltDB,
		caSet:         caSet,
	}
	return mgr, nil

}
func bytes2str(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

/**
 * SubscribeBlockNumber
 */
func (chainsql *ChainsqlManager) SubscribeBlockNumber() {
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

func (chainsql *ChainsqlManager) NotifyBlockNumber(blockNumber int64) {
	log.Infof("MonitorChain - chainsql current height: %v", blockNumber)
	height := uint64(blockNumber)
	if height <= chainsql.currentHeight {
		return
	}
	for chainsql.currentHeight < height {
		if chainsql.FetchLockDepositEvents(chainsql.currentHeight + 1) {
			chainsql.currentHeight++
			if err := chainsql.db.UpdateChainsqlHeight(chainsql.currentHeight); err != nil {
				log.Errorf("ChainsqlManager MonitorChain - save new height %d to DB failed: %v", chainsql.currentHeight, err)
			}
		}
	}

}

func (chainsql *ChainsqlManager) BlockNumber() (int64, error) {
	bn, err := chainsql.client.GetBlockNumber(context.Background())
	if err != nil {
		return 0, fmt.Errorf("block number not found: %v", err)
	}
	str, err := strconv.Unquote(bytes2str(bn))
	if err != nil {
		return 0, fmt.Errorf("ParseInt: %v", err)
	}
	height, err := strconv.ParseInt(str, 0, 0)
	if err != nil {
		return 0, fmt.Errorf("ParseInt: %v", err)
	}
	return height, nil
}

func (chainsql *ChainsqlManager) SyncChainsqlGenesisHeader(poly *sdk.PolySdk, ecmAddr string) {
	eccm := comm.HexToAddress(ecmAddr)

	eccmContract, err := eccm_abi.NewEthCrossChainManager(eccm, chainsql.client)
	if err != nil {
		fmt.Println(err)
	}

	gB, err := poly.GetBlockByHeight(60000)
	if err != nil {
		fmt.Println(err)
	}

	if err != nil {
		panic(err)
	}
	info := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(gB.Header.ConsensusPayload, info); err != nil {
		panic(fmt.Errorf("commitGenesisHeader - unmarshal blockInfo error: %s", err))
	}

	var bookkeepers []keypair.PublicKey
	for _, peer := range info.NewChainConfig.Peers {
		keystr, _ := hex.DecodeString(peer.ID)
		key, _ := keypair.DeserializePublicKey(keystr)
		bookkeepers = append(bookkeepers, key)
	}
	bookkeepers = keypair.SortPublicKeys(bookkeepers)

	publickeys := make([]byte, 0)
	for _, key := range bookkeepers {
		publickeys = append(publickeys, ont.GetOntNoCompressKey(key)...)
	}
	rawHdr := gB.Header.ToArray()

	trans, recp, _ := eccmContract.InitGenesisBlock(chainsql.client.GetTransactOpts(), rawHdr, publickeys)

	log.Infof("InitGenesisBlock: %s,recp:%v", trans.Hash().Hex(), recp.BlockNumber)
}

type BlockRes struct {
	Transactions []string `json:"transactions"`
}

func (chainsql *ChainsqlManager) FetchLockDepositEvents(height uint64) bool {
	eccmAddress := comm.HexToAddress(chainsql.config.ChainsqlConfig.ECCMContractAddress)
	eccmContract, err := eccm_abi.NewEthCrossChainManager(eccmAddress, chainsql.client)
	if err != nil {
		return false
	}
	blk, err := chainsql.client.GetBlockByNumber(context.Background(), strconv.FormatUint(height, 10), false)
	if err != nil {
		log.Errorf("fetchLockDepositEvents - GetBlockByNumber error :%s", err.Error())
		return false
	}
	res := &BlockRes{}
	err = json.Unmarshal(blk, res)
	if err != nil {
		log.Errorf("fetchLockDepositEvents - Unmarshal error :%s", err.Error())
		return false
	}
	for _, tx := range res.Transactions {
		recp, err := chainsql.client.TransactionReceipt(context.Background(), comm.HexToHash(tx))
		if err != nil {
			log.Errorf("fetchLockDepositEvents - TransactionReceipt error: %s", err.Error())
			continue
		}
		if recp.Status != 0 {
			continue
		}
		for _, v := range recp.Logs {
			if v.Address != strings.ToLower(chainsql.config.ChainsqlConfig.ECCMContractAddress) {
				continue
			}
			topics := make([]comm.Hash, len(v.Topics))
			for i, t := range v.Topics {
				topics[i] = comm.HexToHash(t.(string))
			}
			rawData, _ := hex.DecodeString(strings.TrimPrefix(v.Data, "0x"))
			evt, err := eccmContract.ParseCrossChainEvent(types.Log{
				Address: comm.HexToAddress(v.Address),
				Topics:  topics,
				Data:    rawData,
			})
			if err != nil || evt == nil {
				continue
			}

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
				log.Errorf("failed to send for chainsql tx %s: (error: %v, raw_data: %x)", tx, err, rawData)
				continue
			}
			log.Infof("fetchLockDepositEvents - successful to send cross chain info: (tx_hash: %s, hash: %s)",
				hash.ToHexString(), tx)
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
		hasher := sha256.New()
		hasher.Write(rawInfo)
		raw := hasher.Sum(nil)
		key, err := pkcs12.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
		priv := key.(*ecdsa.PrivateKey)
		sig, err = priv.Sign(rand.Reader, raw, nil)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	} else {
		log.Fatalf("Not support GM now.")
		//key, err := sm2.ParsePKCS8UnecryptedPrivateKey(blk.Bytes)
		//if err != nil {
		//	return common.UINT256_EMPTY, fmt.Errorf("failed to ParsePKCS8UnecryptedPrivateKey: %v", err)
		//}
		//sig, err = key.Sign(rand.Reader, rawInfo, nil)
		//if err != nil {
		//	return common.UINT256_EMPTY, err
		//}
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

func (chainsql *ChainsqlManager) RelayCrossChainInfo(sourceChainId uint64, sigForInfo, crossChainInfo,
	relayerAddress []byte, certs *tools.CertTrustChain, signer *sdk.Account) (common.Uint256, error) {
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
