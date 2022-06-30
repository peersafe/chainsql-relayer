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
package manager

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	"github.com/pkg/errors"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"

	"time"

	"github.com/FISCO-BCOS/go-sdk/client"
	"github.com/polynetwork/chainsql-relayer/config"
	"github.com/polynetwork/chainsql-relayer/db"
	"github.com/polynetwork/chainsql-relayer/go_abi/eccd_abi"
	"github.com/polynetwork/chainsql-relayer/go_abi/eccm_abi"
	"github.com/polynetwork/chainsql-relayer/log"
	"github.com/polynetwork/chainsql-relayer/tools"
	polytypes "github.com/polynetwork/poly/core/types"
)

var (
	// ErrNoCode is returned by call and transact operations for which the requested
	// recipient contract to operate on does not exist in the state db or does not
	// have any code associated with it (i.e. suicided).
	ErrNoCode = errors.New("no contract code at given address")

	// This error is raised when attempting to perform a pending state action
	// on a backend that doesn't implement PendingContractCaller.
	ErrNoPendingState = errors.New("backend does not support pending state")

	// This error is returned by WaitDeployed if contract creation leaves an
	// empty contract behind.
	ErrNoCodeAfterDeploy = errors.New("no contract code after deployment")
)

const (
	ChanLen = 64
)

type PolyManager struct {
	config         *config.ServiceConfig
	polySdk        *sdk.PolySdk
	currentHeight  uint32
	contractAbi    *abi.ABI
	exitChan       chan int
	db             *db.BoltDB
	chainsqlSender *ChainsqlSender
}

type ChainsqlSender struct {
	client      *client.Client
	acc         ethcommon.Address
	polySdk     *sdk.PolySdk
	config      *config.ServiceConfig
	contractAbi *abi.ABI
}

func NewPolyManager(servCfg *config.ServiceConfig, startblockHeight uint32, polySdk *sdk.PolySdk, chainsqlsdk *client.Client, boltDB *db.BoltDB) (*PolyManager, error) {
	contractabi, err := abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerABI))
	if err != nil {
		return nil, err
	}

	chainsqlSender := &ChainsqlSender{
		client:      chainsqlsdk,
		acc:         ethcommon.HexToAddress("0x34f00110bad3236f01468799d44fe04d7deb25f0"),
		polySdk:     polySdk,
		config:      servCfg,
		contractAbi: &contractabi,
	}

	return &PolyManager{
		exitChan:       make(chan int),
		config:         servCfg,
		polySdk:        polySdk,
		currentHeight:  startblockHeight,
		contractAbi:    &contractabi,
		db:             boltDB,
		chainsqlSender: chainsqlSender,
	}, nil
}

func (poly *PolyManager) findLatestHeight() uint32 {

	address := ethcommon.HexToAddress(poly.config.ChainsqlConfig.ECCDContractAddress)
	instance, err := eccd_abi.NewEthCrossChainData(address, poly.chainsqlSender.client)
	if err != nil {
		log.Errorf("findLatestHeight - new eth cross chain failed: %s", err.Error())
		return 0
	}
	height, err := instance.GetCurEpochStartHeight(poly.chainsqlSender.client.GetCallOpts())
	if err != nil {
		log.Errorf("findLatestHeight - GetLatestHeight failed: %s", err.Error())
		return 0
	}
	return uint32(height)
}

func (poly *PolyManager) init() bool {
	if poly.currentHeight > 0 {
		log.Infof("PolyManager init - start height from flag: %d", poly.currentHeight)
		return true
	}
	poly.currentHeight = poly.db.GetPolyHeight()
	latestHeight := poly.findLatestHeight()
	if latestHeight > poly.currentHeight {
		poly.currentHeight = latestHeight
		log.Infof("PolyManager init - latest height from ECCM: %d", poly.currentHeight)
		return true
	}
	log.Infof("PolyManager init - latest height from DB: %d", poly.currentHeight)

	return true
}

func (poly *PolyManager) MonitorChain() {
	ret := poly.init()
	if !ret {
		log.Errorf("MonitorChain - init failed\n")
	}
	monitorTicker := time.NewTicker(config.ONT_MONITOR_INTERVAL)
	var blockHandleResult bool
	for {
		select {
		case <-monitorTicker.C:
			latestheight, err := poly.polySdk.GetCurrentBlockHeight()
			if err != nil {
				log.Errorf("MonitorChain - get poly chain block height error: %s", err)
				continue
			}
			latestheight--
			if latestheight-poly.currentHeight < config.ONT_USEFUL_BLOCK_NUM {
				continue
			}
			log.Infof("MonitorChain - poly chain current height: %d", latestheight)
			blockHandleResult = true
			for poly.currentHeight <= latestheight-config.ONT_USEFUL_BLOCK_NUM {
				blockHandleResult = poly.handleDepositEvents(poly.currentHeight)
				if !blockHandleResult {
					break
				}
				poly.currentHeight++
			}
			if err = poly.db.UpdatePolyHeight(poly.currentHeight - 1); err != nil {
				log.Errorf("MonitorChain - failed to save height of poly: %v", err)
			}
		case <-poly.exitChan:
			return
		}
	}
}

func (poly *PolyManager) HandleDepositEvents(height uint32) {
	poly.handleDepositEvents(height)
}

func (poly *PolyManager) HandleCommitHeader(height uint32) {
	hdr, err := poly.polySdk.GetHeaderByHeight(height)
	if err != nil {
		log.Errorf("HandleCommitHeader - GetNodeHeader on height :%d failed", height)
	}
	poly.chainsqlSender.commitHeader(hdr)
}

func (poly *PolyManager) handleDepositEvents(height uint32) bool {
	lastEpoch := poly.findLatestHeight()
	hdr, err := poly.polySdk.GetHeaderByHeight(height + 1)
	if err != nil {
		log.Errorf("handleBlockHeader - GetNodeHeader on height :%d failed", height)
		return false
	}
	isCurr := lastEpoch < height+1
	info := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(hdr.ConsensusPayload, info); err != nil {
		log.Errorf("failed to unmarshal ConsensusPayload for height %d: %v", height+1, err)
		return false
	}
	isEpoch := hdr.NextBookkeeper != common.ADDRESS_EMPTY && info.NewChainConfig != nil
	var (
		anchor *polytypes.Header
		hp     string
	)
	if !isCurr {
		anchor, _ = poly.polySdk.GetHeaderByHeight(lastEpoch + 1)
		proof, _ := poly.polySdk.GetMerkleProof(height+1, lastEpoch+1)
		hp = proof.AuditPath
	} else if isEpoch {
		anchor, _ = poly.polySdk.GetHeaderByHeight(height + 2)
		proof, _ := poly.polySdk.GetMerkleProof(height+1, height+2)
		hp = proof.AuditPath
	}

	cnt := 0
	events, err := poly.polySdk.GetSmartContractEventByBlock(height)
	for err != nil {
		log.Errorf("handleDepositEvents - get block event at height:%d error: %s", height, err.Error())
		return false
	}
	for _, event := range events {
		for _, notify := range event.Notify {
			if notify.ContractAddress == poly.config.PolyConfig.EntranceContractAddress {
				states := notify.States.([]interface{})
				method, _ := states[0].(string)
				if method != "makeProof" {
					continue
				}
				if uint64(states[2].(float64)) != poly.config.ChainsqlConfig.SideChainId {
					continue
				}
				proof, err := poly.polySdk.GetCrossStatesProof(hdr.Height-1, states[5].(string))
				if err != nil {
					log.Errorf("handleDepositEvents - failed to get proof for key %s: %v", states[5].(string), err)
					continue
				}
				auditpath, _ := hex.DecodeString(proof.AuditPath)
				value, _, _, _ := tools.ParseAuditpath(auditpath)
				param := &common2.ToMerkleValue{}
				if err := param.Deserialization(common.NewZeroCopySource(value)); err != nil {
					log.Errorf("handleDepositEvents - failed to deserialize MakeTxParam (value: %x, err: %v)", value, err)
					continue
				}
				var isTarget bool
				if len(poly.config.TargetContracts) > 0 {
					toContractStr := ethcommon.BytesToAddress(param.MakeTxParam.ToContractAddress).String()
					for k, v := range poly.config.TargetContracts {
						if k == toContractStr {
							if len(v["inbound"]) == 0 {
								isTarget = true
								break
							}
							for _, id := range v["inbound"] {
								if id == param.FromChainID {
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
				cnt++

				poly.chainsqlSender.commitDepositEventsWithHeader(hdr, param, hp, anchor, event.TxHash, auditpath)
			}
		}
	}
	if cnt == 0 && isEpoch && isCurr {
		return poly.chainsqlSender.commitHeader(hdr)
	}

	return true
}

func (poly *PolyManager) Stop() {
	poly.exitChan <- 1
	close(poly.exitChan)
	log.Infof("poly chain manager exit.")
}

func (chainsql *ChainsqlSender) commitDepositEventsWithHeader(header *polytypes.Header, param *common2.ToMerkleValue, headerProof string, anchorHeader *polytypes.Header, polyTxHash string, rawAuditPath []byte) bool {
	var (
		sigs       []byte
		headerData []byte
	)
	if anchorHeader != nil && headerProof != "" {
		for _, sig := range anchorHeader.SigData {
			temp := make([]byte, len(sig))
			copy(temp, sig)
			newsig, _ := signature.ConvertToEthCompatible(temp)
			sigs = append(sigs, newsig...)
		}
	} else {
		for _, sig := range header.SigData {
			temp := make([]byte, len(sig))
			copy(temp, sig)
			newsig, _ := signature.ConvertToEthCompatible(temp)
			sigs = append(sigs, newsig...)
		}
	}

	eccdAddr := ethcommon.HexToAddress(chainsql.config.ChainsqlConfig.ECCDContractAddress)
	eccd, err := eccd_abi.NewEthCrossChainData(eccdAddr, chainsql.client)
	if err != nil {
		panic(fmt.Errorf("failed to new eccd: %v", err))
	}

	eccmAddr := ethcommon.HexToAddress(chainsql.config.ChainsqlConfig.ECCMContractAddress)
	eccm, err := eccm_abi.NewEthCrossChainManager(eccmAddr, chainsql.client)
	if err != nil {
		panic(fmt.Errorf("failed to new eccm: %v", err))
	}

	fromTx := [32]byte{}
	copy(fromTx[:], param.TxHash[:32])
	res, _ := eccd.CheckIfFromChainTxExist(chainsql.client.GetCallOpts(), param.FromChainID, fromTx)
	if res {
		log.Debugf("already relayed to chainsql: ( from_chain_id: %d, from_txhash: %x,  param.Txhash: %x)",
			param.FromChainID, param.TxHash, param.MakeTxParam.TxHash)

		return true
	}
	//log.Infof("poly proof with header, height: %d, key: %s, proof: %s", header.Height-1, string(key), proof.AuditPath)

	rawProof, _ := hex.DecodeString(headerProof)
	var rawAnchor []byte
	if anchorHeader != nil {
		rawAnchor = anchorHeader.GetMessage()
	}
	headerData = header.GetMessage()

	trans, _, err := eccm.VerifyHeaderAndExecuteTx(chainsql.client.GetTransactOpts(), rawAuditPath, headerData, rawProof, rawAnchor, sigs)
	if err != nil {
		log.Errorf("commitDepositEventsWithHeader - err:" + err.Error())
		return false
	}
	log.Infof("contractAbi trans txData is : %s", trans.Hash().Hex())

	return true
}

func (chainsql *ChainsqlSender) commitHeader(header *polytypes.Header) bool {
	headerdata := header.GetMessage()
	var (
		bookkeepers []keypair.PublicKey
		sigs        []byte
	)

	for _, sig := range header.SigData {
		temp := make([]byte, len(sig))
		copy(temp, sig)
		newsig, _ := signature.ConvertToEthCompatible(temp)
		sigs = append(sigs, newsig...)
	}

	blkInfo := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(header.ConsensusPayload, blkInfo); err != nil {
		log.Errorf("commitHeader - unmarshal blockInfo error: %s", err)
		return false
	}

	for _, peer := range blkInfo.NewChainConfig.Peers {
		keystr, _ := hex.DecodeString(peer.ID)
		key, _ := keypair.DeserializePublicKey(keystr)
		bookkeepers = append(bookkeepers, key)
	}
	bookkeepers = keypair.SortPublicKeys(bookkeepers)
	publickeys := make([]byte, 0)
	for _, key := range bookkeepers {
		publickeys = append(publickeys, tools.GetNoCompresskey(key)...)
	}

	eccmAddr := ethcommon.HexToAddress(chainsql.config.ChainsqlConfig.ECCDContractAddress)
	eccm, _ := eccm_abi.NewEthCrossChainManager(eccmAddr, chainsql.client)

	tx, recp, err := eccm.ChangeBookKeeper(chainsql.client.GetTransactOpts(), headerdata, publickeys, sigs)
	if err != nil {
		log.Fatal(err)
		return false
	}
	log.Infof("ChangeBookKeeper:%s,recp:%v", tx.Hash().Hex(), recp.BlockNumber)
	return true
}
