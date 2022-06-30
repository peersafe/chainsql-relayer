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
package client

import (
	"encoding/json"

	"github.com/ChainSQL/go-chainsql-api/core"
	"github.com/polynetwork/chainsql-relayer/config"
	"github.com/polynetwork/chainsql-relayer/log"
)

type Account struct {
	Address string
	Secrect string
}

type Config struct {
	URL            string
	ServerName     string
	RootCertPath   string
	ClientCertPath string
	ClientKeyPath  string
	Account        Account
}

type ChainSqlNode struct {
	Chainsql *core.Chainsql
}

func NewConfig(configFilePath string) *Config {

	fileContent, err := config.ReadFile(configFilePath)
	if err != nil {
		log.Errorf("NewServiceConfig: failed, err: %s", err)
		return nil
	}
	config := &Config{}
	err = json.Unmarshal(fileContent, config)
	if err != nil {
		log.Errorf("NewServiceConfig: failed, err: %s", err)
		return nil
	}

	return config
}

// Dial connects a client to the given URL and groupID.
func Dial(config *Config) (*ChainSqlNode, error) {
	node := ChainSqlNode{
		Chainsql: core.NewChainsql(),
	}

	err := node.Chainsql.Connect(
		config.URL,
		config.RootCertPath,
		config.ClientCertPath,
		config.ClientKeyPath,
		config.ServerName)

	if err != nil {
		return nil, err
	}

	node.Chainsql.As(config.Account.Address, config.Account.Secrect)
	return &node, nil
}

func (node *ChainSqlNode) SubscribeBlockNumberNotify(handler func(int)) error {
	go func() {
		var block map[string]interface{}
		node.Chainsql.OnLedgerClosed(func(msg string) {
			err := json.Unmarshal([]byte(msg), &block)
			if err != nil {
				log.Errorf("onLedgerClosed: %s", msg)
			}

			handler(int(block["ledger_index"].(float64)))
		})
	}()
	return nil
}

// GetBlockNumber returns the latest block height(hex format) on a given groupID.
func (node *ChainSqlNode) GetBlockNumber() (int, error) {
	return node.Chainsql.GetLedgerVersion()
}

// GetTransactOpts return *bind.TransactOpts
func (node *ChainSqlNode) GetTransactOpts() *core.TransactOpts {
	return &core.TransactOpts{
		Gas:         30000000,
		Expectation: "validate_success",
	}
}

// GetCallOpts return *bind.CallOpts
func (node *ChainSqlNode) GetCallOpts() *core.CallOpts {
	return &core.CallOpts{
		LedgerIndex: 0,
	}
}

// GetBlockByNumber returns the block information according to the given block number(hex format)
func (node *ChainSqlNode) GetBlockByNumber(seq int) ([]byte, error) {
	block := node.Chainsql.GetLedger(seq)
	return []byte(block), nil
}

// GetLedgerTransactions request a ledger
func (node *ChainSqlNode) GetLedgerTransactions(seq int) string {
	return node.Chainsql.GetLedgerTransactions(seq, false)
}

func (node *ChainSqlNode) GetTransaction(hash string) (map[string]interface{}, error) {
	var txObject map[string]interface{}
	tx, err := node.Chainsql.GetTransaction(hash)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(tx), &txObject)
	if err != nil {
		return nil, err
	}
	return txObject, nil
}
