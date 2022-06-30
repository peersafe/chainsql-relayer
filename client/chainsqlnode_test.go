package client

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/polynetwork/chainsql-relayer/log"
)

func NotifyBlockNumber(blockNumber int64) {
	log.Infof("BlockNunber: %d", blockNumber)
}

func TestSubscribeBlock(t *testing.T) {
	account := Account{
		Address: "zHb9CJAWyB4zj91VRWn96DkukG4bwdtyTh",
		Secrect: "xnoPBzXtMeMyMHUVTgbuqAfg1SUTb",
	}
	config := &Config{
		URL:     "ws://127.0.0.1:6006",
		Account: account,
	}

	chainsql, _ := Dial(config)
	current, _ := chainsql.GetBlockNumber()
	txs := chainsql.GetLedgerTransactions(current)
	var TxsObject map[string]interface{}
	log.Infof("current block: %d", current)
	log.Info(txs)
	json.Unmarshal([]byte(txs), &TxsObject)
	result := TxsObject["result"].(map[string]interface{})
	ledger := result["ledger"].(map[string]interface{})
	transactions := reflect.ValueOf(ledger["transactions"])
	for i := 0; i < transactions.Len(); i++ {
		txHash := transactions.Index(i).Interface().(string)
		log.Infof("hash: %s", txHash)
		tx, _ := chainsql.GetTransaction(txHash)
		log.Infof("tx: %s", tx)
	}
	chainsql.SubscribeBlockNumberNotify(func(seq int) {
		block, _ := chainsql.GetBlockByNumber(seq)
		log.Infof("Block's heigh: %d", seq)
		log.Info(string(block))
	})

	for {
		time.Sleep(time.Second * 1)
	}
}
