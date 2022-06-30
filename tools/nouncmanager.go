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
package tools

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/polynetwork/chainsql-relayer/log"
)

const clear_nonce_interval = 10 * time.Minute

type NonceManager struct {
	addressNonce  map[common.Address]uint64
	returnedNonce map[common.Address]SortedNonceArr
	ethClient     *ethclient.Client
	lock          sync.Mutex
}

func NewNonceManager(ethClient *ethclient.Client) *NonceManager {
	nonceManager := &NonceManager{
		addressNonce:  make(map[common.Address]uint64),
		ethClient:     ethClient,
		returnedNonce: make(map[common.Address]SortedNonceArr),
	}
	go nonceManager.clearNonce()
	return nonceManager
}

// return account nonce, and than nonce++
func (m *NonceManager) GetAddressNonce(address common.Address) uint64 {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.returnedNonce[address].Len() > 0 {
		nonce := m.returnedNonce[address][0]
		m.returnedNonce[address] = m.returnedNonce[address][1:]
		return nonce
	}

	// return a new point
	nonce, ok := m.addressNonce[address]
	if !ok {
		// get nonce from eth network
		uintNonce, err := m.ethClient.PendingNonceAt(context.Background(), address)
		if err != nil {
			log.Errorf("GetAddressNonce: cannot get account %s nonce, err: %s, set it to nil!",
				address, err)
		}
		m.addressNonce[address] = uintNonce
		nonce = uintNonce
	}
	// increase record
	m.addressNonce[address]++
	return nonce
}

func (m *NonceManager) ReturnNonce(addr common.Address, nonce uint64) {
	m.lock.Lock()
	defer m.lock.Unlock()

	arr, ok := m.returnedNonce[addr]
	if !ok {
		arr = make([]uint64, 0)
	}
	arr = append(arr, nonce)
	sort.Sort(arr)
	m.returnedNonce[addr] = arr
}

func (m *NonceManager) DecreaseAddressNonce(address common.Address) {
	m.lock.Lock()
	defer m.lock.Unlock()

	nonce, ok := m.addressNonce[address]
	if ok && nonce > 0 {
		m.addressNonce[address]--
	}
}

// clear nonce per
func (m *NonceManager) clearNonce() {
	for {
		<-time.After(clear_nonce_interval)
		m.lock.Lock()
		for addr, _ := range m.addressNonce {
			delete(m.addressNonce, addr)
		}
		m.lock.Unlock()
	}
}

type SortedNonceArr []uint64

func (arr SortedNonceArr) Less(i, j int) bool {
	return arr[i] < arr[j]
}

func (arr SortedNonceArr) Len() int { return len(arr) }

func (arr SortedNonceArr) Swap(i, j int) { arr[i], arr[j] = arr[j], arr[i] }
