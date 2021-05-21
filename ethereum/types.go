// Copyright 2020 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ethereum

import (
	"context"
	"fmt"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

const (
	// NodeVersion is the version of geth we are using.
	NodeVersion = "1.9.24"

	// Blockchain is RSK.
	Blockchain string = "RSK"

	// MainnetNetwork is the value of the network
	// in MainnetNetworkIdentifier.
	MainnetNetwork string = "Mainnet"

	// TestnetNetwork is the value of the network
	// in TestnetNetworkIdentifier.
	TestnetNetwork string = "Testnet"

	// Symbol is the symbol value
	// used in Currency.
	Symbol = "ETH"

	// Decimals is the decimals value
	// used in Currency.
	Decimals = 18

	// MinerRewardOpType is used to describe
	// a miner block reward.
	MinerRewardOpType = "MINER_REWARD"

	// UncleRewardOpType is used to describe
	// an uncle block reward.
	UncleRewardOpType = "UNCLE_REWARD"

	// FeeOpType is used to represent fee operations.
	FeeOpType = "FEE"

	// CallOpType is used to represent CALL trace operations.
	CallOpType = "CALL"

	// CreateOpType is used to represent CREATE trace operations.
	CreateOpType = "CREATE"

	// Create2OpType is used to represent CREATE2 trace operations.
	Create2OpType = "CREATE2"

	// SelfDestructOpType is used to represent SELFDESTRUCT trace operations.
	SelfDestructOpType = "SELFDESTRUCT"

	// CallCodeOpType is used to represent CALLCODE trace operations.
	CallCodeOpType = "CALLCODE"

	// DelegateCallOpType is used to represent DELEGATECALL trace operations.
	DelegateCallOpType = "DELEGATECALL"

	// StaticCallOpType is used to represent STATICCALL trace operations.
	StaticCallOpType = "STATICCALL"

	// DestructOpType is a synthetic operation used to represent the
	// deletion of suicided accounts that still have funds at the end
	// of a transaction.
	DestructOpType = "DESTRUCT"

	// SuccessStatus is the status of any
	// Ethereum operation considered successful.
	SuccessStatus = "SUCCESS"

	// FailureStatus is the status of any
	// Ethereum operation considered unsuccessful.
	FailureStatus = "FAILURE"

	// HistoricalBalanceSupported is whether
	// historical balance is supported.
	HistoricalBalanceSupported = true

	// UnclesRewardMultiplier is the uncle reward
	// multiplier.
	UnclesRewardMultiplier = 32

	// MaxUncleDepth is the maximum depth for
	// an uncle to be rewarded.
	MaxUncleDepth = 1 // TODO: preguntar por que

	// GenesisBlockIndex is the index of the
	// genesis block.
	GenesisBlockIndex = int64(0)

	// TransferGasLimit is the gas limit
	// of a transfer.
	TransferGasLimit = int64(21000) //nolint:gomnd

	// MainnetGethArguments are the arguments to start a mainnet geth instance.
	MainnetGethArguments = `--config=/app/ethereum/geth.toml --gcmode=archive --graphql`

	// IncludeMempoolCoins does not apply to rosetta-rsk as it is not UTXO-based.
	IncludeMempoolCoins = false

	BridgeTransactionDestinationAddress = "0x0000000000000000000000000000000001000006"
	RemascTransactionDestinationAddress = "0x0000000000000000000000000000000001000008"
	RskNormalTransactionCode            = "0x"
	RskRemascTransactionType            = "remasc"
	RskBridgeTransactionType            = "bridge"
	RskContractCallTransactionType      = "contract call"
	RskContractCreationTransactionType  = "contract creation"
	RskNormalTransactionType            = "normal"
)

var (
	// TestnetGethArguments are the arguments to start a ropsten geth instance.
	TestnetGethArguments = fmt.Sprintf("%s --ropsten", MainnetGethArguments)

	// MainnetGenesisBlockIdentifier is the *types.BlockIdentifier
	// of the mainnet genesis block.
	MainnetGenesisBlockIdentifier = &types.BlockIdentifier{
		Hash:  params.MainnetGenesisHash.Hex(),
		Index: GenesisBlockIndex,
	}

	// TestnetGenesisBlockIdentifier is the *types.BlockIdentifier
	// of the testnet genesis block.
	TestnetGenesisBlockIdentifier = &types.BlockIdentifier{
		Hash:  params.RopstenGenesisHash.Hex(),
		Index: GenesisBlockIndex,
	}

	// Currency is the *types.Currency for all
	// Ethereum networks.
	Currency = &types.Currency{
		Symbol:   Symbol,
		Decimals: Decimals,
	}

	// OperationTypes are all suppoorted operation types.
	OperationTypes = []string{
		MinerRewardOpType,
		UncleRewardOpType,
		FeeOpType,
		CallOpType,
		CreateOpType,
		Create2OpType,
		SelfDestructOpType,
		CallCodeOpType,
		DelegateCallOpType,
		StaticCallOpType,
		DestructOpType,
	}

	// OperationStatuses are all supported operation statuses.
	OperationStatuses = []*types.OperationStatus{
		{
			Status:     SuccessStatus,
			Successful: true,
		},
		{
			Status:     FailureStatus,
			Successful: false,
		},
	}

	// CallMethods are all supported call methods.
	CallMethods = []string{
		"eth_getTransactionReceipt",
	}
)

// JSONRPC is the interface for accessing go-ethereum's JSON RPC endpoint.
type JSONRPC interface {
	CallContext(ctx context.Context, result interface{}, method string, args ...interface{}) error
	BatchCallContext(ctx context.Context, b []rpc.BatchElem) error
	Close()
}

// CallType returns a boolean indicating
// if the provided trace type is a call type.
func CallType(t string) bool {
	callTypes := []string{
		CallOpType,
		CallCodeOpType,
		DelegateCallOpType,
		StaticCallOpType,
	}

	for _, callType := range callTypes {
		if callType == t {
			return true
		}
	}

	return false
}

// CreateType returns a boolean indicating
// if the provided trace type is a create type.
func CreateType(t string) bool {
	createTypes := []string{
		CreateOpType,
		Create2OpType,
	}

	for _, createType := range createTypes {
		if createType == t {
			return true
		}
	}

	return false
}

type RskBlock struct {
	Number       string            `json:"number"`
	Hash         string            `json:"hash"`
	ParentHash   string            `json:"parentHash"`
	Timestamp    string            `json:"timestamp"`
	Transactions []*RskTransaction `json:"transactions"`
}

// contract call: 623429 0x67a12211d26c56a4439b2175b67fb20ad90c2800d1b3d338c8d733ebeb648ac7
// normal transfer: 623431 0x47bd2c10f89bdf3e97337eae7eeeeafb38ee159c5f847f0e5492f5939bd38508
// contract creation: 647449 0xf0470726b044468ff0a507350e65746741f54ab2b2e42910b378d8dd9c853b56
// remasc: 647449 0xf0470726b044468ff0a507350e65746741f54ab2b2e42910b378d8dd9c853b56
// bridge: 647432 0xb1a142f62627b0fa33e4275db20518ca2928004b8cbf409197c432de44ac6b5d

type RskTransaction struct {
	Hash               string `json:"hash"`
	TransactionIndex   string `json:"transactionIndex"` // para operation index
	DestinationAddress string `json:"to"`
}
