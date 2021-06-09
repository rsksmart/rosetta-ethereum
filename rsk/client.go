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

package rsk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

const (
	rskjHTTPTimeout                               = 120 * time.Second
	HexadecimalBitSize                            = 64
	HexadecimalBase                               = 0 // 0 forces strconv to use the "0x" prefix to determine base.
	HexadecimalPrefix                             = "0x"
	LatestBlockNumber                             = "latest"
	EthGetBlockByNumberMethod                     = "eth_getBlockByNumber"
	EthGetBlockByHashMethod                       = "eth_getBlockByHash"
	EthGetTransactionCountMethod                  = "eth_getTransactionCount"
	EthGasPriceMethod                             = "eth_gasPrice"
	EthSendRawTransactionMethod                   = "eth_sendRawTransaction"
	EthGetCodeMethod                              = "eth_getCode"
	EthGetTransactionReceiptMethod                = "eth_getTransactionReceipt"
	EthSyncingMethod                              = "eth_syncing"
	EthGetBalanceMethod                           = "eth_getBalance"
	EthCallMethod                                 = "eth_call"
	DebugTraceTransaction                         = "debug_traceTransaction"
	EncodedAccountBalanceFunctionCallPrefixFormat = "0x70a08231000000000000000000000000%s"
)

var operationSuccessStatus = "SUCCESS"

// Client allows for querying a set of specific Ethereum endpoints in an
// idempotent manner. Client relies on the eth_*, debug_*, and admin_*
// methods.
//
// Client borrows HEAVILY from https://github.com/ethereum/go-ethereum/tree/master/ethclient.
type Client struct {
	chainID *big.Int
	c       JSONRPC
}

// NewClient creates a Client that from the provided url and chain ID.
func NewClient(url string, chainID *big.Int) (*Client, error) {
	c, err := rpc.DialHTTPWithClient(url, &http.Client{
		Timeout: rskjHTTPTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: unable to dial node", err)
	}

	return &Client{chainID, c}, nil
}

// Close shuts down the RPC client connection.
func (ec *Client) Close() {
	ec.c.Close()
}

// Status returns geth status information
// for determining node healthiness.
func (ec *Client) Status(ctx context.Context) (
	*RosettaTypes.BlockIdentifier,
	int64,
	*RosettaTypes.SyncStatus,
	[]*RosettaTypes.Peer,
	error,
) {
	header, err := ec.blockHeader(ctx, nil)
	if err != nil {
		return nil, -1, nil, nil, err
	}

	progress, err := ec.syncProgress(ctx)
	if err != nil {
		return nil, -1, nil, nil, err
	}

	var syncStatus *RosettaTypes.SyncStatus
	if progress != nil {
		currentIndex := int64(progress.CurrentBlock)
		targetIndex := int64(progress.HighestBlock)

		syncStatus = &RosettaTypes.SyncStatus{
			CurrentIndex: &currentIndex,
			TargetIndex:  &targetIndex,
		}
	}

	peers, err := ec.peers(ctx)
	if err != nil {
		return nil, -1, nil, nil, err
	}

	return &RosettaTypes.BlockIdentifier{
			Hash:  header.Hash().Hex(),
			Index: header.Number.Int64(),
		},
		convertTime(header.Time),
		syncStatus,
		peers,
		nil
}

// Header returns a block header from the current canonical chain. If number is
// nil, the latest known header is returned.
func (ec *Client) blockHeader(ctx context.Context, number *big.Int) (*types.Header, error) {
	var head *types.Header
	err := ec.c.CallContext(ctx, &head, EthGetBlockByNumberMethod, toBlockNumArg(number), false)
	if err == nil && head == nil {
		return nil, ethereum.NotFound
	}

	return head, err
}

func convertTime(time uint64) int64 {
	return int64(time) * 1000
}

// PendingNonceAt returns the account nonce of the given account in the pending state.
// This is the nonce that should be used for the next transaction.
func (ec *Client) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, EthGetTransactionCountMethod, account, "pending")
	return uint64(result), err
}

// SuggestGasPrice retrieves the currently suggested gas price to allow a timely
// execution of a transaction.
func (ec *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := ec.c.CallContext(ctx, &hex, EthGasPriceMethod); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

// Peers retrieves all peers of the node.
func (ec *Client) peers(ctx context.Context) ([]*RosettaTypes.Peer, error) {
	var info []*p2p.PeerInfo
	if err := ec.c.CallContext(ctx, &info, "admin_peers"); err != nil {
		return nil, err
	}

	peers := make([]*RosettaTypes.Peer, len(info))
	for i, peerInfo := range info {
		peers[i] = &RosettaTypes.Peer{
			PeerID: peerInfo.ID,
			Metadata: map[string]interface{}{
				"name":      peerInfo.Name,
				"enode":     peerInfo.Enode,
				"caps":      peerInfo.Caps,
				"enr":       peerInfo.ENR,
				"protocols": peerInfo.Protocols,
			},
		}
	}

	return peers, nil
}

// SendTransaction injects a signed transaction into the pending pool for execution.
//
// If the transaction was a contract creation use the TransactionReceipt method to get the
// contract address after the transaction has been mined.
func (ec *Client) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	data, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return err
	}
	return ec.c.CallContext(ctx, nil, EthSendRawTransactionMethod, hexutil.Encode(data))
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	pending := big.NewInt(-1)
	if number.Cmp(pending) == 0 {
		return "pending"
	}
	return hexutil.EncodeBig(number)
}

// Block returns a populated block at the *RosettaTypes.PartialBlockIdentifier.
// If neither the hash or index is populated in the *RosettaTypes.PartialBlockIdentifier,
// the current block is returned.
func (ec *Client) Block(
	ctx context.Context,
	blockIdentifier *RosettaTypes.PartialBlockIdentifier,
) (*RosettaTypes.Block, error) {
	if blockIdentifier != nil {
		if blockIdentifier.Hash != nil {
			block, err := ec.getParsedBlock(ctx, EthGetBlockByHashMethod, *blockIdentifier.Hash, true)
			return block, err
		}
		if blockIdentifier.Index != nil {
			block, err := ec.getParsedBlock(
				ctx,
				EthGetBlockByNumberMethod,
				toBlockNumArg(big.NewInt(*blockIdentifier.Index)),
				true,
			)
			return block, err
		}
	}
	block, err := ec.getParsedBlock(ctx, EthGetBlockByNumberMethod, toBlockNumArg(nil), true)
	return block, err
}

func (ec *Client) getParsedBlock(
	ctx context.Context,
	blockMethod string,
	args ...interface{},
) (
	*RosettaTypes.Block,
	error,
) {
	var raw json.RawMessage
	err := ec.c.CallContext(ctx, &raw, blockMethod, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: block fetch failed", err)
	} else if len(raw) == 0 {
		return nil, errors.New("failed to get block, result was empty")
	}

	var rskBlock Block
	if err := json.Unmarshal(raw, &rskBlock); err != nil {
		return nil, err
	}

	return ec.buildRosettaFormattedBlock(ctx, rskBlock)
}

func (ec *Client) buildRosettaFormattedBlock(ctx context.Context, rskBlock Block) (*RosettaTypes.Block, error) {
	rosettaFormattedBlockNumber, err := hexToInt(rskBlock.Number)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse block number", err)
	}
	blockIdentifier := &RosettaTypes.BlockIdentifier{
		Index: rosettaFormattedBlockNumber,
		Hash:  rskBlock.Hash,
	}
	parentBlockIdentifier := ec.buildParentBlockIdentifierFromBlockIdentifier(blockIdentifier, rskBlock)
	rosettaTimestamp, err := hexToInt(rskBlock.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse block timestamp", err)
	}

	rosettaTransactions, err := ec.buildRosettaTransactions(ctx, rskBlock)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to build rosetta transactions", err)
	}

	return &RosettaTypes.Block{
		BlockIdentifier:       blockIdentifier,
		ParentBlockIdentifier: parentBlockIdentifier,
		Timestamp:             rosettaTimestamp,
		Transactions:          rosettaTransactions,
		Metadata:              nil,
	}, nil
}

func hexToInt(hex string) (int64, error) {
	return strconv.ParseInt(hex, HexadecimalBase, HexadecimalBitSize)
}

func hexToFloat(hex string) (*big.Float, error) {
	i, err := strconv.ParseUint(hex, HexadecimalBase, HexadecimalBitSize)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse %s", err, hex)
	}
	return big.NewFloat(math.Float64frombits(i)), nil
}

func (ec *Client) buildRosettaTransactions(ctx context.Context, rskBlock Block) ([]*RosettaTypes.Transaction, error) {
	rosettaTransactions := make([]*RosettaTypes.Transaction, len(rskBlock.Transactions))
	var wg sync.WaitGroup
	errorChannel := make(chan error, len(rskBlock.Transactions))
	for index, rskTransaction := range rskBlock.Transactions {
		wg.Add(1)
		go ec.addRosettaTransactionToRosettaTransactions(ctx, rskBlock, rskTransaction, rosettaTransactions, index, &wg, errorChannel)
	}

	wg.Wait()
	close(errorChannel)
	select {
	case err, errorOccurred := <-errorChannel:
		if errorOccurred {
			return nil, fmt.Errorf("%w: failed to build rosetta transactions", err)
		}
	}

	return rosettaTransactions, nil
}

func (ec *Client) addRosettaTransactionToRosettaTransactions(ctx context.Context, rskBlock Block,
	rskTransaction *Transaction, rosettaTransactions []*RosettaTypes.Transaction, index int, wg *sync.WaitGroup,
	errorChannel chan<- error) {
	defer wg.Done()
	rosettaTransactionIdentifier := &RosettaTypes.TransactionIdentifier{
		Hash: rskTransaction.Hash,
	}
	transactionIndex, err := hexToInt(rskTransaction.TransactionIndex)
	if err != nil {
		errorChannel <- fmt.Errorf("%w: failed to parse transaction index", err)
		return
	}

	rskTransactionType, err := ec.determineRskTransactionType(ctx, rskBlock.Number, rskTransaction)
	if err != nil {
		errorChannel <- fmt.Errorf("%w: failed to determine transaction type", err)
		return
	}

	// TODO: get debug_traceBlockByHash vs. debug_traceTransactionByHash? to build tx metadata
	// TODO: get tx receipt to create operations

	transactionReceipt, err := ec.getTransactionReceipt(ctx, rskTransaction.Hash)
	if err != nil {
		errorChannel <- fmt.Errorf("%w: failed to get receipt for transaction %s", err, rskTransaction.Hash)
		return
	}
	transactionTrace, err := ec.getTransactionTrace(ctx, rskTransaction.Hash)
	if err != nil {
		errorChannel <- fmt.Errorf("%w: failed to get trace for transaction %s", err, rskTransaction.Hash)
		return
	}

	rosettaTransactionOperation := &RosettaTypes.Operation{
		OperationIdentifier: &RosettaTypes.OperationIdentifier{
			Index: transactionIndex,
		},
		Type: rskTransactionType,
	}

	transactionGasPrice, err := hexToInt(rskTransaction.GasPrice)
	if err != nil {
		errorChannel <- fmt.Errorf("%w: failed to convert gas price to float", err)
		return
	}

	transactionGasUsed, err := hexToInt(transactionReceipt.GasUsed)
	if err != nil {
		errorChannel <- fmt.Errorf("%w: failed to convert gas used to float", err)
		return
	}

	// TODO: chequear que vienen bien los floats
	rosettaTransactionOperations := []*RosettaTypes.Operation{rosettaTransactionOperation}


	// 0.000000000183 * 0.000006826083

	// 1.6662527471175838e-634

	// 1,249173189E-15

	fmt.Printf("first: %d, second: %d\n", transactionGasPrice, transactionGasUsed)

	transactionFeeAmount := transactionGasPrice * transactionGasUsed
	if transactionFeeAmount != 0 {

		deductionFeeIdentifier := &RosettaTypes.OperationIdentifier{
			Index: 0,
		}
		fee1 := &RosettaTypes.Operation{
			OperationIdentifier: deductionFeeIdentifier,
			RelatedOperations:   nil,
			Type:                "FEE", // TODO: move to actual type constant or something
			Status:              &operationSuccessStatus,
			Account: &RosettaTypes.AccountIdentifier{
				Address: rskTransaction.From,
			},
			Amount: &RosettaTypes.Amount{
				Value:    fmt.Sprint(transactionFeeAmount),
				Currency: DefaultCurrency,
			},
		}
		fmt.Printf("fee1: \n%v\n", fee1)

		fee2 := &RosettaTypes.Operation{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: 1,
			},
			RelatedOperations: []*RosettaTypes.OperationIdentifier{deductionFeeIdentifier},
			Type:              "FEE", // TODO: move to actual type constant or something
			Status:            &operationSuccessStatus,
			Account: &RosettaTypes.AccountIdentifier{
				Address: rskTransaction.To,
			},
			Amount: &RosettaTypes.Amount{
				Value:    fmt.Sprint(transactionFeeAmount * -1),
				Currency: DefaultCurrency,
			},
		}
		fmt.Printf("fee2: \n%v\n", fee2)

		rosettaTransactionOperations = append(rosettaTransactionOperations, fee1, fee2)
	}

	// TODO: create operations

	rosettaMetadata := map[string]interface{}{
		"receipt": transactionReceipt,
		"trace":   transactionTrace,
	}

	rosettaTransactions[index] = &RosettaTypes.Transaction{
		TransactionIdentifier: rosettaTransactionIdentifier,
		Operations:            rosettaTransactionOperations,
		Metadata:              rosettaMetadata,
	}
}

func (ec *Client) buildParentBlockIdentifierFromBlockIdentifier(blockIdentifier *RosettaTypes.BlockIdentifier, rskBlock Block) *RosettaTypes.BlockIdentifier {
	parentBlockIdentifier := blockIdentifier
	if blockIdentifier.Index != GenesisBlockIndex {
		parentBlockIdentifier = &RosettaTypes.BlockIdentifier{
			Hash:  rskBlock.ParentHash,
			Index: blockIdentifier.Index - 1,
		}
	}
	return parentBlockIdentifier
}

func (ec *Client) determineRskTransactionType(ctx context.Context, rskBlockNumber string, rskTransaction *Transaction) (string, error) {
	if rskTransaction.To == "" {
		return RskContractCreationTransactionType, nil
	} else if rskTransaction.To == RemascTransactionDestinationAddress {
		return RskRemascTransactionType, nil
	} else if rskTransaction.To == BridgeTransactionDestinationAddress {
		return RskBridgeTransactionType, nil
	} else {
		var rawResponse json.RawMessage
		err := ec.c.CallContext(ctx, &rawResponse, EthGetCodeMethod, rskTransaction.To, rskBlockNumber)
		if err != nil {
			return "", fmt.Errorf("%w: failed to get code for block's destination address", err)
		}
		if rawResponse != nil {
			return ec.determineRskTransactionTypeFromEthGetCodeRawResponse(rawResponse)
		}
	}
	return "", errors.New("failed to determine transaction type")
}

func (ec *Client) determineRskTransactionTypeFromEthGetCodeRawResponse(rawResponse json.RawMessage) (string, error) {
	var response string
	err := json.Unmarshal(rawResponse, &response)
	if err != nil {
		return "", errors.New("failed to parse eth_getCode response")
	}
	if response == RskNormalTransactionCode {
		return RskNormalTransactionType, nil
	}
	return RskContractCallTransactionType, nil
}

// Call is an Ethereum debug trace.
type Call struct {
	Type         string         `json:"type"`
	From         common.Address `json:"from"`
	To           common.Address `json:"to"`
	Value        *big.Int       `json:"value"`
	GasUsed      *big.Int       `json:"gasUsed"`
	Revert       bool
	ErrorMessage string  `json:"error"`
	Calls        []*Call `json:"calls"`
}

type flatCall struct {
	Type         string         `json:"type"`
	From         common.Address `json:"from"`
	To           common.Address `json:"to"`
	Value        *big.Int       `json:"value"`
	GasUsed      *big.Int       `json:"gasUsed"`
	Revert       bool
	ErrorMessage string `json:"error"`
}

func (t *Call) flatten() *flatCall {
	return &flatCall{
		Type:         t.Type,
		From:         t.From,
		To:           t.To,
		Value:        t.Value,
		GasUsed:      t.GasUsed,
		Revert:       t.Revert,
		ErrorMessage: t.ErrorMessage,
	}
}

// UnmarshalJSON is a custom unmarshaler for Call.
func (t *Call) UnmarshalJSON(input []byte) error {
	type CustomTrace struct {
		Type         string         `json:"type"`
		From         common.Address `json:"from"`
		To           common.Address `json:"to"`
		Value        *hexutil.Big   `json:"value"`
		GasUsed      *hexutil.Big   `json:"gasUsed"`
		Revert       bool
		ErrorMessage string  `json:"error"`
		Calls        []*Call `json:"calls"`
	}
	var dec CustomTrace
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}

	t.Type = dec.Type
	t.From = dec.From
	t.To = dec.To
	if dec.Value != nil {
		t.Value = (*big.Int)(dec.Value)
	} else {
		t.Value = new(big.Int)
	}
	if dec.GasUsed != nil {
		t.GasUsed = (*big.Int)(dec.Value)
	} else {
		t.GasUsed = new(big.Int)
	}
	if dec.ErrorMessage != "" {
		// Any error surfaced by the decoder means that the transaction
		// has reverted.
		t.Revert = true
	}
	t.ErrorMessage = dec.ErrorMessage
	t.Calls = dec.Calls
	return nil
}

// getTransactionReceipt returns the receipt of a transaction by transaction hash.
func (ec *Client) getTransactionReceipt(
	ctx context.Context,
	transactionHash string,
) (*Receipt, error) {
	var receipt *Receipt
	err := ec.c.CallContext(ctx, &receipt, EthGetTransactionReceiptMethod, transactionHash)
	if err == nil {
		if receipt == nil {
			return nil, ethereum.NotFound
		}
	}
	return receipt, err
}

func (ec *Client) getTransactionTrace(ctx context.Context, transactionHash string) (*Trace, error) {
	var raw json.RawMessage
	if err := ec.c.CallContext(ctx, &raw, DebugTraceTransaction, transactionHash); err != nil {
		return nil, fmt.Errorf("%w: failed to obtain trace for transaction %s", err, transactionHash)
	}

	var transactionTrace *Trace
	if err := json.Unmarshal(raw, &transactionTrace); err != nil {
		return nil, fmt.Errorf("%w: failed to parse program trace for transaction %s", err, transactionHash)
	}

	return transactionTrace, nil
}

type rpcProgress struct {
	StartingBlock hexutil.Uint64
	CurrentBlock  hexutil.Uint64
	HighestBlock  hexutil.Uint64
	PulledStates  hexutil.Uint64
	KnownStates   hexutil.Uint64
}

// syncProgress retrieves the current progress of the sync algorithm. If there's
// no sync currently running, it returns nil.
func (ec *Client) syncProgress(ctx context.Context) (*ethereum.SyncProgress, error) {
	var raw json.RawMessage
	if err := ec.c.CallContext(ctx, &raw, EthSyncingMethod); err != nil {
		return nil, err
	}

	var syncing bool
	if err := json.Unmarshal(raw, &syncing); err == nil {
		return nil, nil // Not syncing (always false)
	}

	var progress rpcProgress
	if err := json.Unmarshal(raw, &progress); err != nil {
		return nil, err
	}

	return &ethereum.SyncProgress{
		StartingBlock: uint64(progress.StartingBlock),
		CurrentBlock:  uint64(progress.CurrentBlock),
		HighestBlock:  uint64(progress.HighestBlock),
		PulledStates:  uint64(progress.PulledStates),
		KnownStates:   uint64(progress.KnownStates),
	}, nil
}

// Balance returns the balance of a *RosettaTypes.AccountIdentifier
// at a *RosettaTypes.PartialBlockIdentifier.
func (ec *Client) Balance(
	ctx context.Context,
	account *RosettaTypes.AccountIdentifier,
	block *RosettaTypes.PartialBlockIdentifier,
	currencies []*RosettaTypes.Currency,
) (*RosettaTypes.AccountBalanceResponse, error) {

	err := ec.validateRequestCurrencies(currencies)
	if err != nil {
		return nil, fmt.Errorf("%w: error validating request currencies", err)
	}
	if currencies == nil || len(currencies) == 0 {
		currencies = AvailableCurrencies
	}

	accountBalanceResponse := &RosettaTypes.AccountBalanceResponse{
		Balances: []*RosettaTypes.Amount{},
	}

	blockIdentifier, err := ec.getBlockIdentifierForAccountBalance(ctx, block)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to obtain block identifier", err)
	}

	balanceChannel := make(chan *RosettaTypes.Amount, len(currencies))
	errorChannel := make(chan error, len(currencies))
	var wg sync.WaitGroup

	for _, currency := range currencies {
		wg.Add(1)
		go ec.processBalanceForCurrency(ctx, account, blockIdentifier, currency, balanceChannel, errorChannel, &wg)
	}

	wg.Wait()
	close(balanceChannel)
	close(errorChannel)

	select {
	case err, errorOccurred := <-errorChannel:
		if errorOccurred {
			return nil, err
		}
	}

	for balance := range balanceChannel {
		accountBalanceResponse.Balances = append(accountBalanceResponse.Balances, balance)
	}
	accountBalanceResponse.BlockIdentifier = blockIdentifier

	return accountBalanceResponse, nil
}

func (ec *Client) validateRequestCurrencies(currencies []*RosettaTypes.Currency) error {
	for _, currency := range currencies {
		tokenDecimals, isTokenValid := DecimalsByCurrencySymbol[currency.Symbol]
		if !isTokenValid {
			return fmt.Errorf("currency '%v' is not supported", currency.Symbol)
		}
		if tokenDecimals != currency.Decimals {
			return fmt.Errorf("currency '%v' uses %d decimals", currency.Symbol, tokenDecimals)
		}
	}
	return nil
}

func (ec *Client) processBalanceForCurrency(ctx context.Context, account *RosettaTypes.AccountIdentifier,
	blockIdentifier *RosettaTypes.BlockIdentifier, currency *RosettaTypes.Currency,
	balanceChannel chan<- *RosettaTypes.Amount, errorChannel chan<- error, wg *sync.WaitGroup) {

	defer wg.Done()

	var balance *RosettaTypes.Amount
	var err error
	if currency.Symbol == DefaultCurrency.Symbol {
		balance, err = ec.getAccountBalanceForDefaultCurrency(ctx, account, blockIdentifier)
	} else {
		balance, err = ec.getAccountBalanceForToken(ctx, account, blockIdentifier, currency)
	}

	if err != nil {
		errorChannel <- fmt.Errorf("%w: failed to get account balance", err)
		return
	}
	balanceChannel <- balance
}

func (ec *Client) getAccountBalanceForDefaultCurrency(ctx context.Context, account *RosettaTypes.AccountIdentifier,
	blockIdentifier *RosettaTypes.BlockIdentifier) (*RosettaTypes.Amount, error) {
	var stringifiedBalanceValue string
	blockIndexHex := fmt.Sprintf("%s%x", HexadecimalPrefix, blockIdentifier.Index)
	accountAddress := account.Address
	stringifiedBalanceValue, err := ec.getStringifiedAccountBalanceForBlock(ctx, blockIndexHex, accountAddress)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get account balance", err)
	}
	balance := &RosettaTypes.Amount{
		Value:    stringifiedBalanceValue,
		Currency: DefaultCurrency,
	}
	return balance, nil
}

func (ec *Client) getStringifiedAccountBalanceForBlock(ctx context.Context, blockIndexHex string, accountAddress string) (string, error) {
	var rawResponse json.RawMessage
	err := ec.c.CallContext(ctx, &rawResponse, EthGetBalanceMethod, accountAddress, blockIndexHex)
	if err != nil {
		return "", fmt.Errorf("%w: failed to get balance for address %s and block %s", err, accountAddress, blockIndexHex)
	}
	if rawResponse != nil {
		var response string
		err := json.Unmarshal(rawResponse, &response)
		if err != nil {
			return "", fmt.Errorf("%w: failed to unmarshal response for eth_getBalance", err)
		}
		balanceValue, err := hexToInt(response)
		if err != nil {
			return "", fmt.Errorf("%w: failed to parse response for eth_getBalance", err)
		}
		return strconv.FormatInt(balanceValue, 10), nil
	}
	return "", fmt.Errorf("got empty response in eth_getBalance for address %s and block %s", accountAddress, blockIndexHex)
}

func (ec *Client) getBlockIdentifierForAccountBalance(ctx context.Context, partialBlockIdentifier *RosettaTypes.PartialBlockIdentifier) (*RosettaTypes.BlockIdentifier, error) {
	if partialBlockIdentifier != nil && partialBlockIdentifier.Hash != nil && partialBlockIdentifier.Index != nil {
		return &RosettaTypes.BlockIdentifier{
			Index: *partialBlockIdentifier.Index,
			Hash:  *partialBlockIdentifier.Hash,
		}, nil
	}
	if partialBlockIdentifier != nil && partialBlockIdentifier.Hash != nil {
		return ec.buildBlockIdentifierFromBlockHash(ctx, partialBlockIdentifier)
	}
	return ec.buildBlockIdentifierFromBlockNumber(ctx, partialBlockIdentifier)
}

func (ec *Client) buildBlockIdentifierFromBlockHash(ctx context.Context, partialBlockIdentifier *RosettaTypes.PartialBlockIdentifier) (*RosettaTypes.BlockIdentifier, error) {
	block, err := ec.getParsedBlock(ctx, EthGetBlockByHashMethod, *partialBlockIdentifier.Hash, true)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get block by hash (%s)", err, *partialBlockIdentifier.Hash)
	}
	return block.BlockIdentifier, nil
}

func (ec *Client) buildBlockIdentifierFromBlockNumber(ctx context.Context, partialBlockIdentifier *RosettaTypes.PartialBlockIdentifier) (*RosettaTypes.BlockIdentifier, error) {
	var stringifiedBlockNumber string
	if partialBlockIdentifier != nil && partialBlockIdentifier.Index != nil {
		stringifiedBlockNumber = toBlockNumArg(big.NewInt(*partialBlockIdentifier.Index))
	} else {
		stringifiedBlockNumber = LatestBlockNumber
	}
	block, err := ec.getParsedBlock(ctx, EthGetBlockByNumberMethod, stringifiedBlockNumber, true)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get block by number (%s)", err, stringifiedBlockNumber)
	}
	return block.BlockIdentifier, nil
}

func (ec *Client) getAccountBalanceForToken(ctx context.Context, account *RosettaTypes.AccountIdentifier,
	blockIdentifier *RosettaTypes.BlockIdentifier, currency *RosettaTypes.Currency) (*RosettaTypes.Amount, error) {
	var response string
	addressWithoutPrefix := account.Address[2:]
	balanceFunctionParameters := map[string]string{
		"data": fmt.Sprintf(EncodedAccountBalanceFunctionCallPrefixFormat, addressWithoutPrefix),
		"to":   AddressByTokenSymbol[currency.Symbol],
	}
	blockIndexHex := fmt.Sprintf("%s%x", HexadecimalPrefix, blockIdentifier.Index)
	err := ec.c.CallContext(ctx, &response, EthCallMethod, balanceFunctionParameters, blockIndexHex)
	if err != nil {
		return nil, fmt.Errorf("%w: block fetch failed", err)
	} else if len(response) == 0 {
		return nil, errors.New("failed to get block, result was empty")
	}
	balanceValue := ec.formatBigHexToDecimalString(response)
	return &RosettaTypes.Amount{
		Value:    balanceValue,
		Currency: currency,
	}, nil
}

func (ec *Client) formatBigHexToDecimalString(response string) string {
	n := new(big.Int)
	response = strings.Replace(response, HexadecimalPrefix, "", -1)
	n.SetString(response, 16)
	return n.String()
}

// GetTransactionReceiptInput is the input to the call
// method "eth_getTransactionReceipt".
type GetTransactionReceiptInput struct {
	TxHash string `json:"tx_hash"`
}
