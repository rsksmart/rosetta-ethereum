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
	"golang.org/x/sync/semaphore"
)

const (
	gethHTTPTimeout = 120 * time.Second

	maxTraceConcurrency            = int64(16) // nolint:gomnd
	HexadecimalBitSize             = 64
	HexadecimalBase                = 0
	LatestBlockNumber              = "latest"
	EthGetBlockByNumberMethod      = "eth_getBlockByNumber"
	EthGetBlockByHashMethod        = "eth_getBlockByHash"
	EthGetTransactionCountMethod   = "eth_getTransactionCount"
	EthGasPriceMethod              = "eth_gasPrice"
	EthSendRawTransactionMethod    = "eth_sendRawTransaction"
	EthGetCodeMethod               = "eth_getCode"
	EthGetTransactionReceiptMethod = "eth_getTransactionReceipt"
	EthSyncingMethod               = "eth_syncing"
	EthGetBalanceMethod            = "eth_getBalance"
	EthCallMethod                  = "eth_call"
)

// Client allows for querying a set of specific Ethereum endpoints in an
// idempotent manner. Client relies on the eth_*, debug_*, and admin_*
// methods.
//
// Client borrows HEAVILY from https://github.com/ethereum/go-ethereum/tree/master/ethclient.
type Client struct {
	chainID        *big.Int
	c              JSONRPC
	traceSemaphore *semaphore.Weighted // TODO: delete if won't use traces.
}

// NewClient creates a Client that from the provided url and chain ID.
func NewClient(url string, chainID *big.Int) (*Client, error) {
	c, err := rpc.DialHTTPWithClient(url, &http.Client{
		Timeout: gethHTTPTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: unable to dial node", err)
	}

	return &Client{chainID, c, semaphore.NewWeighted(maxTraceConcurrency)}, nil
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

	var rskBlock RskBlock
	if err := json.Unmarshal(raw, &rskBlock); err != nil {
		return nil, err
	}

	return ec.buildRosettaFormattedBlock(ctx, rskBlock)
}

func (ec *Client) buildRosettaFormattedBlock(ctx context.Context, rskBlock RskBlock) (*RosettaTypes.Block, error) {
	rosettaFormattedBlockNumber, err := strconv.ParseInt(rskBlock.Number, HexadecimalBase, HexadecimalBitSize) // 0 forces strconv to use the "0x" prefix to determine base.
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse block number", err)
	}
	blockIdentifier := &RosettaTypes.BlockIdentifier{
		Index: rosettaFormattedBlockNumber,
		Hash:  rskBlock.Hash,
	}
	parentBlockIdentifier := ec.buildParentBlockIdentifierFromBlockIdentifier(blockIdentifier, rskBlock)
	rosettaTimestamp, err := strconv.ParseInt(rskBlock.Timestamp, HexadecimalBase, HexadecimalBitSize)
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

func (ec *Client) buildRosettaTransactions(ctx context.Context, rskBlock RskBlock) ([]*RosettaTypes.Transaction, error) {
	rosettaTransactions := make([]*RosettaTypes.Transaction, len(rskBlock.Transactions))
	for index, rskTransaction := range rskBlock.Transactions {
		rosettaTransactionIdentifier := &RosettaTypes.TransactionIdentifier{
			Hash: rskTransaction.Hash,
		}
		transactionIndex, err := strconv.ParseInt(rskTransaction.TransactionIndex, HexadecimalBase, HexadecimalBitSize)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse transaction index", err)
		}

		rskTransactionType, err := ec.determineRskTransactionType(ctx, rskBlock.Number, rskTransaction)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to determine transaction type", err)
		}

		rosettaTransactionOperation := &RosettaTypes.Operation{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: transactionIndex,
			},
			Type: rskTransactionType,
		}
		rosettaTransactionOperations := []*RosettaTypes.Operation{rosettaTransactionOperation}
		rosettaTransactions[index] = &RosettaTypes.Transaction{
			TransactionIdentifier: rosettaTransactionIdentifier,
			Operations:            rosettaTransactionOperations,
			Metadata:              nil,
		}
	}
	return rosettaTransactions, nil
}

func (ec *Client) buildParentBlockIdentifierFromBlockIdentifier(blockIdentifier *RosettaTypes.BlockIdentifier, rskBlock RskBlock) *RosettaTypes.BlockIdentifier {
	parentBlockIdentifier := blockIdentifier
	if blockIdentifier.Index != GenesisBlockIndex {
		parentBlockIdentifier = &RosettaTypes.BlockIdentifier{
			Hash:  rskBlock.ParentHash,
			Index: blockIdentifier.Index - 1,
		}
	}
	return parentBlockIdentifier
}

func (ec *Client) determineRskTransactionType(ctx context.Context, rskBlockNumber string, rskTransaction *RskTransaction) (string, error) {
	if rskTransaction.DestinationAddress == "" {
		return RskContractCreationTransactionType, nil
	} else if rskTransaction.DestinationAddress == RemascTransactionDestinationAddress {
		return RskRemascTransactionType, nil
	} else if rskTransaction.DestinationAddress == BridgeTransactionDestinationAddress {
		return RskBridgeTransactionType, nil
	} else {
		var rawResponse json.RawMessage
		err := ec.c.CallContext(ctx, &rawResponse, EthGetCodeMethod, rskTransaction.DestinationAddress, rskBlockNumber)
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

// transactionReceipt returns the receipt of a transaction by transaction hash.
// Note that the receipt is not available for pending transactions.
func (ec *Client) transactionReceipt(
	ctx context.Context,
	txHash common.Hash,
) (*types.Receipt, error) {
	var r *types.Receipt
	err := ec.c.CallContext(ctx, &r, EthGetTransactionReceiptMethod, txHash)
	if err == nil {
		if r == nil {
			return nil, ethereum.NotFound
		}
	}

	return r, err
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
		if currency.Symbol == DefaultCurrency.Symbol {
			if currency.Decimals != DefaultCurrency.Decimals {
				return fmt.Errorf("default currency (%s) uses %d decimals", DefaultCurrency.Symbol, DefaultCurrency.Decimals)
			}
			continue
		}
		tokenDecimals, isTokenValid := DecimalsByToken[currency.Symbol]
		if !isTokenValid {
			return fmt.Errorf("currency %v is not supported", *currency)
		}
		if tokenDecimals != currency.Decimals {
			return fmt.Errorf("token %v uses %d decimals", currency.Symbol, tokenDecimals)
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
	blockIndexHex := fmt.Sprintf("0x%x", blockIdentifier.Index)
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

func hexToInt(hex string) (int64, error) {
	hex = strings.Replace(hex, "0x", "", -1)
	return strconv.ParseInt(hex, 16, HexadecimalBitSize)
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
	balanceFunctionParameters := map[string]string{
		"data": fmt.Sprintf("0x70a08231000000000000000000000000%s", account.Address[2:]),
		"to":   AddressByTokenSymbol[currency.Symbol],
	}
	blockIndexHex := fmt.Sprintf("0x%x", blockIdentifier.Index)
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
	response = strings.Replace(response, "0x", "", -1)
	n.SetString(response, 16)
	return n.String()
}

// GetTransactionReceiptInput is the input to the call
// method "eth_getTransactionReceipt".
type GetTransactionReceiptInput struct {
	TxHash string `json:"tx_hash"`
}

// Call handles calls to the /call endpoint.
func (ec *Client) Call(
	ctx context.Context,
	request *RosettaTypes.CallRequest,
) (*RosettaTypes.CallResponse, error) {
	switch request.Method { // nolint:gocritic
	case EthGetTransactionReceiptMethod:
		var input GetTransactionReceiptInput
		if err := RosettaTypes.UnmarshalMap(request.Parameters, &input); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCallParametersInvalid, err.Error())
		}

		if len(input.TxHash) == 0 {
			return nil, fmt.Errorf("%w:tx_hash missing from params", ErrCallParametersInvalid)
		}

		receipt, err := ec.transactionReceipt(ctx, common.HexToHash(input.TxHash))
		if err != nil {
			return nil, err
		}

		// We cannot use RosettaTypes.MarshalMap because geth uses a custom
		// marshaler to convert *types.Receipt to JSON.
		jsonOutput, err := receipt.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCallOutputMarshal, err.Error())
		}

		var receiptMap map[string]interface{}
		if err := json.Unmarshal(jsonOutput, &receiptMap); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCallOutputMarshal, err.Error())
		}

		// We must encode data over the wire so we can unmarshal correctly
		return &RosettaTypes.CallResponse{
			Result: receiptMap,
		}, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrCallMethodInvalid, request.Method)
}
