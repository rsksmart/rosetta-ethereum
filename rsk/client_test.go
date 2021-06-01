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
	"io/ioutil"
	"math/big"
	"reflect"
	"strings"
	"testing"

	mocks "github.com/rsksmart/rosetta-rsk/mocks/ethereum"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/sync/semaphore"
)

var (
	unsupportedCurrency = &RosettaTypes.Currency{
		Symbol:   "UNSUPPORTED",
		Decimals: 18,
	}
	testError = errors.New("test error")
)

func TestStatus_NotReady(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c:              mockJSONRPC,
		traceSemaphore: semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"latest",
		false,
	).Return(
		nil,
	).Once()

	block, timestamp, syncStatus, peers, err := c.Status(ctx)
	assert.Nil(t, block)
	assert.Equal(t, int64(-1), timestamp)
	assert.Nil(t, syncStatus)
	assert.Nil(t, peers)
	assert.True(t, errors.Is(err, ethereum.NotFound))

	mockJSONRPC.AssertExpectations(t)
}

func TestStatus_NotSyncing(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c:              mockJSONRPC,
		traceSemaphore: semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"latest",
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			header := args.Get(1).(**types.Header)
			file, err := ioutil.ReadFile("testdata/basic_header.json")
			assert.NoError(t, err)

			*header = new(types.Header)

			assert.NoError(t, (*header).UnmarshalJSON(file))
		},
	).Once()

	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_syncing",
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			status := args.Get(1).(*json.RawMessage)

			*status = json.RawMessage("false")
		},
	).Once()

	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"admin_peers",
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			info := args.Get(1).(*[]*p2p.PeerInfo)

			file, err := ioutil.ReadFile("testdata/peers.json")
			assert.NoError(t, err)

			assert.NoError(t, json.Unmarshal(file, info))
		},
	).Once()

	block, timestamp, syncStatus, peers, err := c.Status(ctx)
	assert.Equal(t, &RosettaTypes.BlockIdentifier{
		Hash:  "0x48269a339ce1489cff6bab70eff432289c4f490b81dbd00ff1f81c68de06b842",
		Index: 8916656,
	}, block)
	assert.Equal(t, int64(1603225195000), timestamp)
	assert.Nil(t, syncStatus)
	assert.Equal(t, []*RosettaTypes.Peer{
		{
			PeerID: "16dedaa93519f9ba41a50d77876aae4bfcddfa7cecf232b9abe3ab5bf0b871f3",
			Metadata: map[string]interface{}{
				"caps": []string{
					"eth/63",
					"eth/64",
					"eth/65",
				},
				"enode": "enode://5654cc39fd278c994c451434dfa7b1a44977c52018a87e911368b54daf795955d5a2dc2ece98be5a7e8d0eb245c8ef573c92e04e8b15363f9c713a8127fe7c7b@35.183.116.112:57510", // nolint
				"enr":   "",
				"name":  "Geth/v1.9.22-stable-c71a7e26/linux-amd64/go1.15",
				"protocols": map[string]interface{}{
					"eth": map[string]interface{}{
						"difficulty": float64(31779242235308530),
						"head":       "0x4a01c35e3e2627bf5a735bc9c7f336cb1e6450f93955473008ff64cf01feeef8",
						"version":    float64(65),
					},
				},
			},
		},
		{
			PeerID: "1b75a634fbc9198d73413a0ced02837707d1fd09e4e90b8b90a0abac57113299",
			Metadata: map[string]interface{}{
				"caps": []string{
					"eth/63",
					"eth/64",
					"eth/65",
				},
				"enode": "enode://bead1278155bfabdd51f04a6e896356da2f5687aa1f550bebc540828579522b87e22c67edf90efa651582e40c8c8037eb0f998208cab4a69b52c5e3387671b59@174.129.122.13:30303",                                                    // nolint
				"enr":   "enr:-Je4QICGSLfIHa7vX3bdWnKqWIS7YwmLUP6JVqU5nBhxPpH_X_Uz1pZwVS8a48uESHay1nvz9FtxLYFftpMr3wvFZJ4Qg2V0aMfGhGcn75CAgmlkgnY0gmlwhK6Beg2Jc2VjcDI1NmsxoQO-rRJ4FVv6vdUfBKboljVtovVoeqH1UL68VAgoV5UiuIN0Y3CCdl-DdWRwgnZf", // nolint
				"name":  "Geth/v1.9.15-omnibus-75eb5240/linux-amd64/go1.14.4",
				"protocols": map[string]interface{}{
					"eth": map[string]interface{}{
						"difficulty": float64(31779248439556308),
						"head":       "0x562415e43630bb6d79176ea2fa35ff2a54cee276b678b755831886b1029911bd",
						"version":    float64(65),
					},
				},
			},
		},
	}, peers)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
}

func TestStatus_Syncing(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c:              mockJSONRPC,
		traceSemaphore: semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"latest",
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			header := args.Get(1).(**types.Header)
			file, err := ioutil.ReadFile("testdata/basic_header.json")
			assert.NoError(t, err)

			*header = new(types.Header)

			assert.NoError(t, (*header).UnmarshalJSON(file))
		},
	).Once()

	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_syncing",
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			progress := args.Get(1).(*json.RawMessage)
			file, err := ioutil.ReadFile("testdata/syncing_info.json")
			assert.NoError(t, err)

			*progress = json.RawMessage(file)
		},
	).Once()

	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"admin_peers",
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			info := args.Get(1).(*[]*p2p.PeerInfo)

			file, err := ioutil.ReadFile("testdata/peers.json")
			assert.NoError(t, err)

			assert.NoError(t, json.Unmarshal(file, info))
		},
	).Once()

	block, timestamp, syncStatus, peers, err := c.Status(ctx)
	assert.Equal(t, &RosettaTypes.BlockIdentifier{
		Hash:  "0x48269a339ce1489cff6bab70eff432289c4f490b81dbd00ff1f81c68de06b842",
		Index: 8916656,
	}, block)
	assert.Equal(t, int64(1603225195000), timestamp)
	assert.Equal(t, &RosettaTypes.SyncStatus{
		CurrentIndex: RosettaTypes.Int64(25),
		TargetIndex:  RosettaTypes.Int64(8916760),
	}, syncStatus)
	assert.Equal(t, []*RosettaTypes.Peer{
		{
			PeerID: "16dedaa93519f9ba41a50d77876aae4bfcddfa7cecf232b9abe3ab5bf0b871f3",
			Metadata: map[string]interface{}{
				"caps": []string{
					"eth/63",
					"eth/64",
					"eth/65",
				},
				"enode": "enode://5654cc39fd278c994c451434dfa7b1a44977c52018a87e911368b54daf795955d5a2dc2ece98be5a7e8d0eb245c8ef573c92e04e8b15363f9c713a8127fe7c7b@35.183.116.112:57510", // nolint
				"enr":   "",
				"name":  "Geth/v1.9.22-stable-c71a7e26/linux-amd64/go1.15",
				"protocols": map[string]interface{}{
					"eth": map[string]interface{}{
						"difficulty": float64(31779242235308530),
						"head":       "0x4a01c35e3e2627bf5a735bc9c7f336cb1e6450f93955473008ff64cf01feeef8",
						"version":    float64(65),
					},
				},
			},
		},
		{
			PeerID: "1b75a634fbc9198d73413a0ced02837707d1fd09e4e90b8b90a0abac57113299",
			Metadata: map[string]interface{}{
				"caps": []string{
					"eth/63",
					"eth/64",
					"eth/65",
				},
				"enode": "enode://bead1278155bfabdd51f04a6e896356da2f5687aa1f550bebc540828579522b87e22c67edf90efa651582e40c8c8037eb0f998208cab4a69b52c5e3387671b59@174.129.122.13:30303",                                                    // nolint
				"enr":   "enr:-Je4QICGSLfIHa7vX3bdWnKqWIS7YwmLUP6JVqU5nBhxPpH_X_Uz1pZwVS8a48uESHay1nvz9FtxLYFftpMr3wvFZJ4Qg2V0aMfGhGcn75CAgmlkgnY0gmlwhK6Beg2Jc2VjcDI1NmsxoQO-rRJ4FVv6vdUfBKboljVtovVoeqH1UL68VAgoV5UiuIN0Y3CCdl-DdWRwgnZf", // nolint
				"name":  "Geth/v1.9.15-omnibus-75eb5240/linux-amd64/go1.14.4",
				"protocols": map[string]interface{}{
					"eth": map[string]interface{}{
						"difficulty": float64(31779248439556308),
						"head":       "0x562415e43630bb6d79176ea2fa35ff2a54cee276b678b755831886b1029911bd",
						"version":    float64(65),
					},
				},
			},
		},
	}, peers)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
}

func TestBalance_ReturnsErrorWhenCurrencyDecimalsAreIncorrect(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c: mockJSONRPC,
	}
	ctx := context.Background()
	address := "0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d"
	currencySymbol := DefaultCurrency.Symbol
	expectedErrorMessage := fmt.Sprintf("currency '%s' uses 18 decimals: error validating request currencies", currencySymbol)
	invalidDecimalAmountForCurrency := DefaultCurrency.Decimals + 1
	response, err := c.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: address,
		},
		nil,
		[]*RosettaTypes.Currency {
			{
				Symbol:   currencySymbol,
				Decimals: invalidDecimalAmountForCurrency,
			},
		},
	)

	assert.NotNil(t, err)
	assert.Equal(t, expectedErrorMessage, err.Error())
	assert.Nil(t, response)
}

func TestBalance_ReturnsAllCurrencyBalancesWhenNoCurrencyOrBlockIdentifierIsPassed(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c: mockJSONRPC,
	}
	ctx := context.Background()
	blockHexNumber := "0x2af0"
	address := "0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d"
	expectedResponse := &RosettaTypes.AccountBalanceResponse{
		BlockIdentifier: &RosettaTypes.BlockIdentifier{
			Index: 10992,
			Hash:  "0x67a12211d26c56a4439b2175b67fb20ad90c2800d1b3d338c8d733ebeb648ac7",
		},
		Balances: []*RosettaTypes.Amount{
			{
				Value:    "0",
				Currency: DOCCurrency,
			},
			{
				Value:    "0",
				Currency: RIFCurrency,
			},
			{
				Value:    "0",
				Currency: RDOCCurrency,
			},
			{
				Value:    "59760731096204670",
				Currency: DefaultCurrency,
			},
		},
	}
	mockEthGetBlockLatestBlockNumber(t, mockJSONRPC, ctx)
	mockSuccessfulEthGetBalanceResponse(t, mockJSONRPC, ctx, address, blockHexNumber)
	for tokenSymbol := range AddressByTokenSymbol {
		mockEmptyEthCallResponse(t, mockJSONRPC, ctx, strings.Replace(address, "0x", "", -1), AddressByTokenSymbol[tokenSymbol])
	}

	response, err := c.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: address,
		},
		nil,
		nil,
	)

	assertAccountBalanceResponsesAreEqual(t, expectedResponse, response)
	assert.Nil(t, err)
}

func assertAccountBalanceResponsesAreEqual(t *testing.T, expectedResponse *RosettaTypes.AccountBalanceResponse,
	response *RosettaTypes.AccountBalanceResponse) {
	assert.Equal(t, expectedResponse.BlockIdentifier, response.BlockIdentifier)
	assert.Equal(t, expectedResponse.Metadata, response.Metadata)
	assert.Equal(t, len(expectedResponse.Balances), len(response.Balances))
	for _, expectedBalance := range expectedResponse.Balances {
		foundBalance := false
		for _, balance := range response.Balances {
			if reflect.DeepEqual(expectedBalance, balance) {
				foundBalance = true
				break
			}
		}
		assert.True(t, foundBalance)
	}
}

func mockEthGetBlockLatestBlockNumber(t *testing.T, mockJSONRPC *mocks.JSONRPC, ctx context.Context) *mock.Call {
	return mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		EthGetBlockByNumberMethod,
		LatestBlockNumber,
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)
			file, err := ioutil.ReadFile("testdata/block_10992.json")
			assert.NoError(t, err)
			*r = file
		},
	).Once()
}

func mockEmptyEthCallResponse(t *testing.T, mockJSONRPC *mocks.JSONRPC, ctx context.Context, address string,
	contractAddress string) *mock.Call {
	return mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		EthCallMethod,
		map[string]string{
			"data": fmt.Sprintf("0x70a08231000000000000000000000000%s", strings.Replace(address, "0x", "", -1)),
			"to":   contractAddress,
		},
		mock.Anything,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*string)
			*r = "0x"
		},
	).Once()
}

func mockEthGetLatestBlockReturnsError(mockJSONRPC *mocks.JSONRPC, ctx context.Context) *mock.Call {
	return mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		EthGetBlockByNumberMethod,
		LatestBlockNumber,
		true,
	).Return(
		testError,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)
			*r = nil
		},
	).Once()
}

func mockEthGetBlock10992ByHash(t *testing.T, mockJSONRPC *mocks.JSONRPC, ctx context.Context) *mock.Call {
	return mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		EthGetBlockByHashMethod,
		"0x67a12211d26c56a4439b2175b67fb20ad90c2800d1b3d338c8d733ebeb648ac7",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)
			file, err := ioutil.ReadFile("testdata/block_10992.json")
			assert.NoError(t, err)
			*r = file
		},
	).Once()
}

func mockEthGetBlock10992ByNumber(t *testing.T, mockJSONRPC *mocks.JSONRPC, ctx context.Context) *mock.Call {
	return mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		EthGetBlockByNumberMethod,
		"0x2af0",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)
			file, err := ioutil.ReadFile("testdata/block_10992.json")
			assert.NoError(t, err)
			*r = file
		},
	).Once()
}

func mockSuccessfulEthGetBalanceResponse(t *testing.T, mockJSONRPC *mocks.JSONRPC, ctx context.Context, address string,
	blockHexNumber string) *mock.Call {
	return mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		EthGetBalanceMethod,
		address,
		blockHexNumber,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)
			file, err := ioutil.ReadFile("testdata/rsk_balance_0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d.json")
			assert.NoError(t, err)
			*r = file
		},
	).Once()
}

func mockErrorEthGetBalanceResponse(mockJSONRPC *mocks.JSONRPC, ctx context.Context, address string, blockHexNumber string) *mock.Call {
	return mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		EthGetBalanceMethod,
		address,
		blockHexNumber,
	).Return(
		testError,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)
			*r = nil
		},
	).Once()
}

func TestBalance_ReturnsAllCurrenciesBalanceWhenBlockNumberIsPassedButNoCurrencyIsPassed(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c: mockJSONRPC,
	}
	ctx := context.Background()
	blockHexNumber := "0x2af0"
	address := "0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d"
	blockNumber := int64(10992)
	blockHash := "0x67a12211d26c56a4439b2175b67fb20ad90c2800d1b3d338c8d733ebeb648ac7"
	expectedResponse := &RosettaTypes.AccountBalanceResponse{
		BlockIdentifier: &RosettaTypes.BlockIdentifier{
			Index: blockNumber,
			Hash:  blockHash,
		},
		Balances: []*RosettaTypes.Amount{
			{
				Value:    "0",
				Currency: DOCCurrency,
			},
			{
				Value:    "0",
				Currency: RIFCurrency,
			},
			{
				Value:    "0",
				Currency: RDOCCurrency,
			},
			{
				Value:    "59760731096204670",
				Currency: DefaultCurrency,
			},
		},
	}

	mockEthGetBlock10992ByNumber(t, mockJSONRPC, ctx)
	mockSuccessfulEthGetBalanceResponse(t, mockJSONRPC, ctx, address, blockHexNumber)
	for tokenSymbol := range AddressByTokenSymbol {
		mockEmptyEthCallResponse(t, mockJSONRPC, ctx, strings.Replace(address, "0x", "", -1), AddressByTokenSymbol[tokenSymbol])
	}

	response, err := c.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: address,
		},
		&RosettaTypes.PartialBlockIdentifier{
			Index: &blockNumber,
		},
		nil,
	)

	assert.Nil(t, err)
	assertAccountBalanceResponsesAreEqual(t, expectedResponse, response)
}

func TestBalance_ReturnsAllCurrenciesBalanceWhenBlockHashIsPassedButNoCurrencyIsPassed(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c: mockJSONRPC,
	}
	ctx := context.Background()
	blockHexNumber := "0x2af0"
	address := "0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d"
	blockNumber := int64(10992)
	blockHash := "0x67a12211d26c56a4439b2175b67fb20ad90c2800d1b3d338c8d733ebeb648ac7"
	expectedResponse := &RosettaTypes.AccountBalanceResponse{
		BlockIdentifier: &RosettaTypes.BlockIdentifier{
			Index: blockNumber,
			Hash:  blockHash,
		},
		Balances: []*RosettaTypes.Amount{
			{
				Value:    "0",
				Currency: DOCCurrency,
			},
			{
				Value:    "0",
				Currency: RIFCurrency,
			},
			{
				Value:    "0",
				Currency: RDOCCurrency,
			},
			{
				Value:    "59760731096204670",
				Currency: DefaultCurrency,
			},
		},
	}
	mockEthGetBlock10992ByHash(t, mockJSONRPC, ctx)
	mockSuccessfulEthGetBalanceResponse(t, mockJSONRPC, ctx, address, blockHexNumber)
	for tokenSymbol := range AddressByTokenSymbol {
		mockEmptyEthCallResponse(t, mockJSONRPC, ctx, strings.Replace(address, "0x", "", -1), AddressByTokenSymbol[tokenSymbol])
	}

	resp, err := c.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: address,
		},
		&RosettaTypes.PartialBlockIdentifier{
			Hash: &blockHash,
		},
		nil,
	)

	assert.Nil(t, err)
	assertAccountBalanceResponsesAreEqual(t, expectedResponse, resp)
}

func TestBalance_ReturnsAllCurrenciesBalanceWhenFullBlockIdentifierIsPassedButNoCurrencyIsPassed(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c: mockJSONRPC,
	}
	ctx := context.Background()
	blockHexNumber := "0x2af0"
	address := "0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d"
	blockNumber := int64(10992)
	blockHash := "0x67a12211d26c56a4439b2175b67fb20ad90c2800d1b3d338c8d733ebeb648ac7"
	expectedResponse := &RosettaTypes.AccountBalanceResponse{
		BlockIdentifier: &RosettaTypes.BlockIdentifier{
			Index: blockNumber,
			Hash:  blockHash,
		},
		Balances: []*RosettaTypes.Amount{
			{
				Value:    "0",
				Currency: DOCCurrency,
			},
			{
				Value:    "0",
				Currency: RIFCurrency,
			},
			{
				Value:    "0",
				Currency: RDOCCurrency,
			},
			{
				Value:    "59760731096204670",
				Currency: DefaultCurrency,
			},
		},
	}
	mockEthGetBlock10992ByHash(t, mockJSONRPC, ctx)
	mockSuccessfulEthGetBalanceResponse(t, mockJSONRPC, ctx, address, blockHexNumber)
	for tokenSymbol := range AddressByTokenSymbol {
		mockEmptyEthCallResponse(t, mockJSONRPC, ctx, strings.Replace(address, "0x", "", -1), AddressByTokenSymbol[tokenSymbol])
	}

	resp, err := c.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: address,
		},
		&RosettaTypes.PartialBlockIdentifier{
			Index: &blockNumber,
			Hash:  &blockHash,
		},
		nil,
	)

	assert.Nil(t, err)
	assertAccountBalanceResponsesAreEqual(t, expectedResponse, resp)
}

func TestBalance_ReturnsErrorWhenNotSupportedCurrenciesAreRequested(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c: mockJSONRPC,
	}
	ctx := context.Background()
	address := "0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d"
	expectedErrorMessage := "currency 'UNSUPPORTED' is not supported: error validating request currencies"
	mockEthGetBlockLatestBlockNumber(t, mockJSONRPC, ctx)

	resp, err := c.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: address,
		},
		nil,
		[]*RosettaTypes.Currency{
			unsupportedCurrency,
		},
	)

	assert.NotNil(t, err)
	assert.Equal(t, expectedErrorMessage, err.Error())
	assert.Nil(t, resp)
}

func TestBalance_ReturnsErrorWhenBlockObtentionFails(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c: mockJSONRPC,
	}
	ctx := context.Background()
	address := "0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d"
	expectedErrorMessage := "test error: block fetch failed: failed to get block by number (latest): failed to obtain block identifier"
	mockEthGetLatestBlockReturnsError(mockJSONRPC, ctx)

	resp, err := c.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: address,
		},
		nil,
		[]*RosettaTypes.Currency{
			DefaultCurrency,
		},
	)

	assert.NotNil(t, err)
	assert.Equal(t, expectedErrorMessage, err.Error())
	assert.Nil(t, resp)
}

func TestBalance_ReturnsErrorWhenAccountBalanceObtentionFails(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c: mockJSONRPC,
	}
	ctx := context.Background()
	blockHexNumber := "0x2af0"
	address := "0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d"
	blockHash := "0x67a12211d26c56a4439b2175b67fb20ad90c2800d1b3d338c8d733ebeb648ac7"
	expectedErrorMessage := "test error: failed to get balance for address 0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d and block 0x2af0: failed to get account balance: failed to get account balance"
	mockEthGetBlock10992ByHash(t, mockJSONRPC, ctx)
	mockErrorEthGetBalanceResponse(mockJSONRPC, ctx, address, blockHexNumber)

	resp, err := c.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: address,
		},
		&RosettaTypes.PartialBlockIdentifier{
			Hash: &blockHash,
		},
		[]*RosettaTypes.Currency{DefaultCurrency},
	)

	assert.NotNil(t, err)
	assert.Equal(t, expectedErrorMessage, err.Error())
	assert.Nil(t, resp)
}

func TestCall(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}

	c := &Client{
		c:              mockJSONRPC,
		traceSemaphore: semaphore.NewWeighted(100),
	}

	ctx := context.Background()

	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getTransactionReceipt",
		common.HexToHash("0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d"),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(**types.Receipt)

			file, err := ioutil.ReadFile(
				"testdata/call_0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d.json",
			)
			assert.NoError(t, err)

			*r = new(types.Receipt)

			assert.NoError(t, (*r).UnmarshalJSON(file))
		},
	).Once()
	resp, err := c.Call(
		ctx,
		&RosettaTypes.CallRequest{
			Method: "eth_getTransactionReceipt",
			Parameters: map[string]interface{}{
				"tx_hash": "0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d",
			},
		},
	)
	assert.Equal(t, &RosettaTypes.CallResponse{
		Result: map[string]interface{}{
			"blockHash":         "0x928b4d7d1ab8fcb2f62ffa7bba7a1a52251a1145ffc0faec3e009535ba4a2669",
			"blockNumber":       "0x7edcff",
			"contractAddress":   "0x0000000000000000000000000000000000000000",
			"cumulativeGasUsed": "0x744f1b",
			"gasUsed":           "0x5208",
			"logs":              []interface{}{},
			"logsBloom":         "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", // nolint
			"root":              "0x",
			"status":            "0x1",
			"transactionHash":   "0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d",
			"transactionIndex":  "0x21",
		},
		Idempotent: false,
	}, resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
}

func TestCall_InvalidArgs(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}

	c := &Client{
		c:              mockJSONRPC,
		traceSemaphore: semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	resp, err := c.Call(
		ctx,
		&RosettaTypes.CallRequest{
			Method: "eth_getTransactionReceipt",
		},
	)
	assert.Nil(t, resp)
	assert.True(t, errors.Is(err, ErrCallParametersInvalid))

	mockJSONRPC.AssertExpectations(t)
}

func TestCall_InvalidMethod(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}

	c := &Client{
		c:              mockJSONRPC,
		traceSemaphore: semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	resp, err := c.Call(
		ctx,
		&RosettaTypes.CallRequest{
			Method: "blah",
		},
	)
	assert.Nil(t, resp)
	assert.True(t, errors.Is(err, ErrCallMethodInvalid))

	mockJSONRPC.AssertExpectations(t)
}

func TestBlock_Current(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}

	c := &Client{
		c:              mockJSONRPC,
		chainID:        TestnetChainID,
		traceSemaphore: semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"latest",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := ioutil.ReadFile("testdata/block_10992.json")
			assert.NoError(t, err)

			*r = json.RawMessage(file)
		},
	).Once()

	correctRaw, err := ioutil.ReadFile("testdata/block_response_10992.json")
	assert.NoError(t, err)
	var correct *RosettaTypes.BlockResponse
	assert.NoError(t, json.Unmarshal(correctRaw, &correct))

	resp, err := c.Block(
		ctx,
		nil,
	)
	assert.Equal(t, correct.Block, resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
}

func TestBlock_Hash(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c:              mockJSONRPC,
		chainID:        TestnetChainID,
		traceSemaphore: semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByHash",
		"0xba9ded5ca1ec9adb9451bf062c9de309d9552fa0f0254a7b982d3daf7ae436ae",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := ioutil.ReadFile("testdata/block_10992.json")
			assert.NoError(t, err)

			*r = json.RawMessage(file)
		},
	).Once()

	correctRaw, err := ioutil.ReadFile("testdata/block_response_10992.json")
	assert.NoError(t, err)
	var correct *RosettaTypes.BlockResponse
	assert.NoError(t, json.Unmarshal(correctRaw, &correct))

	resp, err := c.Block(
		ctx,
		&RosettaTypes.PartialBlockIdentifier{
			Hash: RosettaTypes.String(
				"0xba9ded5ca1ec9adb9451bf062c9de309d9552fa0f0254a7b982d3daf7ae436ae",
			),
		},
	)
	assert.Equal(t, correct.Block, resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
}

func TestBlock_Index(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c:              mockJSONRPC,
		chainID:        TestnetChainID,
		traceSemaphore: semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"0x2af0",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := ioutil.ReadFile("testdata/block_10992.json")
			assert.NoError(t, err)

			*r = json.RawMessage(file)
		},
	).Once()

	correctRaw, err := ioutil.ReadFile("testdata/block_response_10992.json")
	assert.NoError(t, err)
	var correct *RosettaTypes.BlockResponse
	assert.NoError(t, json.Unmarshal(correctRaw, &correct))

	resp, err := c.Block(
		ctx,
		&RosettaTypes.PartialBlockIdentifier{
			Index: RosettaTypes.Int64(10992),
		},
	)
	assert.Equal(t, correct.Block, resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
}

func jsonifyBlock(b *RosettaTypes.Block) (*RosettaTypes.Block, error) {
	bytes, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}

	var bo RosettaTypes.Block
	if err := json.Unmarshal(bytes, &bo); err != nil {
		return nil, err
	}

	return &bo, nil
}

// Block with transactions
func TestBlock_10994(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c:              mockJSONRPC,
		chainID:        TestnetChainID,
		traceSemaphore: semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"0x2af2",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := ioutil.ReadFile("testdata/block_10994.json")
			assert.NoError(t, err)

			*r = json.RawMessage(file)
		},
	).Once()
	mockContractCallTransactionCode(t, mockJSONRPC, ctx)
	mockNormalTransactionCode(t, mockJSONRPC, ctx)

	correctRaw, err := ioutil.ReadFile("testdata/block_response_10994.json")
	assert.NoError(t, err)
	var correctResp *RosettaTypes.BlockResponse
	assert.NoError(t, json.Unmarshal(correctRaw, &correctResp))

	resp, err := c.Block(
		ctx,
		&RosettaTypes.PartialBlockIdentifier{
			Index: RosettaTypes.Int64(10994),
		},
	)
	assert.NoError(t, err)

	// Ensure types match
	jsonResp, err := jsonifyBlock(resp)
	assert.NoError(t, err)
	assert.Equal(t, correctResp.Block, jsonResp)

	mockJSONRPC.AssertExpectations(t)
}

func mockContractCallTransactionCode(t *testing.T, mockJSONRPC *mocks.JSONRPC, ctx context.Context) *mock.Call {
	return mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getCode",
		"0x70dad688e561ee0f357dac3d26c215be12af11a1",
		"0x2af2",
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)
			file, err := ioutil.ReadFile("testdata/tx_code_0x70dad68_10994.json")
			assert.NoError(t, err)
			*r = file
		},
	).Once()
}

func mockNormalTransactionCode(t *testing.T, mockJSONRPC *mocks.JSONRPC, ctx context.Context) *mock.Call {
	return mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getCode",
		"0x161a66173caf5dd328228329d48347ecef462b90",
		"0x2af2",
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)
			file, err := ioutil.ReadFile("testdata/tx_code_0x161a661_10994.json")
			assert.NoError(t, err)
			*r = file
		},
	).Once()
}

func TestPendingNonceAt(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c:              mockJSONRPC,
		traceSemaphore: semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getTransactionCount",
		common.HexToAddress("0xfFC614eE978630D7fB0C06758DeB580c152154d3"),
		"pending",
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*hexutil.Uint64)

			*r = hexutil.Uint64(10)
		},
	).Once()
	resp, err := c.PendingNonceAt(
		ctx,
		common.HexToAddress("0xfFC614eE978630D7fB0C06758DeB580c152154d3"),
	)
	assert.Equal(t, uint64(10), resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
}

func TestSuggestGasPrice(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c:              mockJSONRPC,
		traceSemaphore: semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_gasPrice",
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*hexutil.Big)

			*r = *(*hexutil.Big)(big.NewInt(100000))
		},
	).Once()
	resp, err := c.SuggestGasPrice(
		ctx,
	)
	assert.Equal(t, big.NewInt(100000), resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
}

func TestSendTransaction(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	c := &Client{
		c:              mockJSONRPC,
		traceSemaphore: semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_sendRawTransaction",
		"0xf86a80843b9aca00825208941ff502f9fe838cd772874cb67d0d96b93fd1d6d78725d4b6199a415d8029a01d110bf9fd468f7d00b3ce530832e99818835f45e9b08c66f8d9722264bb36c7a02711f47ec99f9ac585840daef41b7118b52ec72f02fcb30d874d36b10b668b59", // nolint
	).Return(
		nil,
	).Once()

	rawTx, err := ioutil.ReadFile("testdata/submitted_tx.json")
	assert.NoError(t, err)

	tx := new(types.Transaction)
	assert.NoError(t, tx.UnmarshalJSON(rawTx))

	assert.NoError(t, c.SendTransaction(
		ctx,
		tx,
	))

	mockJSONRPC.AssertExpectations(t)
}
