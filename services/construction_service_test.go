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

package services

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rsksmart/rosetta-rsk/configuration"
	rskMocks "github.com/rsksmart/rosetta-rsk/mocks/rsk"
	servicesMocks "github.com/rsksmart/rosetta-rsk/mocks/services"
	"github.com/rsksmart/rosetta-rsk/rsk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"math/big"
	"testing"

	"github.com/coinbase/rosetta-sdk-go/types"
)

func forceHexDecode(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("could not decode hex %s", s)
	}

	return b
}

func forceMarshalMap(t *testing.T, i interface{}) map[string]interface{} {
	m, err := marshalJSONMap(i)
	if err != nil {
		t.Fatalf("could not marshal map %s", types.PrintStruct(i))
	}

	return m
}

func TestConstructionService(t *testing.T) {
	transactionNonce, chainID, gasPrice, gasLimit, receiverAddress, senderAddress, value, data,
	rlpSignedTransactionParameters, rlpUnsignedTransactionParameters, compressedPublicKey := buildTestData(t)
	constructionServiceNetworkIdentifier := &types.NetworkIdentifier{
		Network:    rsk.TestnetNetwork,
		Blockchain: rsk.Blockchain,
	}
	cfg := &configuration.Configuration{
		Mode:    configuration.Online,
		Network: constructionServiceNetworkIdentifier,
		ChainID: rsk.TestnetChainID,
	}
	mockClient := &servicesMocks.Client{}
	mockTransactionEncoder := &rskMocks.TransactionEncoder{}
	service := NewConstructionAPIService(cfg, mockClient, mockTransactionEncoder)
	ctx := context.Background()

	// Tests each construction service in succession, feeding the outputs of one phase to the next (in general).
	testConstructionDerive(t, service, ctx, constructionServiceNetworkIdentifier, senderAddress, compressedPublicKey)
	ops, options := testPreProcess(t, service, ctx, constructionServiceNetworkIdentifier)
	metadata := testMetadata(t, gasPrice, transactionNonce, mockClient, ctx, senderAddress, service, constructionServiceNetworkIdentifier, options)
	encodedUnsignedTransactionBytes, unsignedRaw := testPayloads(t, mockTransactionEncoder,
		rlpUnsignedTransactionParameters, senderAddress, receiverAddress, value, data, transactionNonce,
		gasPrice, gasLimit, chainID, constructionServiceNetworkIdentifier, ops, metadata, service, ctx)
	parseOps, parseMetadata := testParseUnsigned(t, senderAddress, receiverAddress, service, ctx, constructionServiceNetworkIdentifier, unsignedRaw, metadata)
	signedRaw, signedRawBytes := testCombine(t, mockTransactionEncoder, rlpSignedTransactionParameters, service, ctx, constructionServiceNetworkIdentifier, unsignedRaw)
	testParseSigned(t, mockTransactionEncoder, signedRawBytes, rlpSignedTransactionParameters,
		encodedUnsignedTransactionBytes, service, ctx, constructionServiceNetworkIdentifier, signedRaw, parseOps,
		senderAddress, parseMetadata)
	transactionHash, transactionIdentifier := testHash(t, service, ctx, signedRaw)
	testSubmit(t, mockClient, ctx, transactionHash, service, signedRaw, transactionIdentifier)

	mockClient.AssertExpectations(t)
	mockTransactionEncoder.AssertExpectations(t)
}

func testParseUnsigned(t *testing.T, senderAddress string, receiverAddress string, service *ConstructionAPIService,
	ctx context.Context, constructionServiceNetworkIdentifier *types.NetworkIdentifier, unsignedRaw string,
	metadata *metadata) ([]*types.Operation, *parseMetadata) {
	parseOpsRaw := fmt.Sprintf(`[{"operation_identifier":{"index":0},"type":"CALL","account":{"address":"%s"},"amount":{"value":"-10000000000000000","currency":{"symbol":"RBTC","decimals":18}}},{"operation_identifier":{"index":1},"related_operations":[{"index":0}],"type":"CALL","account":{"address":"%s"},"amount":{"value":"10000000000000000","currency":{"symbol":"RBTC","decimals":18}}}]`,
		senderAddress, receiverAddress)
	var parseOps []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(parseOpsRaw), &parseOps))

	parseUnsignedResponse, customErr := service.ConstructionParse(ctx, &types.ConstructionParseRequest{
		NetworkIdentifier: constructionServiceNetworkIdentifier,
		Signed:            false,
		Transaction:       unsignedRaw,
	})
	assert.Nil(t, customErr)
	parseMetadata := &parseMetadata{
		Nonce:    metadata.Nonce,
		GasPrice: metadata.GasPrice,
		ChainID:  rsk.TestnetChainID,
	}
	assert.Equal(t, &types.ConstructionParseResponse{
		Operations:               parseOps,
		AccountIdentifierSigners: []*types.AccountIdentifier{},
		Metadata:                 forceMarshalMap(t, parseMetadata),
	}, parseUnsignedResponse)
	return parseOps, parseMetadata
}

func buildTestData(t *testing.T) (transactionNonce uint64, chainID *big.Int, gasPrice *big.Int, gasLimit *big.Int,
	receiverAddress string, senderAddress string, value *big.Int, data []byte,
	rlpSignedTransactionParameters *rsk.RlpTransactionParameters, rlpUnsignedTransactionParameters *rsk.RlpTransactionParameters,
	compressedPublicKey string) {
	transactionNonce = 1
	chainID = rsk.TestnetChainID
	gasPrice = big.NewInt(20000000000)
	gasLimit = big.NewInt(21000)
	receiverAddress = "0x6e88DD4C85eddE75aE906f6165cEC292794FC8D9"
	senderAddress = "0x0f265E792F8F937Ed4f505a040a1Bdb672f48e62"
	value = big.NewInt(10000000000000000)
	data = make([]byte, 0)
	ecdsaSignatureR, ok := new(big.Int).SetString("84007fdcb62e921eaedc37f7d6eab8c7290f29bf994a21642e1bf16631aef1c3", 16)
	if !ok {
		t.Fatal("failed to initialize ECDSA signature R value")
	}
	ecdsaSignatureS, ok := new(big.Int).SetString("3fe112900a4dcebbeda46537c301f39ce7e02e0d7a063ce0bd878dbb21c7f50d", 16)
	if !ok {
		t.Fatal("failed to initialize ECDSA signature R value")
	}
	ecdsaSignatureV, ok := new(big.Int).SetString("1b", 16)
	if !ok {
		t.Fatal("failed to initialize ECDSA signature R value")
	}
	rlpSignedTransactionParameters = buildRlpTransactionParameters(transactionNonce, gasLimit, receiverAddress, gasPrice,
		value, data, ecdsaSignatureV, ecdsaSignatureR, ecdsaSignatureS, chainID)

	rlpUnsignedTransactionParameters = buildRlpTransactionParameters(transactionNonce, gasLimit, receiverAddress, gasPrice,
		value, data, nil, nil, nil, chainID)

	compressedPublicKey = "0289bb7fd6d12364a42106347bfdddc63018246c5953fa0bf81d2403f2e25a0dda"
	return
}

func buildRlpTransactionParameters(transactionNonce uint64, gasLimit *big.Int, receiverAddress string, gasPrice *big.Int,
	value *big.Int, data []byte, ecdsaSignatureV *big.Int, ecdsaSignatureR *big.Int, ecdsaSignatureS *big.Int,
	chainID *big.Int) *rsk.RlpTransactionParameters {
	return &rsk.RlpTransactionParameters{
		Nonce:           transactionNonce,
		Gas:             gasLimit,
		ReceiverAddress: receiverAddress,
		GasPrice:        gasPrice,
		Value:           value,
		Data:            data,
		EcdsaSignatureV: ecdsaSignatureV,
		EcdsaSignatureR: ecdsaSignatureR,
		EcdsaSignatureS: ecdsaSignatureS,
		ChainID:         chainID,
	}
}

func testConstructionDerive(t *testing.T, service *ConstructionAPIService, ctx context.Context,
	constructionServiceNetworkIdentifier *types.NetworkIdentifier, senderAddress, compressedPublicKey string) {
	publicKey := &types.PublicKey{
		Bytes: forceHexDecode(
			t,
			compressedPublicKey,
		),
		CurveType: types.Secp256k1,
	}

	deriveResponse, customErr := service.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
		NetworkIdentifier: constructionServiceNetworkIdentifier,
		PublicKey:         publicKey,
	})

	assert.Nil(t, customErr)
	assert.Equal(t, &types.ConstructionDeriveResponse{
		AccountIdentifier: &types.AccountIdentifier{
			Address: senderAddress,
		},
	}, deriveResponse)
}

func testPreProcess(t *testing.T, service *ConstructionAPIService, ctx context.Context,
	constructionServiceNetworkIdentifier *types.NetworkIdentifier) ([]*types.Operation, options) {
	intent := `
[{
    "operation_identifier": {
        "index": 0
    },
    "type": "CALL",
    "account": {
        "address": "0x0f265E792F8F937Ed4f505a040a1Bdb672f48e62"
    },
    "amount": {
        "value": "-10000000000000000",
        "currency": {
            "symbol": "RBTC",
            "decimals": 18
        }
    }
}, {
    "operation_identifier": {
        "index": 1
    },
    "type": "CALL",
    "account": {
        "address": "0x6e88DD4C85eddE75aE906f6165cEC292794FC8D9"
    },
    "amount": {
        "value": "10000000000000000",
        "currency": {
            "symbol": "RBTC",
            "decimals": 18
        }
    }
}]
`
	var operations []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(intent), &operations))

	preprocessResponse, customErr := service.ConstructionPreprocess(
		ctx,
		&types.ConstructionPreprocessRequest{
			NetworkIdentifier: constructionServiceNetworkIdentifier,
			Operations:        operations,
		},
	)

	assert.Nil(t, customErr)
	optionsRaw := `{"from":"0x0f265E792F8F937Ed4f505a040a1Bdb672f48e62"}`
	var options options
	assert.NoError(t, json.Unmarshal([]byte(optionsRaw), &options))
	assert.Equal(t, &types.ConstructionPreprocessResponse{
		Options: forceMarshalMap(t, options),
	}, preprocessResponse)
	return operations, options
}

func testMetadata(t *testing.T, gasPrice *big.Int, transactionNonce uint64, mockClient *servicesMocks.Client,
	ctx context.Context, senderAddress string, service *ConstructionAPIService,
	constructionServiceNetworkIdentifier *types.NetworkIdentifier, options options) *metadata {
	metadata := &metadata{
		GasPrice: gasPrice,
		Nonce:    transactionNonce,
	}
	mockClient.On("SuggestGasPrice", ctx).Return(gasPrice, nil).Once()
	mockClient.On("PendingNonceAt", ctx, common.HexToAddress(senderAddress)).Return(transactionNonce, nil).Once()

	metadataResponse, customErr := service.ConstructionMetadata(ctx, &types.ConstructionMetadataRequest{
		NetworkIdentifier: constructionServiceNetworkIdentifier,
		Options:           forceMarshalMap(t, options),
	})

	assert.Nil(t, customErr)
	assert.Equal(t, &types.ConstructionMetadataResponse{
		Metadata: forceMarshalMap(t, metadata),
		SuggestedFee: []*types.Amount{
			{
				Value:    "420000000000000",
				Currency: rsk.DefaultCurrency,
			},
		},
	}, metadataResponse)
	return metadata
}

func testPayloads(t *testing.T, mockTransactionEncoder *rskMocks.TransactionEncoder, rlpUnsignedTransactionParameters *rsk.RlpTransactionParameters,
	senderAddress string, receiverAddress string, value *big.Int, data []byte, transactionNonce uint64, gasPrice *big.Int,
	gasLimit *big.Int, chainID *big.Int, constructionServiceNetworkIdentifier *types.NetworkIdentifier, ops []*types.Operation,
	metadata *metadata, service *ConstructionAPIService, ctx context.Context) ([]byte, string) {
	encodedUnsignedTransaction := "eb018504a817c800825208946e88dd4c85edde75ae906f6165cec292794fc8d9872386f26fc10000801f8080"
	encodedUnsignedTransactionBytes, err := hex.DecodeString(encodedUnsignedTransaction)
	if err != nil {
		t.Fatal("failed to decode unsigned transaction string")
	}
	mockTransactionEncoder.On("EncodeTransaction", rlpUnsignedTransactionParameters).Return(encodedUnsignedTransactionBytes, nil).Once()
	unsignedRaw := fmt.Sprintf(`{"from":"%s","to":"%s","value":"0x%x","input":"0x%x","nonce":"0x%x","gas_price":"0x%x","gas":"0x%x","chain_id":"0x%x"}`,
		senderAddress, receiverAddress, value, data, transactionNonce, gasPrice, gasLimit, chainID)
	constructionPayloadsRequest := &types.ConstructionPayloadsRequest{
		NetworkIdentifier: constructionServiceNetworkIdentifier,
		Operations:        ops,
		Metadata:          forceMarshalMap(t, metadata),
	}

	payloadsResponse, customErr := service.ConstructionPayloads(ctx, constructionPayloadsRequest)

	assert.Nil(t, customErr)
	payloadsRaw := fmt.Sprintf(`
[
  {
    "address": "%s",
    "hex_bytes": "eb018504a817c800825208946e88dd4c85edde75ae906f6165cec292794fc8d9872386f26fc10000801f8080",
    "account_identifier": {
      "address": "%s"
    },
    "signature_type": "ecdsa_recovery"
  }
]
`, senderAddress, senderAddress)
	var payloads []*types.SigningPayload
	assert.NoError(t, json.Unmarshal([]byte(payloadsRaw), &payloads))
	assert.Equal(t, &types.ConstructionPayloadsResponse{
		UnsignedTransaction: unsignedRaw,
		Payloads:            payloads,
	}, payloadsResponse)
	return encodedUnsignedTransactionBytes, unsignedRaw
}

func testCombine(t *testing.T, mockTransactionEncoder *rskMocks.TransactionEncoder,
	rlpSignedTransactionParameters *rsk.RlpTransactionParameters, service *ConstructionAPIService,
	ctx context.Context, constructionServiceNetworkIdentifier *types.NetworkIdentifier, unsignedRaw string) (string, []byte) {
	signaturesRaw := `
	[{
	"hex_bytes": "84007fdcb62e921eaedc37f7d6eab8c7290f29bf994a21642e1bf16631aef1c33fe112900a4dcebbeda46537c301f39ce7e02e0d7a063ce0bd878dbb21c7f50d1b",
	"signing_payload": {
	    "address": "0x0f265E792F8F937Ed4f505a040a1Bdb672f48e62",
	    "account_identifier": {
	        "address": "0x0f265E792F8F937Ed4f505a040a1Bdb672f48e62"
	    },
	    "signature_type": "ecdsa_recovery"
	},
	"public_key": {
	    "hex_bytes": "0289bb7fd6d12364a42106347bfdddc63018246c5953fa0bf81d2403f2e25a0dda",
	    "curve_type": "secp256k1"
	},
	"signature_type": "ecdsa_recovery"
	}]
	`
	var signatures []*types.Signature
	assert.NoError(t, json.Unmarshal([]byte(signaturesRaw), &signatures))
	signedRaw := "f86b018504a817c800825208946e88dd4c85edde75ae906f6165cec292794fc8d9872386f26fc100008061a084007fdcb62e921eaedc37f7d6eab8c7290f29bf994a21642e1bf16631aef1c3a03fe112900a4dcebbeda46537c301f39ce7e02e0d7a063ce0bd878dbb21c7f50d"
	signedRawBytes, err := hex.DecodeString(signedRaw)
	if err != nil {
		t.Fatal("failed to decode signed raw transaction string")
	}
	mockTransactionEncoder.On("EncodeTransaction", rlpSignedTransactionParameters).Return(signedRawBytes, nil).Once()

	combineResponse, customErr := service.ConstructionCombine(ctx, &types.ConstructionCombineRequest{
		NetworkIdentifier:   constructionServiceNetworkIdentifier,
		UnsignedTransaction: unsignedRaw,
		Signatures:          signatures,
	})
	assert.Nil(t, customErr)
	assert.Equal(t, &types.ConstructionCombineResponse{
		SignedTransaction: signedRaw,
	}, combineResponse)
	return signedRaw, signedRawBytes
}

func testParseSigned(t *testing.T, mockTransactionEncoder *rskMocks.TransactionEncoder, signedRawBytes []byte,
	rlpSignedTransactionParameters *rsk.RlpTransactionParameters, encodedUnsignedTransactionBytes []byte,
	service *ConstructionAPIService, ctx context.Context, constructionServiceNetworkIdentifier *types.NetworkIdentifier,
	signedRaw string, parseOps []*types.Operation, senderAddress string, parseMetadata *parseMetadata) {
	mockTransactionEncoder.On("DecodeTransaction", signedRawBytes).Return(rlpSignedTransactionParameters, nil).Once()
	mockTransactionEncoder.On("EncodeRawTransaction", rlpSignedTransactionParameters).Return(encodedUnsignedTransactionBytes, nil).Once()

	parseSignedResponse, customErr := service.ConstructionParse(ctx, &types.ConstructionParseRequest{
		NetworkIdentifier: constructionServiceNetworkIdentifier,
		Signed:            true,
		Transaction:       signedRaw,
	})
	assert.Nil(t, customErr)
	assert.Equal(t, &types.ConstructionParseResponse{
		Operations: parseOps,
		AccountIdentifierSigners: []*types.AccountIdentifier{
			{Address: senderAddress},
		},
		Metadata: forceMarshalMap(t, parseMetadata),
	}, parseSignedResponse)
}

func testHash(t *testing.T, service *ConstructionAPIService, ctx context.Context, signedRaw string) (string, *types.TransactionIdentifier) {
	transactionHash := "0x3f460547917c80bcd6478aa591034f0300193845503b077d94f4e7a222f0a6be"

	transactionIdentifier := &types.TransactionIdentifier{
		Hash: transactionHash,
	}
	hashResponse, customErr := service.ConstructionHash(ctx, &types.ConstructionHashRequest{
		NetworkIdentifier: networkServiceNetworkIdentifier,
		SignedTransaction: signedRaw,
	})
	assert.Nil(t, customErr)
	assert.Equal(t, &types.TransactionIdentifierResponse{
		TransactionIdentifier: transactionIdentifier,
	}, hashResponse)
	return transactionHash, transactionIdentifier
}

func testSubmit(t *testing.T, mockClient *servicesMocks.Client, ctx context.Context, transactionHash string,
	service *ConstructionAPIService, signedRaw string, transactionIdentifier *types.TransactionIdentifier) {
	mockClient.On("SendTransaction", ctx, mock.Anything).Return(transactionHash, nil).Once()
	submitResponse, customErr := service.ConstructionSubmit(ctx, &types.ConstructionSubmitRequest{
		NetworkIdentifier: networkServiceNetworkIdentifier,
		SignedTransaction: signedRaw,
	})
	assert.Nil(t, customErr)
	assert.Equal(t, &types.TransactionIdentifierResponse{
		TransactionIdentifier: transactionIdentifier,
	}, submitResponse)
}
