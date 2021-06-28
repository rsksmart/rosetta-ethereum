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
	"github.com/ethereum/go-ethereum/common"
	"github.com/rsksmart/rosetta-rsk/configuration"
	servicesMocks "github.com/rsksmart/rosetta-rsk/mocks/services"
	"github.com/rsksmart/rosetta-rsk/rsk"
	"github.com/stretchr/testify/assert"
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
	// TODO: change to mock encoder
	// mockTransactionEncoder := &rskMocks.TransactionEncoder{}
	mockTransactionEncoder := &rsk.RlpTransactionEncoder{}
	service := NewConstructionAPIService(cfg, mockClient, mockTransactionEncoder)
	ctx := context.Background()

	// Test Derive
	compressedPublicKey := "0289bb7fd6d12364a42106347bfdddc63018246c5953fa0bf81d2403f2e25a0dda"
	publicKey := &types.PublicKey{
		Bytes: forceHexDecode(
			t,
			compressedPublicKey,
		),
		CurveType: types.Secp256k1,
	}
	deriveResponse, err := service.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
		NetworkIdentifier: constructionServiceNetworkIdentifier,
		PublicKey:         publicKey,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionDeriveResponse{
		AccountIdentifier: &types.AccountIdentifier{
			Address: "0x0f265E792F8F937Ed4f505a040a1Bdb672f48e62",
		},
	}, deriveResponse)

	// Test Preprocess
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
	var ops []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(intent), &ops))
	preprocessResponse, err := service.ConstructionPreprocess(
		ctx,
		&types.ConstructionPreprocessRequest{
			NetworkIdentifier: constructionServiceNetworkIdentifier,
			Operations:        ops,
		},
	)
	assert.Nil(t, err)
	optionsRaw := `{"from":"0x0f265E792F8F937Ed4f505a040a1Bdb672f48e62"}`
	var options options
	assert.NoError(t, json.Unmarshal([]byte(optionsRaw), &options))
	assert.Equal(t, &types.ConstructionPreprocessResponse{
		Options: forceMarshalMap(t, options),
	}, preprocessResponse)

	// Test Metadata
	var transactionNonce uint64 = 1
	metadata := &metadata{
		GasPrice: big.NewInt(20000000000),
		Nonce:    transactionNonce,
	}

	mockClient.On(
		"SuggestGasPrice",
		ctx,
	).Return(
		big.NewInt(20000000000),
		nil,
	).Once()
	mockClient.On(
		"PendingNonceAt",
		ctx,
		common.HexToAddress("0x0f265E792F8F937Ed4f505a040a1Bdb672f48e62"),
	).Return(
		transactionNonce,
		nil,
	).Once()
	metadataResponse, err := service.ConstructionMetadata(ctx, &types.ConstructionMetadataRequest{
		NetworkIdentifier: constructionServiceNetworkIdentifier,
		Options:           forceMarshalMap(t, options),
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionMetadataResponse{
		Metadata: forceMarshalMap(t, metadata),
		SuggestedFee: []*types.Amount{
			{
				Value:    "420000000000000",
				Currency: rsk.DefaultCurrency,
			},
		},
	}, metadataResponse)

	// Test Payloads
	unsignedRaw := `{"from":"0x0f265E792F8F937Ed4f505a040a1Bdb672f48e62","to":"0x6e88DD4C85eddE75aE906f6165cEC292794FC8D9","value":"0x2386f26fc10000","input":"0x","nonce":"0x1","gas_price":"0x4a817c800","gas":"0x5208","chain_id":"0x1f"}`
	constructionPayloadsRequest := &types.ConstructionPayloadsRequest{
		NetworkIdentifier: constructionServiceNetworkIdentifier,
		Operations:        ops,
		Metadata:          forceMarshalMap(t, metadata),
	}
	payloadsResponse, err := service.ConstructionPayloads(ctx, constructionPayloadsRequest)
	assert.Nil(t, err)
	payloadsRaw := `
[
  {
    "address": "0x0f265E792F8F937Ed4f505a040a1Bdb672f48e62",
    "hex_bytes": "bf538d532ea3865d48c4e80d65d74e971baa4349ae6a5ffbd2d4356f34bd183b",
    "account_identifier": {
      "address": "0x0f265E792F8F937Ed4f505a040a1Bdb672f48e62"
    },
    "signature_type": "ecdsa_recovery"
  }
]
`
	var payloads []*types.SigningPayload
	assert.NoError(t, json.Unmarshal([]byte(payloadsRaw), &payloads))
	assert.Equal(t, &types.ConstructionPayloadsResponse{
		UnsignedTransaction: unsignedRaw,
		Payloads:            payloads,
	}, payloadsResponse)

	// Test Parse Unsigned
	parseOpsRaw := `[{"operation_identifier":{"index":0},"type":"CALL","account":{"address":"0x0f265E792F8F937Ed4f505a040a1Bdb672f48e62"},"amount":{"value":"-10000000000000000","currency":{"symbol":"RBTC","decimals":18}}},{"operation_identifier":{"index":1},"related_operations":[{"index":0}],"type":"CALL","account":{"address":"0x6e88DD4C85eddE75aE906f6165cEC292794FC8D9"},"amount":{"value":"10000000000000000","currency":{"symbol":"RBTC","decimals":18}}}]` // nolint
	var parseOps []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(parseOpsRaw), &parseOps))
	parseUnsignedResponse, err := service.ConstructionParse(ctx, &types.ConstructionParseRequest{
		NetworkIdentifier: constructionServiceNetworkIdentifier,
		Signed:            false,
		Transaction:       unsignedRaw,
	})
	assert.Nil(t, err)
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

	// Test Combine
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
	// TODO: mockear salida de transaction encoder
	signedRaw := "0xf86b018504a817c800825208946e88dd4c85edde75ae906f6165cec292794fc8d9872386f26fc10000801ba084007fdcb62e921eaedc37f7d6eab8c7290f29bf994a21642e1bf16631aef1c3a03fe112900a4dcebbeda46537c301f39ce7e02e0d7a063ce0bd878dbb21c7f50d"

	combineResponse, err := service.ConstructionCombine(ctx, &types.ConstructionCombineRequest{
		NetworkIdentifier:   constructionServiceNetworkIdentifier,
		UnsignedTransaction: unsignedRaw,
		Signatures:          signatures,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionCombineResponse{
		SignedTransaction: signedRaw,
	}, combineResponse)

	// Test Parse Signed

	//parseSignedResponse, err := service.ConstructionParse(ctx, &types.ConstructionParseRequest{
	//	NetworkIdentifier: constructionServiceNetworkIdentifier,
	//	Signed:            true,
	//	Transaction:       signedRaw,
	//})
	//assert.Nil(t, err)
	//// rsk signer: 0xc6d824659A0F21754939F2947D4BEe343e8e8Dd4
	//// eip155 signer: 0xc6d824659A0F21754939F2947D4BEe343e8e8Dd4
	//// TODO: el problema no está en el parseo, sino en el firmado
	//DELETETHIS := &types.ConstructionParseResponse{
	//	Operations: parseOps,
	//	AccountIdentifierSigners: []*types.AccountIdentifier{
	//		{Address: "0x0f265E792F8F937Ed4f505a040a1Bdb672f48e62"},
	//	},
	//	Metadata: forceMarshalMap(t, parseMetadata),
	//}
	//bla := parseSignedResponse.AccountIdentifierSigners[0].Address
	//fmt.Printf("wanted: %s, got: %s\n", "0x0f265E792F8F937Ed4f505a040a1Bdb672f48e62", bla)
	//assert.Equal(t, DELETETHIS, parseSignedResponse)

	//// Test Hash
	//transactionIdentifier := &types.TransactionIdentifier{
	//	Hash: "0x945153c18fedea059bac8c393714399611683212a5e419eae6c66e210cc6ece2",
	//}
	////TODO: el hash sirve para ver que estas formateando bien el objeto
	//hashResponse, err := service.ConstructionHash(ctx, &types.ConstructionHashRequest{
	//	NetworkIdentifier: networkServiceNetworkIdentifier,
	//	SignedTransaction: signedRaw,
	//})
	//assert.Nil(t, err)
	//assert.Equal(t, &types.TransactionIdentifierResponse{
	//	TransactionIdentifier: transactionIdentifier,
	//}, hashResponse)
	//
	//// Test Submit
	//mockClient.On(
	//	"SendTransaction",
	//	ctx,
	//	mock.Anything, // can't test ethTx here because it contains "time"
	//).Return(
	//	nil,
	//)
	//submitResponse, err := service.ConstructionSubmit(ctx, &types.ConstructionSubmitRequest{
	//	NetworkIdentifier: networkServiceNetworkIdentifier,
	//	SignedTransaction: signedRaw,
	//})
	//assert.Nil(t, err)
	//assert.Equal(t, &types.TransactionIdentifierResponse{
	//	TransactionIdentifier: transactionIdentifier,
	//}, submitResponse)
	//
	//mockClient.AssertExpectations(t)
}
