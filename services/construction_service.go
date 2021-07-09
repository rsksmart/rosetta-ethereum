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
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/rsksmart/rosetta-rsk/configuration"
	"github.com/rsksmart/rosetta-rsk/rsk"
	"math/big"
	"strconv"
	"strings"

	"github.com/coinbase/rosetta-sdk-go/parser"
	"github.com/coinbase/rosetta-sdk-go/types"
)

const (
	HexadecimalPrefix  = "0x"
	minimumEcdsaVValue = 27
)

// ConstructionAPIService implements the server.ConstructionAPIServicer interface.
type ConstructionAPIService struct {
	config             *configuration.Configuration
	client             Client
	transactionEncoder rsk.TransactionEncoder
}

// NewConstructionAPIService creates a new instance of a ConstructionAPIService.
func NewConstructionAPIService(
	cfg *configuration.Configuration,
	client Client,
	transactionEncoder rsk.TransactionEncoder,
) *ConstructionAPIService {
	return &ConstructionAPIService{
		config:             cfg,
		client:             client,
		transactionEncoder: transactionEncoder,
	}
}

// ConstructionDerive implements the /construction/derive endpoint.
func (s *ConstructionAPIService) ConstructionDerive(
	ctx context.Context,
	request *types.ConstructionDeriveRequest,
) (*types.ConstructionDeriveResponse, *types.Error) {
	pubkey, err := crypto.DecompressPubkey(request.PublicKey.Bytes)
	if err != nil {
		return nil, wrapErr(ErrUnableToDecompressPubkey, err)
	}

	addr := crypto.PubkeyToAddress(*pubkey)
	return &types.ConstructionDeriveResponse{
		AccountIdentifier: &types.AccountIdentifier{
			Address: addr.Hex(),
		},
	}, nil
}

// ConstructionPreprocess implements the /construction/preprocess
// endpoint.
func (s *ConstructionAPIService) ConstructionPreprocess(
	ctx context.Context,
	request *types.ConstructionPreprocessRequest,
) (*types.ConstructionPreprocessResponse, *types.Error) {
	descriptions := &parser.Descriptions{
		OperationDescriptions: []*parser.OperationDescription{
			{
				Type: rsk.CallOpType,
				Account: &parser.AccountDescription{
					Exists: true,
				},
				Amount: &parser.AmountDescription{
					Exists:   true,
					Sign:     parser.NegativeAmountSign,
					Currency: rsk.DefaultCurrency,
				},
			},
			{
				Type: rsk.CallOpType,
				Account: &parser.AccountDescription{
					Exists: true,
				},
				Amount: &parser.AmountDescription{
					Exists:   true,
					Sign:     parser.PositiveAmountSign,
					Currency: rsk.DefaultCurrency,
				},
			},
		},
		ErrUnmatched: true,
	}

	matches, err := parser.MatchOperations(descriptions, request.Operations)
	if err != nil {
		return nil, wrapErr(ErrUnclearIntent, err)
	}

	fromOp, _ := matches[0].First()
	fromAdd := fromOp.Account.Address
	toOp, _ := matches[1].First()
	toAdd := toOp.Account.Address

	// Ensure valid from address
	checkFrom, ok := rsk.ChecksumAddress(fromAdd)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", fromAdd))
	}

	// Ensure valid to address
	_, ok = rsk.ChecksumAddress(toAdd)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", toAdd))
	}

	preprocessOutput := &options{
		From: checkFrom,
	}

	marshaled, err := marshalJSONMap(preprocessOutput)
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	return &types.ConstructionPreprocessResponse{
		Options: marshaled,
	}, nil
}

// ConstructionMetadata implements the /construction/metadata endpoint.
func (s *ConstructionAPIService) ConstructionMetadata(
	ctx context.Context,
	request *types.ConstructionMetadataRequest,
) (*types.ConstructionMetadataResponse, *types.Error) {
	if s.config.Mode != configuration.Online {
		return nil, ErrUnavailableOffline
	}

	var input options
	if err := unmarshalJSONMap(request.Options, &input); err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	nonce, err := s.client.PendingNonceAt(ctx, common.HexToAddress(input.From))
	if err != nil {
		return nil, wrapErr(ErrRskj, err)
	}
	gasPrice, err := s.client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, wrapErr(ErrRskj, err)
	}

	metadata := &metadata{
		Nonce:    nonce,
		GasPrice: gasPrice,
	}

	metadataMap, err := marshalJSONMap(metadata)
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	// Find suggested gas usage
	suggestedFee := metadata.GasPrice.Int64() * rsk.TransferGasLimit

	return &types.ConstructionMetadataResponse{
		Metadata: metadataMap,
		SuggestedFee: []*types.Amount{
			{
				Value:    strconv.FormatInt(suggestedFee, 10),
				Currency: rsk.DefaultCurrency,
			},
		},
	}, nil
}

// ConstructionPayloads implements the /construction/payloads endpoint.
func (s *ConstructionAPIService) ConstructionPayloads(
	ctx context.Context,
	request *types.ConstructionPayloadsRequest,
) (*types.ConstructionPayloadsResponse, *types.Error) {
	descriptions := &parser.Descriptions{
		OperationDescriptions: []*parser.OperationDescription{
			{
				Type: rsk.CallOpType,
				Account: &parser.AccountDescription{
					Exists: true,
				},
				Amount: &parser.AmountDescription{
					Exists:   true,
					Sign:     parser.NegativeAmountSign,
					Currency: rsk.DefaultCurrency,
				},
			},
			{
				Type: rsk.CallOpType,
				Account: &parser.AccountDescription{
					Exists: true,
				},
				Amount: &parser.AmountDescription{
					Exists:   true,
					Sign:     parser.PositiveAmountSign,
					Currency: rsk.DefaultCurrency,
				},
			},
		},
		ErrUnmatched: true,
	}
	matches, err := parser.MatchOperations(descriptions, request.Operations)
	if err != nil {
		return nil, wrapErr(ErrUnclearIntent, err)
	}

	// Convert map to Metadata struct
	var metadata metadata
	if err := unmarshalJSONMap(request.Metadata, &metadata); err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	// Required Fields for constructing a real Ethereum transaction
	toOp, amount := matches[1].First()
	toAdd := toOp.Account.Address
	nonce := metadata.Nonce
	gasPrice := metadata.GasPrice
	chainID := s.config.ChainID
	transferGasLimit := uint64(rsk.TransferGasLimit)
	transferData := []byte{}

	// Additional Fields for constructing custom Ethereum tx struct
	fromOp, _ := matches[0].First()
	fromAdd := fromOp.Account.Address

	// Ensure valid from address
	checkFrom, ok := rsk.ChecksumAddress(fromAdd)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", fromAdd))
	}

	// Ensure valid to address
	checkTo, ok := rsk.ChecksumAddress(toAdd)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", toAdd))
	}

	tx := ethTypes.NewTransaction(
		nonce,
		common.HexToAddress(checkTo),
		amount,
		transferGasLimit,
		gasPrice,
		transferData,
	)

	unsignedTx := &transaction{
		From:     checkFrom,
		To:       checkTo,
		Value:    amount,
		Input:    tx.Data(),
		Nonce:    tx.Nonce(),
		GasPrice: gasPrice,
		GasLimit: tx.Gas(),
		ChainID:  chainID,
	}

	// Construct SigningPayload
	encodedTransaction, err := s.transactionEncoder.EncodeTransaction(&rsk.RlpTransactionParameters{
		Nonce:           unsignedTx.Nonce,
		Gas:             new(big.Int).SetUint64(unsignedTx.GasLimit),
		ReceiverAddress: unsignedTx.To,
		GasPrice:        unsignedTx.GasPrice,
		Value:           unsignedTx.Value,
		Data:            unsignedTx.Input,
		ChainID:         unsignedTx.ChainID,
	})
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, fmt.Errorf("%w: failed to encode transaction", err))
	}

	payload := &types.SigningPayload{
		AccountIdentifier: &types.AccountIdentifier{Address: checkFrom},
		Bytes:             encodedTransaction,
		SignatureType:     types.EcdsaRecovery,
	}

	unsignedTxJSON, err := json.Marshal(unsignedTx)
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	c := &types.ConstructionPayloadsResponse{
		UnsignedTransaction: string(unsignedTxJSON),
		Payloads:            []*types.SigningPayload{payload},
	}
	return c, nil
}

type RskSigner struct {
	ethTypes.FrontierSigner
}

func (rs *RskSigner) SignatureValues(tx *ethTypes.Transaction, sig []byte) (r, s, v *big.Int, err error) {
	if len(sig) != crypto.SignatureLength {
		return nil, nil, nil, fmt.Errorf("wrong size for signature: got %d, want %d", len(sig), crypto.SignatureLength)
	}
	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64]})
	return r, s, v, nil
}

// ConstructionCombine implements the /construction/combine
// endpoint.
func (s *ConstructionAPIService) ConstructionCombine(
	ctx context.Context,
	request *types.ConstructionCombineRequest,
) (*types.ConstructionCombineResponse, *types.Error) {
	var unsignedTx transaction
	if err := json.Unmarshal([]byte(request.UnsignedTransaction), &unsignedTx); err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	ethTransaction := ethTypes.NewTransaction(
		unsignedTx.Nonce,
		common.HexToAddress(unsignedTx.To),
		unsignedTx.Value,
		unsignedTx.GasLimit,
		unsignedTx.GasPrice,
		unsignedTx.Input,
	)

	signer := &RskSigner{}
	signedTx, err := ethTransaction.WithSignature(signer, request.Signatures[0].Bytes)
	if err != nil {
		return nil, wrapErr(ErrSignatureInvalid, err)
	}

	ecdsaR, ecdsaS, ecdsaV, _ := signer.SignatureValues(ethTransaction, request.Signatures[0].Bytes)
	nonce := signedTx.Nonce()
	gas := new(big.Int).SetUint64(signedTx.Gas())
	gasPrice := signedTx.GasPrice()
	value := signedTx.Value()
	data := signedTx.Data()

	rlpTransactionParameters := &rsk.RlpTransactionParameters{
		Nonce: nonce, Gas: gas, ReceiverAddress: unsignedTx.To, GasPrice: gasPrice, Value: value, Data: data,
		EcdsaSignatureV: ecdsaV, EcdsaSignatureR: ecdsaR, EcdsaSignatureS: ecdsaS, ChainID: unsignedTx.ChainID,
	}
	encodedTxBytes, err := s.transactionEncoder.EncodeTransaction(rlpTransactionParameters)
	encodedTxHex := hex.EncodeToString(encodedTxBytes)
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}
	return &types.ConstructionCombineResponse{
		SignedTransaction: encodedTxHex,
	}, nil
}

// ConstructionHash implements the /construction/hash endpoint.
func (s *ConstructionAPIService) ConstructionHash(
	ctx context.Context,
	request *types.ConstructionHashRequest,
) (*types.TransactionIdentifierResponse, *types.Error) {
	transactionBytes, err := hex.DecodeString(request.SignedTransaction)
	if err != nil {
		return nil, wrapErr(ErrCallParametersInvalid, fmt.Errorf("%w: signed transaction should be a hex string", err))
	}
	transactionHash := crypto.Keccak256(transactionBytes)
	return &types.TransactionIdentifierResponse{
		TransactionIdentifier: &types.TransactionIdentifier{
			Hash: fmt.Sprintf("0x%x", transactionHash),
		},
	}, nil
}

// ConstructionParse implements the /construction/parse endpoint.
func (s *ConstructionAPIService) ConstructionParse(
	ctx context.Context,
	request *types.ConstructionParseRequest,
) (*types.ConstructionParseResponse, *types.Error) {
	var tx transaction
	if !request.Signed {
		err := json.Unmarshal([]byte(request.Transaction), &tx)
		if err != nil {
			return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
		}
	} else {
		request.Transaction = strings.Replace(request.Transaction, HexadecimalPrefix, "", -1)
		transactionBytes, err := hex.DecodeString(request.Transaction)
		if err != nil {
			return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
		}
		decodedTransaction, err := s.transactionEncoder.DecodeTransaction(transactionBytes)
		if err != nil {
			return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
		}

		senderAddress, err := s.deriveSenderAddressFromDecodedTransaction(decodedTransaction, err)
		if err != nil {
			return nil, wrapErr(ErrUnableToParseIntermediateResult, fmt.Errorf("%w: failed to derive sender address from decoded transaction", err))
		}

		tx.To = decodedTransaction.ReceiverAddress
		tx.Value = decodedTransaction.Value
		tx.Input = decodedTransaction.Data
		tx.Nonce = decodedTransaction.Nonce
		tx.GasPrice = decodedTransaction.GasPrice
		tx.GasLimit = decodedTransaction.Gas.Uint64()
		tx.ChainID = decodedTransaction.ChainID
		tx.From = senderAddress
	}

	// Ensure valid from address
	checkFrom, ok := rsk.ChecksumAddress(tx.From)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", tx.From))
	}

	// Ensure valid to address
	checkTo, ok := rsk.ChecksumAddress(tx.To)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", tx.To))
	}

	ops := []*types.Operation{
		{
			Type: rsk.CallOpType,
			OperationIdentifier: &types.OperationIdentifier{
				Index: 0,
			},
			Account: &types.AccountIdentifier{
				Address: checkFrom,
			},
			Amount: &types.Amount{
				Value:    new(big.Int).Neg(tx.Value).String(),
				Currency: rsk.DefaultCurrency,
			},
		},
		{
			Type: rsk.CallOpType,
			OperationIdentifier: &types.OperationIdentifier{
				Index: 1,
			},
			RelatedOperations: []*types.OperationIdentifier{
				{
					Index: 0,
				},
			},
			Account: &types.AccountIdentifier{
				Address: checkTo,
			},
			Amount: &types.Amount{
				Value:    tx.Value.String(),
				Currency: rsk.DefaultCurrency,
			},
		},
	}

	metadata := &parseMetadata{
		Nonce:    tx.Nonce,
		GasPrice: tx.GasPrice,
		ChainID:  tx.ChainID,
	}
	metaMap, err := marshalJSONMap(metadata)
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	var resp *types.ConstructionParseResponse
	if request.Signed {
		resp = &types.ConstructionParseResponse{
			Operations: ops,
			AccountIdentifierSigners: []*types.AccountIdentifier{
				{
					Address: checkFrom,
				},
			},
			Metadata: metaMap,
		}
	} else {
		resp = &types.ConstructionParseResponse{
			Operations:               ops,
			AccountIdentifierSigners: []*types.AccountIdentifier{},
			Metadata:                 metaMap,
		}
	}
	return resp, nil
}

func (s *ConstructionAPIService) deriveSenderAddressFromDecodedTransaction(decodedTransaction *rsk.RlpTransactionParameters, err error) (string, error) {
	recoveryIDFromEcdsaVComponent := decodedTransaction.EcdsaSignatureV.Int64() - minimumEcdsaVValue
	hexSignature := fmt.Sprintf("%x%x%02x", decodedTransaction.EcdsaSignatureR, decodedTransaction.EcdsaSignatureS,
		recoveryIDFromEcdsaVComponent)
	signatureBytes, err := hex.DecodeString(hexSignature)
	if err != nil {
		return "", errors.New("signature is not valid")
	}
	publicKeyBytes, err := s.getCompressedPublicKeyFromTransactionAndSignature(decodedTransaction, signatureBytes)
	if err != nil {
		return "", fmt.Errorf("failed to get compressed public key from transaction and signature")
	}
	senderAddress, err := s.getSenderAddressFromCompressedPublicKey(publicKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to get sender address from public key")
	}
	return senderAddress, nil
}

// getSenderAddressFromCompressedPublicKey derives sender address from compressed public key.
func (s *ConstructionAPIService) getSenderAddressFromCompressedPublicKey(compressedPublicKeyBytes []byte) (string, error) {
	senderAddressBytes := s.keccak256Omitting12FirstBytes(compressedPublicKeyBytes)
	senderAddress, ok := rsk.ChecksumAddress(fmt.Sprintf("0x%x", senderAddressBytes))
	if !ok {
		return "", fmt.Errorf("failed to checksum address")
	}
	return senderAddress, nil
}

// getCompressedPublicKeyFromTransactionAndSignature derives compressed public key from transaction and signature.
func (s *ConstructionAPIService) getCompressedPublicKeyFromTransactionAndSignature(decodedTransaction *rsk.RlpTransactionParameters,
	signatureBytes []byte) ([]byte, error) {
	encodedRawTransaction, err := s.transactionEncoder.EncodeRawTransaction(s.copyRlpTransactionParameters(decodedTransaction))
	if err != nil {
		return nil, fmt.Errorf("failed to get raw encoded transaction from RLP transaction parameters")
	}
	keccak256EncodedRawTransaction := crypto.Keccak256(encodedRawTransaction)
	publicKeyBytes, err := secp256k1.RecoverPubkey(keccak256EncodedRawTransaction, signatureBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to recover public key from encoded raw transaction encoded with keccak256")
	}
	return publicKeyBytes, nil
}

// copyRlpTransactionParameters creates new instance of RlpTransactionParameters copying the original.
func (s *ConstructionAPIService) copyRlpTransactionParameters(decodedTransaction *rsk.RlpTransactionParameters) *rsk.RlpTransactionParameters {
	return &rsk.RlpTransactionParameters{
		Nonce:           decodedTransaction.Nonce,
		Gas:             new(big.Int).SetBytes(decodedTransaction.Gas.Bytes()),
		GasPrice:        new(big.Int).SetBytes(decodedTransaction.GasPrice.Bytes()),
		ReceiverAddress: decodedTransaction.ReceiverAddress,
		Value:           new(big.Int).SetBytes(decodedTransaction.Value.Bytes()),
		Data:            decodedTransaction.Data,
		EcdsaSignatureV: new(big.Int).SetBytes(decodedTransaction.EcdsaSignatureV.Bytes()),
		EcdsaSignatureR: new(big.Int).SetBytes(decodedTransaction.EcdsaSignatureR.Bytes()),
		EcdsaSignatureS: new(big.Int).SetBytes(decodedTransaction.EcdsaSignatureS.Bytes()),
		ChainID:         new(big.Int).SetBytes(decodedTransaction.ChainID.Bytes()),
	}
}

// keccak256Omitting12FirstBytes applies Keccak256 to all but the first byte of what's passed, then omits 12 first bytes
// of the result. This is intended for address calculations in RSK.
func (s *ConstructionAPIService) keccak256Omitting12FirstBytes(bytes []byte) []byte {
	return crypto.Keccak256(bytes[1:])[12:]
}

// ConstructionSubmit implements the /construction/submit endpoint.
func (s *ConstructionAPIService) ConstructionSubmit(
	ctx context.Context,
	request *types.ConstructionSubmitRequest,
) (*types.TransactionIdentifierResponse, *types.Error) {
	if s.config.Mode != configuration.Online {
		return nil, ErrUnavailableOffline
	}
	request.SignedTransaction = strings.Replace(request.SignedTransaction, "0x", "", -1)
	signedTransactionBytes, err := hex.DecodeString(request.SignedTransaction)
	if err != nil {
		return nil, wrapErr(ErrCallParametersInvalid, fmt.Errorf("%w: signed transaction should be a hex string", err))
	}
	signedTransactionHexStr := fmt.Sprintf("0x%x", signedTransactionBytes)
	result, err := s.client.SendTransaction(ctx, signedTransactionHexStr)
	if err != nil {
		return nil, wrapErr(ErrBroadcastFailed, fmt.Errorf("%w: failed to send transaction", err))
	}
	_, err = hex.DecodeString(strings.Replace(result, "0x", "", -1))
	if err != nil {
		return nil, wrapErr(ErrCallParametersInvalid, fmt.Errorf("%w: returned transaction hash was invalid", err))
	}
	return &types.TransactionIdentifierResponse{
		TransactionIdentifier: &types.TransactionIdentifier{Hash: result},
	}, nil
}
