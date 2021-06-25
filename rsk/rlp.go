package rsk

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/rlp"
	"math/big"
	"strings"
)

const (
	chainIDInc = 35 // TODO: rename to anything clearer.
	lowerRealV = 27 // TODO: rename to anything clearer.
)

type TransactionEncoder interface {
	EncodeTransaction(nonce uint64, gas uint64, receiverAddress string, gasPrice *big.Int, value *big.Int, data []byte,
		ecdsaSignatureV *big.Int, ecdsaSignatureR *big.Int, ecdsaSignatureS *big.Int, chainID *big.Int) ([]byte, error)
}

type RlpTransactionEncoder struct {
}

func (e *RlpTransactionEncoder) EncodeTransaction(nonce uint64, gas uint64, receiverAddress string, gasPrice *big.Int,
	value *big.Int, data []byte, ecdsaSignatureV *big.Int, ecdsaSignatureR *big.Int, ecdsaSignatureS *big.Int,
	chainID *big.Int) ([]byte, error) {
	encodedTxFieldsBytes, err := e.getEncodedTxFieldsBytes(nonce, gas, receiverAddress, gasPrice, value, data,
		ecdsaSignatureV, ecdsaSignatureR, ecdsaSignatureS, chainID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get bytes of encoded transaction fields", err)
	}
	joinedEncodedTxFieldsBytes := e.flattenByteArrays(encodedTxFieldsBytes)
	rlpEncodedTransaction := e.prefixEncodedTxWithRlpMetadata(joinedEncodedTxFieldsBytes)
	// maybe decode first bytes according to rsk list format, then use rlp decode for the rest?
	return rlpEncodedTransaction, nil
}

func (e *RlpTransactionEncoder) getEncodedTxFieldsBytes(nonce uint64, gas uint64, receiverAddress string,
	gasPrice *big.Int, value *big.Int, data []byte, ecdsaSignatureV *big.Int, ecdsaSignatureR *big.Int,
	ecdsaSignatureS *big.Int, chainID *big.Int) ([][]byte, error) {
	binaryToAddress, err := hex.DecodeString(strings.Replace(receiverAddress, "0x", "", 1))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get receiver address bytes", err)
	}
	// Converting uint64 to bytes is Satan himself, so better work with big.Int when possible
	nonceBytes, err := e.encodeBigIntAsUnsigned(e.uint64ToBigInt(nonce))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode nonce", err)
	}
	gasPriceBytes, err := e.encodeBigInt(gasPrice)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode gas price", err)
	}
	gasBytes, err := rlp.EncodeToBytes(e.uint64ToBigInt(gas))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode gas", err)
	}
	toBytes, err := rlp.EncodeToBytes(binaryToAddress)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode receiver address", err)
	}
	valueBytes, err := e.encodeBigInt(value)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode value", err)
	}
	dataBytes, err := rlp.EncodeToBytes(data)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode data", err)
	}

	vBytes, err := e.encodeEcdsaSignatureV(chainID, ecdsaSignatureV)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode component V of ECDSA signature", err)
	}
	rBytes, err := e.encodeBigIntAsUnsigned(ecdsaSignatureR)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode component R of ECDSA signature", err)
	}
	sBytes, err := e.encodeBigIntAsUnsigned(ecdsaSignatureS)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode component S of ECDSA signature", err)
	}
	return [][]byte{
		nonceBytes, gasPriceBytes, gasBytes, toBytes, valueBytes, dataBytes, vBytes, rBytes, sBytes,
	}, nil
}

func (e *RlpTransactionEncoder) encodeEcdsaSignatureV(chainID, ecdsaSignatureV *big.Int) ([]byte, error) {
	defaultV := ecdsaSignatureV
	v := big.NewInt(0)
	if chainID.Cmp(big.NewInt(0)) != 0 {
		// TODO: document this correctly (Transaction.java line 464 in node)
		v = v.
			Add(v, chainID).
			Mul(v, big.NewInt(2)).
			Add(v, big.NewInt(chainIDInc)). // CHAIN_ID_INC
			Sub(v, big.NewInt(lowerRealV)). // LOWER_REAL_V
			Add(v, defaultV)
	} else {
		v.Add(v, defaultV)
	}
	fmt.Printf("v is %d\n", v)
	return e.encodeBigInt(ecdsaSignatureV.Abs(ecdsaSignatureV))
}

// TODO: move to some math package.
func (e *RlpTransactionEncoder) uint64ToBigInt(number uint64) *big.Int {
	return new(big.Int).SetUint64(number)
}

func (e *RlpTransactionEncoder) encodeBigIntAsUnsigned(bigInt *big.Int) ([]byte, error) {
	bytes := bigInt.Bytes()
	if len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	return rlp.EncodeToBytes(bytes)
}

func (e *RlpTransactionEncoder) encodeBigInt(bigInt *big.Int) ([]byte, error) {
	bytes := bigInt.Bytes()
	return rlp.EncodeToBytes(bytes)
}

func (e *RlpTransactionEncoder) flattenByteArrays(encodedTxFieldsBytes [][]byte) []byte {
	var joinedEncodedTxFieldsBytes []byte
	for _, encodedTxFieldBytes := range encodedTxFieldsBytes {
		joinedEncodedTxFieldsBytes = append(joinedEncodedTxFieldsBytes, encodedTxFieldBytes...)
	}
	return joinedEncodedTxFieldsBytes
}

func (e *RlpTransactionEncoder) prefixEncodedTxWithRlpMetadata(joinedEncodedTxFieldsBytes []byte) []byte {
	encodedByteAmount := len(joinedEncodedTxFieldsBytes)
	encodedListPrefix := e.getListEncodingPrefix(uint64(encodedByteAmount))
	joinedEncodedTxFieldsBytes = append(encodedListPrefix, joinedEncodedTxFieldsBytes...)
	return joinedEncodedTxFieldsBytes
}

func (e *RlpTransactionEncoder) getListEncodingPrefix(encodedByteAmount uint64) []byte {
	// TODO: still have to contemplate lists with less than 56 bytes
	bytesNeededToRepresentAmount := 0
	tmp := encodedByteAmount
	for tmp != 0 {
		bytesNeededToRepresentAmount++
		tmp = tmp >> 8
	}
	prefix := uint64(bytesNeededToRepresentAmount + 247)
	binaryPrefix := make([]byte, 8)
	binary.LittleEndian.PutUint64(binaryPrefix, prefix)

	bytesRepresentingLengthOfEncodedData := make([]byte, 8)
	binary.BigEndian.PutUint64(bytesRepresentingLengthOfEncodedData, encodedByteAmount)

	prefixBytes := append([]byte{binaryPrefix[0]}, bytesRepresentingLengthOfEncodedData[8-bytesNeededToRepresentAmount:8]...)

	return prefixBytes
}
