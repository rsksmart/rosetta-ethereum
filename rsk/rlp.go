package rsk

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/rlp"
	"math/big"
)

type TransactionEncoder interface {
	EncodeTransaction(nonce uint64, gas uint64, receiverAddress string, gasPrice *big.Int, value *big.Int,
		data []byte, ecdsaSignatureV *big.Int, ecdsaSignatureR *big.Int, ecdsaSignatureS *big.Int) ([]byte, error)
}

type RlpTransactionEncoder struct {
}

func (e *RlpTransactionEncoder) EncodeTransaction(nonce uint64, gas uint64, receiverAddress string, gasPrice *big.Int,
	value *big.Int, data []byte, ecdsaSignatureV *big.Int, ecdsaSignatureR *big.Int, ecdsaSignatureS *big.Int) ([]byte, error) {
	// TODO: improve error handling (we just ignore and return nil today).
	fmt.Printf("nonce is: %v\n", nonce)
	fmt.Printf("nonce is: %v\n", gas)

	binaryNonce := make([]byte, 8)
	binary.LittleEndian.PutUint64(binaryNonce, nonce)

	binaryGas := make([]byte, 8)
	binary.LittleEndian.PutUint64(binaryGas, gas)

	binaryToAddress, err := hex.DecodeString(receiverAddress)

	nonceBytes := e.encodeNonce(err, binaryNonce)
	gasPriceBytes, err := e.encodeBigInt(gasPrice)
	gasBytes, err := rlp.EncodeToBytes(binaryGas[0:2])
	toBytes, err := rlp.EncodeToBytes(binaryToAddress)
	valueBytes, err := e.encodeBigInt(value)
	dataBytes, err := rlp.EncodeToBytes(data)
	vBytes, err := e.encodeBigInt(ecdsaSignatureV)
	rBytes, err := e.encodeBigInt(ecdsaSignatureR)
	sBytes, err := e.encodeBigInt(ecdsaSignatureS)

	encodedTxFieldsBytes := [][]byte{
		nonceBytes, gasPriceBytes, gasBytes, toBytes, valueBytes, dataBytes, vBytes, rBytes, sBytes,
	}
	var joinedEncodedTxFieldsBytes []byte
	for _, encodedTxFieldBytes := range encodedTxFieldsBytes {
		joinedEncodedTxFieldsBytes = append(joinedEncodedTxFieldsBytes, encodedTxFieldBytes...)
	}

	// 247 is 0xf7

	encodedByteAmount := len(joinedEncodedTxFieldsBytes)
	// how many bytes do we need to represent this amount?

	encodedListPrefix := e.getListEncodingPrefix(uint64(encodedByteAmount))
	fmt.Println(encodedListPrefix)
	fmt.Printf("length of encoded list prefix is %d\n", len(encodedListPrefix))
	joinedEncodedTxFieldsBytes = append(encodedListPrefix, joinedEncodedTxFieldsBytes...)
	return joinedEncodedTxFieldsBytes, nil
}

func (e *RlpTransactionEncoder) encodeBigInt(gasPrice *big.Int) ([]byte, error) {
	return rlp.EncodeToBytes(gasPrice.Bytes())
}

func (e *RlpTransactionEncoder) encodeNonce(err error, binaryNonce []byte) []byte {
	nonceBytes, err := rlp.EncodeToBytes(binaryNonce[0:0]) // TODO: might have to change to []byte
	return nonceBytes
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
