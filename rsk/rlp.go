package rsk

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"math"
	"math/big"
	"strings"
)

const (
	chainIDDecodingMask                     = 0x00ff
	chainIDEncodingMultiplicationModifier   = 2
	chainIDEncodingAdditionModifier         = 35
	lowestPossibleV                         = 27
	rlpEncodingPrefixBaseNumber             = 247
	smallRlpItemMaxSize                     = 55
	minimumListSizeInBytes                  = 192
	emptyMark                               = 128
	expectedElementsInRlpEncodedTransaction = 9
	expectedRlpEncodedEcdsaVSizeInBytes     = 1
	smallRlpItemMask                        = 0x7f
	shortListMaxSize                        = 56
	shortListPrefixByteOffset               = 0xc0
)

type RlpTransactionParameters struct {
	Nonce           uint64
	Gas             *big.Int
	ReceiverAddress string
	GasPrice        *big.Int
	Value           *big.Int
	Data            []byte
	EcdsaSignatureV *big.Int
	EcdsaSignatureR *big.Int
	EcdsaSignatureS *big.Int
	ChainID         *big.Int
}

type TransactionEncoder interface {
	EncodeRawTransaction(rlpTransactionParameters *RlpTransactionParameters) ([]byte, error)
	EncodeTransaction(rlpTransactionParameters *RlpTransactionParameters) ([]byte, error)
	DecodeTransaction([]byte) (*RlpTransactionParameters, error)
}

type RlpTransactionEncoder struct {
}

func NewRlpTransactionEncoder() *RlpTransactionEncoder {
	return &RlpTransactionEncoder{}
}

func (e *RlpTransactionEncoder) EncodeRawTransaction(rlpTransactionParameters *RlpTransactionParameters) ([]byte, error) {
	var vBytes, rBytes, sBytes []byte
	if rlpTransactionParameters.ChainID.Cmp(big.NewInt(0)) != 0 {
		var err error
		vBytes, err = e.encodeBigInt(rlpTransactionParameters.ChainID)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to encode chain ID", err)
		}
		rBytes, err = rlp.EncodeToBytes([]byte{})
		sBytes, err = rlp.EncodeToBytes([]byte{})
		fmt.Println(fmt.Sprintf("r: %x, s: %x", rBytes, sBytes))
	}
	return e.encodeTransactionWithPreEncodedEcdsaValues(rlpTransactionParameters, vBytes, rBytes, sBytes)
}

// EncodeTransaction RLP encodes a transaction. It uses RSK custom logic for prefix bytes, and geth logic for
// leaf item encoding. Due to the custom prefix bytes, decoding cannot use any geth logic.
func (e *RlpTransactionEncoder) EncodeTransaction(rlpTransactionParameters *RlpTransactionParameters) ([]byte, error) {
	vBytes, err := e.encodeEcdsaSignatureV(rlpTransactionParameters.ChainID, rlpTransactionParameters.EcdsaSignatureV)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode component V of ECDSA signature", err)
	}
	rBytes, err := e.encodeBigIntAsUnsigned(rlpTransactionParameters.EcdsaSignatureR)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode component R of ECDSA signature", err)
	}
	sBytes, err := e.encodeBigIntAsUnsigned(rlpTransactionParameters.EcdsaSignatureS)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode component S of ECDSA signature", err)
	}

	encodedTxFieldsBytes, err := e.encodeTransactionWithPreEncodedEcdsaValues(rlpTransactionParameters, vBytes, rBytes, sBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to encode transaction with pre encoded ECDSA values", err)
	}
	return encodedTxFieldsBytes, nil
}

// EncodeTransaction RLP encodes a transaction. It uses RSK custom logic for prefix bytes, and geth logic for
// leaf item encoding. Due to the custom prefix bytes, decoding cannot use any geth logic. ECDSA signature values (r, s and v)
// should already come RLP encoded.
func (e *RlpTransactionEncoder) encodeTransactionWithPreEncodedEcdsaValues(rlpTransactionParameters *RlpTransactionParameters, v, r, s []byte) ([]byte, error) {
	encodedTxFieldsBytes, err := e.getEncodedTxFieldsBytes(rlpTransactionParameters)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get bytes of encoded transaction fields", err)
	}
	if r != nil && s != nil && v != nil {
		encodedTxFieldsBytes = append(encodedTxFieldsBytes, v, r, s)
	}
	joinedEncodedTxFieldsBytes := e.flattenByteSlices(encodedTxFieldsBytes)
	rlpEncodedTransaction := e.prefixEncodedTxWithRlpMetadata(joinedEncodedTxFieldsBytes)
	return rlpEncodedTransaction, nil
}

// getEncodedTxFieldsBytes returns slice of byte slices, where each represents an encoded transaction field in the
// following order:
func (e *RlpTransactionEncoder) getEncodedTxFieldsBytes(rlpTransactionParameters *RlpTransactionParameters) ([][]byte, error) {
	binaryToAddress, err := hex.DecodeString(strings.Replace(rlpTransactionParameters.ReceiverAddress, "0x", "", 1))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get receiver address bytes", err)
	}
	// Converting uint64 to bytes proved problematic - preferred big.Int when possible
	nonceBytes, err := e.encodeBigIntAsUnsigned(e.uint64ToBigInt(rlpTransactionParameters.Nonce))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode nonce", err)
	}
	gasPriceBytes, err := e.encodeBigInt(rlpTransactionParameters.GasPrice)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode gas price", err)
	}
	gasBytes, err := rlp.EncodeToBytes(rlpTransactionParameters.Gas)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode gas", err)
	}
	toBytes, err := rlp.EncodeToBytes(binaryToAddress)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode receiver address", err)
	}
	valueBytes, err := e.encodeBigInt(rlpTransactionParameters.Value)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode value", err)
	}
	dataBytes, err := rlp.EncodeToBytes(rlpTransactionParameters.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP encode data", err)
	}
	return [][]byte{
		nonceBytes, gasPriceBytes, gasBytes, toBytes, valueBytes, dataBytes,
	}, nil
}

// encodeEcdsaSignatureV RLP encodes ECDSA signature's V component.
func (e *RlpTransactionEncoder) encodeEcdsaSignatureV(chainID, ecdsaSignatureV *big.Int) ([]byte, error) {
	var v *big.Int
	isChainIDValid := chainID.Cmp(big.NewInt(0)) != 0
	if isChainIDValid {
		v = e.encodeChainIDInEcdsaSignatureV(chainID, ecdsaSignatureV)
	} else {
		v = new(big.Int)
		v.SetBytes(ecdsaSignatureV.Bytes())
	}
	return e.encodeBigInt(v.Abs(v))
}

// encodeChainIDInEcdsaSignatureV encodes chain ID into ECDSA signature's V component.
func (e *RlpTransactionEncoder) encodeChainIDInEcdsaSignatureV(chainID *big.Int, v *big.Int) *big.Int {
	vWithEncodedChainId := big.NewInt(0)
	return vWithEncodedChainId.
		Add(vWithEncodedChainId, chainID).
		Mul(vWithEncodedChainId, big.NewInt(chainIDEncodingMultiplicationModifier)).
		Add(vWithEncodedChainId, big.NewInt(chainIDEncodingAdditionModifier)).
		Sub(vWithEncodedChainId, big.NewInt(lowestPossibleV)).
		Add(vWithEncodedChainId, v)
}

// uint64ToBigInt converts an uint64 to big.Int.
func (e *RlpTransactionEncoder) uint64ToBigInt(number uint64) *big.Int {
	return new(big.Int).SetUint64(number)
}

// encodeBigIntAsUnsigned RLP encodes big.Int as unsigned int.
func (e *RlpTransactionEncoder) encodeBigIntAsUnsigned(bigInt *big.Int) ([]byte, error) {
	bytes := bigInt.Bytes()
	if len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	return rlp.EncodeToBytes(bytes)
}

// encodeBigInt RLP encodes big.Int.
func (e *RlpTransactionEncoder) encodeBigInt(bigInt *big.Int) ([]byte, error) {
	bytes := bigInt.Bytes()
	return rlp.EncodeToBytes(bytes)
}

// flattenByteSlices flattens byte slices into a single byte slice.
func (e *RlpTransactionEncoder) flattenByteSlices(byteSlices [][]byte) []byte {
	var resultingByteSlice []byte
	for _, byteSlice := range byteSlices {
		resultingByteSlice = append(resultingByteSlice, byteSlice...)
	}
	return resultingByteSlice
}

// prefixEncodedTxWithRlpMetadata adds encoding prefix to RLP encoded transaction fields.
func (e *RlpTransactionEncoder) prefixEncodedTxWithRlpMetadata(joinedEncodedTxFieldsBytes []byte) []byte {
	toString := hex.EncodeToString(joinedEncodedTxFieldsBytes)
	fmt.Println(toString)
	encodedByteAmount := len(joinedEncodedTxFieldsBytes)
	encodedListPrefix := e.getListEncodingPrefix(uint64(encodedByteAmount))
	encodeToString := hex.EncodeToString(encodedListPrefix)
	fmt.Println(encodeToString)
	// TODO: make test for raw encoding, so that we get eb018504a817c800825208946e88dd4c85edde75ae906f6165cec292794fc8d9872386f26fc10000801f8080
	joinedEncodedTxFieldsBytes = append(encodedListPrefix, joinedEncodedTxFieldsBytes...)
	return joinedEncodedTxFieldsBytes
}

// getListEncodingPrefix returns a prefix indicating that an encoded list is what follows.
func (e *RlpTransactionEncoder) getListEncodingPrefix(encodedByteAmount uint64) []byte {
	// TODO: handle case were elements are null?
	// TODO: contemplate non-list items if deciding to not use geth at all.
	var prefixBytes []byte
	if encodedByteAmount < shortListMaxSize {
		prefixBytes = []byte{byte(shortListPrefixByteOffset + encodedByteAmount)} // we use only one byte for list prefix if the list is short
	} else {
		bytesNeededToRepresentAmount := 0
		tmp := encodedByteAmount
		for tmp != 0 {
			bytesNeededToRepresentAmount++
			tmp = tmp >> 8
		}
		prefix := uint64(bytesNeededToRepresentAmount + rlpEncodingPrefixBaseNumber)
		binaryPrefix := make([]byte, 8)
		binary.LittleEndian.PutUint64(binaryPrefix, prefix)

		bytesRepresentingLengthOfEncodedData := make([]byte, 8)
		binary.BigEndian.PutUint64(bytesRepresentingLengthOfEncodedData, encodedByteAmount)

		prefixBytes = append([]byte{binaryPrefix[0]}, bytesRepresentingLengthOfEncodedData[8-bytesNeededToRepresentAmount:8]...)
	}
	return prefixBytes
}

// DecodeTransaction RLP decodes a transaction. It uses RSK custom logic - due to the custom prefix bytes, decoding
// cannot use any geth logic.
func (e *RlpTransactionEncoder) DecodeTransaction(encodedTransaction []byte) (*RlpTransactionParameters, error) {
	decodedRlpList, err := e.decodeList(encodedTransaction)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode encoded transaction as RLP list", err)
	}
	elements, err := decodedRlpList.GetElements(e)
	decodedElementAmount := len(elements)
	if decodedElementAmount != expectedElementsInRlpEncodedTransaction {
		return nil, fmt.Errorf("expected %d encoded elements but got %d", expectedElementsInRlpEncodedTransaction, decodedElementAmount)
	}

	result := &RlpTransactionParameters{}

	err = rlp.DecodeBytes(elements[0].GetData(), &(result.Nonce))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode transaction's nonce", err)
	}

	vData := elements[6].GetData()
	if vData != nil {
		if len(vData) != expectedRlpEncodedEcdsaVSizeInBytes {
			return nil, errors.New("V component of ECDSA signature has invalid length")
		}
		var r, s *big.Int
		r = new(big.Int)
		s = new(big.Int)
		result.EcdsaSignatureR = r.SetBytes(elements[7].GetData())
		result.EcdsaSignatureS = s.SetBytes(elements[8].GetData())
		v := vData[0]
		result.EcdsaSignatureV = e.getBigIntFromByte(e.extractEcdsaVFromEncodedV(v))
		result.ChainID = e.getBigIntFromByte(e.extractChainIdFromEncodedV(v))
	} else {
		result.ChainID = big.NewInt(0)
		log.Info("RLP encoded transaction is not signed")
	}

	var gasPrice, gas, value *big.Int

	if elements[1].GetData() != nil {
		gasPrice = new(big.Int)
		gasPrice.SetBytes(elements[1].GetData())
		result.GasPrice = gasPrice
	}

	if elements[2].GetData() != nil {
		gas = new(big.Int)
		result.Gas = gas.SetBytes(elements[2].GetData())
	}

	result.ReceiverAddress = hex.EncodeToString(elements[3].GetData())

	if elements[4].GetData() != nil {
		value = new(big.Int)
		result.Value = value.SetBytes(elements[4].GetData())
	}

	result.Data = elements[5].GetData()

	return result, nil
}

func (e *RlpTransactionEncoder) getBigIntFromByte(b byte) *big.Int {
	return new(big.Int).SetBytes([]byte{b})
}

func (e *RlpTransactionEncoder) extractEcdsaVFromEncodedV(v byte) byte {
	if !e.isChainIDEncodedInV(v) {
		return v
	}
	isEncodedVEven := v%2 == 0
	if isEncodedVEven {
		return byte(lowestPossibleV + 1)
	}
	return lowestPossibleV
}

func (e *RlpTransactionEncoder) isChainIDEncodedInV(v byte) bool {
	return v != lowestPossibleV && v != lowestPossibleV+1
}

func (e *RlpTransactionEncoder) extractChainIdFromEncodedV(v byte) byte {
	if !e.isChainIDEncodedInV(v) {
		return 0
	}
	decodedVWithoutChainID := ((chainIDDecodingMask & v) - chainIDEncodingAdditionModifier) / chainIDEncodingMultiplicationModifier
	return decodedVWithoutChainID
}

func (e *RlpTransactionEncoder) bytesToLength(bytes []byte, position, size int) (int, error) {
	if position+size > len(bytes) {
		return 0, errors.New("the length of the RLP item length can't possibly the data byte array")
	}
	length := 0
	for i := 0; i < size; i++ {
		length <<= 8
		length += int(bytes[position+i] & 0xff)
	}
	return length, nil
}

// decodeList decodes single (non-nested) list from data bytes - fails it any other structure is used.
func (e *RlpTransactionEncoder) decodeList(data []byte) (*RlpList, error) {
	decodedEntities, err := e.decodeSiblingRlpEntities(data)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to RLP decode entities", err)
	}
	decodedEntityAmount := len(decodedEntities)
	if decodedEntityAmount != 1 {
		return nil, fmt.Errorf("expected one RLP item to be returned but got %d", decodedEntityAmount)
	}
	decodedEntity := decodedEntities[0]
	if !decodedEntity.IsList() {
		return nil, errors.New("the decoded element wasn't a list")
	}
	list, ok := decodedEntity.(*RlpList)
	if !ok {
		return nil, errors.New("failed to cast decoded entity to RLP list entity")
	}
	return list, nil
}

// decodeSiblingRlpEntities runs through data, returning RLP decoded elements - only decodes at same level or 'height'.
func (e *RlpTransactionEncoder) decodeSiblingRlpEntities(data []byte) ([]RlpEntity, error) {
	result := make([]RlpEntity, 0)
	if data == nil {
		return result, nil // TODO: test that this happens upon nil byte slice
	}
	dataByteAmount := len(data)
	dataPosition := 0
	for dataPosition < dataByteAmount {
		decodedElement, elementEndIndex, err := e.decodeElement(data, dataPosition)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to RLP decode data element at position %d", err, dataPosition)
		}
		result = append(result, decodedElement)
		dataPosition = elementEndIndex
	}
	return result, nil
}

// decodeElement returns decoded RLP entity and the index up until which it lasts (in the data byte array).
func (e *RlpTransactionEncoder) decodeElement(data []byte, position int) (RlpEntity, int, error) {
	currentNumericDataByte := data[position] & 0xff
	isElementAList := currentNumericDataByte >= minimumListSizeInBytes
	if isElementAList {
		list, dataEndIndex, err := e.decodeRlpList(data, position, currentNumericDataByte)
		if err != nil {
			return nil, -1, fmt.Errorf("%w: failed to decode RLP list", err)
		}
		return list, dataEndIndex, nil
	}
	if currentNumericDataByte == emptyMark {
		return &RlpItem{data: []byte{}}, position + 1, nil
	}
	// in practice, the following is usually the V component of the ECDSA signature.
	if currentNumericDataByte < emptyMark {
		responseData := []byte{data[position]}
		return &RlpItem{data: responseData}, position + 1, nil
	}
	length, offset, err := e.getRlpItemMetadata(data, position, currentNumericDataByte)
	if err != nil {
		return nil, -1, fmt.Errorf("%w: failed to get RLP item metadata", err)
	}

	err = e.validateRlpItem(data, position, length, offset)
	if err != nil {
		return nil, -1, fmt.Errorf("%w: RLP item is invalid", err)
	}

	decoded := make([]byte, length)
	copy(decoded, data[position+offset:position+offset+length])
	return &RlpItem{data: decoded}, position + offset + length, nil
}

// decodeRlpList returns a decoded RLP list, indicating where it ends (in the data bytes).
func (e *RlpTransactionEncoder) decodeRlpList(data []byte, position int, currentNumericDataByte byte) (rlpList *RlpList,
	listEndIndex int, err error) {
	length, offset, err := e.getListMetadata(data, position, currentNumericDataByte)
	if err != nil {
		return nil, -1, fmt.Errorf("%w: failed to get list metadata", err)
	}
	dataEndIndex := position + length
	if dataEndIndex > len(data) {
		return nil, -1, errors.New("the RLP byte array doesn't have enough space to hold an element with the specified length")
	}
	listDataBytes := data[position:dataEndIndex]
	list := &RlpList{
		RlpItem: RlpItem{
			data: listDataBytes,
		},
		offset: offset,
	}
	return list, dataEndIndex, nil
}

// getListMetadata obtains metadata for RLP list.
func (e *RlpTransactionEncoder) getListMetadata(data []byte, position int, numericFirstByte byte) (length, offset int, err error) {
	isSmallList := numericFirstByte <= minimumListSizeInBytes+smallRlpItemMaxSize
	if isSmallList {
		length = int(numericFirstByte-minimumListSizeInBytes) + 1
		offset = 1
	} else {
		bytesNeededToRepresentAmount := int(numericFirstByte - rlpEncodingPrefixBaseNumber)
		amountOfEncodedDataBytes, err := e.bytesToLength(data, position+1, bytesNeededToRepresentAmount)
		if err != nil {
			err = fmt.Errorf("%w: failed to determine amount of encoded data bytes", err)
			return -1, -1, err
		}
		length = 1 + int(bytesNeededToRepresentAmount) + amountOfEncodedDataBytes
		offset = 1 + bytesNeededToRepresentAmount
	}
	return
}

// getRlpItemMetadata returns length and offset or RLP item being decoded.
func (e *RlpTransactionEncoder) getRlpItemMetadata(data []byte, position int, numericFirstByte byte) (length, offset int, err error) {
	isBigRlpItem := numericFirstByte > emptyMark+smallRlpItemMaxSize
	if isBigRlpItem {
		offset = int(numericFirstByte) - (emptyMark + smallRlpItemMaxSize) + 1
		length, err = e.bytesToLength(data, position+1, offset-1)
		if err != nil {
			return -1, -1, fmt.Errorf("%w: failed to determine length of RLP item", err)
		}
	} else {
		length = int(numericFirstByte & smallRlpItemMask)
		offset = 1
	}
	return
}

// validateRlpItem validates RLP item (its length, and that it has enough space to encode what it pretends to encode).
func (e *RlpTransactionEncoder) validateRlpItem(data []byte, position int, length int, offset int) error {
	isRlpItemBiggerThanExpected := uint32(length) > math.MaxUint32
	if isRlpItemBiggerThanExpected {
		return errors.New("the current implementation doesn't support lengths longer than 0x7fffffff due to node limitations")
	}
	if position+offset+length < 0 || position+offset+length > len(data) {
		return errors.New("the RLP byte array doesn't have enough space to hold an element with the specified length")
	}
	return nil
}

type RlpEntity interface {
	IsList() bool
	GetData() []byte
	GetOffset() int
	GetElements(*RlpTransactionEncoder) ([]RlpEntity, error)
}

type RlpItem struct {
	data []byte
}

func (i *RlpItem) IsList() bool {
	return false
}

func (i *RlpItem) GetData() []byte {
	return i.data
}

func (i *RlpItem) GetOffset() int {
	return -1
}

func (i *RlpItem) GetElements(*RlpTransactionEncoder) ([]RlpEntity, error) {
	return nil, errors.New("operation is not implemented for single RLP item")
}

type RlpList struct {
	RlpItem
	elements []RlpEntity
	offset   int
}

func (l *RlpList) IsList() bool {
	return true
}

func (l *RlpList) GetData() []byte {
	return l.data
}

func (l *RlpList) GetOffset() int {
	return l.offset
}

// GetElements returns the RLP list elements, which are lazily loaded.
func (l *RlpList) GetElements(rlpTransactionEncoder *RlpTransactionEncoder) ([]RlpEntity, error) {
	if l.elements == nil {
		err := l.initializeElements(rlpTransactionEncoder)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to initialize RLP list elements", err)
		}
	}
	return l.elements, nil
}

// initializeElements decodes the elements of the RLP list.
func (l *RlpList) initializeElements(rlpTransactionEncoder *RlpTransactionEncoder) error {
	data := l.GetData()
	content := make([]byte, len(data)-l.GetOffset())
	copy(content, data[l.GetOffset():])
	// Since there are no nested lists (when decoding a list initially, an error occurs if multiple or nested lists appear),
	// we can safely assume that decodeSiblingRlpEntities will return the leaf elements of the list.
	decodedContent, err := rlpTransactionEncoder.decodeSiblingRlpEntities(content)
	if err != nil {
		return fmt.Errorf("%w: failed to decode list content", err)
	}
	l.elements = decodedContent
	return nil
}
