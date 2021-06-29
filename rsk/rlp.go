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
	smallRlpListMaxSize                     = 55
	minimumListSizeInBytes                  = 192 // TODO: figure out meaning and rename
	emptyMark                               = 128
	expectedElementsInRlpEncodedTransaction = 9
	expectedRlpEncodedEcdsaVSizeInBytes     = 1
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
	EncodeTransaction(rlpTransactionParameters *RlpTransactionParameters) ([]byte, error)
	DecodeTransaction([]byte) (*RlpTransactionParameters, error)
}

type RlpTransactionEncoder struct {
}

func NewRlpTransactionEncoder() *RlpTransactionEncoder {
	return &RlpTransactionEncoder{}
}

func (e *RlpTransactionEncoder) EncodeTransaction(rlpTransactionParameters *RlpTransactionParameters) ([]byte, error) {
	encodedTxFieldsBytes, err := e.getEncodedTxFieldsBytes(rlpTransactionParameters)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get bytes of encoded transaction fields", err)
	}
	joinedEncodedTxFieldsBytes := e.flattenByteArrays(encodedTxFieldsBytes)
	rlpEncodedTransaction := e.prefixEncodedTxWithRlpMetadata(joinedEncodedTxFieldsBytes)
	// maybe decode first bytes according to rsk list format, then use rlp decode for the rest?
	return rlpEncodedTransaction, nil
}

func (e *RlpTransactionEncoder) getEncodedTxFieldsBytes(rlpTransactionParameters *RlpTransactionParameters) ([][]byte, error) {
	binaryToAddress, err := hex.DecodeString(strings.Replace(rlpTransactionParameters.ReceiverAddress, "0x", "", 1))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get receiver address bytes", err)
	}
	// Converting uint64 to bytes is Satan himself, so better work with big.Int when possible
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
	return [][]byte{
		nonceBytes, gasPriceBytes, gasBytes, toBytes, valueBytes, dataBytes, vBytes, rBytes, sBytes,
	}, nil
}

// in RSK, the encoded V value also features the chain ID
func (e *RlpTransactionEncoder) encodeEcdsaSignatureV(chainID, ecdsaSignatureV *big.Int) ([]byte, error) {
	defaultV := ecdsaSignatureV
	v := big.NewInt(0)
	if chainID.Cmp(big.NewInt(0)) != 0 {
		// TODO: document this correctly (Transaction.java line 464 in node)
		v = v.
			Add(v, chainID).
			Mul(v, big.NewInt(chainIDEncodingMultiplicationModifier)).
			Add(v, big.NewInt(chainIDEncodingAdditionModifier)).
			Sub(v, big.NewInt(lowestPossibleV)).
			Add(v, defaultV)
	} else {
		v.Add(v, defaultV)
	}
	fmt.Printf("v is %d\n", v)
	return e.encodeBigInt(ecdsaSignatureV.Abs(v))
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
	prefix := uint64(bytesNeededToRepresentAmount + rlpEncodingPrefixBaseNumber)
	binaryPrefix := make([]byte, 8)
	binary.LittleEndian.PutUint64(binaryPrefix, prefix)

	bytesRepresentingLengthOfEncodedData := make([]byte, 8)
	binary.BigEndian.PutUint64(bytesRepresentingLengthOfEncodedData, encodedByteAmount)

	prefixBytes := append([]byte{binaryPrefix[0]}, bytesRepresentingLengthOfEncodedData[8-bytesNeededToRepresentAmount:8]...)

	return prefixBytes
}

func (e *RlpTransactionEncoder) DecodeTransaction(encodedTransaction []byte) (*RlpTransactionParameters, error) {
	decodedRlpList, err := e.decodeList(encodedTransaction)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode encoded transaction as RLP list", err)
	}
	fmt.Println(decodedRlpList)

	// TODO: port logic in Transaction::Transaction(RLPList transaction)
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
		// TODO: refactor this way of making a big.Int from a byte (extract to function)
		result.EcdsaSignatureV = new(big.Int).SetBytes([]byte{e.extractEcdsaVFromEncodedV(v)})
		result.ChainID = new(big.Int).SetBytes([]byte{e.extractChainIdFromEncodedV(v)})
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

// TODO: reorganize, probably move decoding logic to new RlpTransactionDecoder
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

func (e *RlpTransactionEncoder) decodeList(data []byte) (*RlpList, error) {
	decodedEntities, err := e.decode2(data)
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

// runs through data, returning RLP decoded elements - might return multiple lists
// named decode2 in rskj
func (e *RlpTransactionEncoder) decode2(data []byte) ([]RlpEntity, error) { // TODO: rename function name
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

// TODO: refactor
// returns decoded RLP entity and the index up until which it lasts (in the data byte array)
func (e *RlpTransactionEncoder) decodeElement(data []byte, position int) (RlpEntity, int, error) {
	numericFirstByte := data[position] & 0xff
	isElementAList := numericFirstByte >= minimumListSizeInBytes
	if isElementAList {
		length, offset, err := e.getListMetadata(data, position, numericFirstByte)
		if err != nil {
			return nil, -1, err
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
	if numericFirstByte == emptyMark {
		return &RlpItem{data: []byte{}}, position + 1, nil
	}
	if numericFirstByte < emptyMark { // maybe to detect V?
		responseData := []byte{data[position]}
		return &RlpItem{data: responseData}, position + 1, nil
	}
	var length, offset int
	if numericFirstByte > emptyMark+smallRlpListMaxSize { // TODO: disambiguate meaning
		offset = int(numericFirstByte) - (emptyMark + smallRlpListMaxSize) + 1
		var err error
		length, err = e.bytesToLength(data, position+1, offset-1)
		if err != nil {
			return nil, -1, fmt.Errorf("%w: failed to determine length of RLP item", err)
		}
	} else {
		length = int(numericFirstByte & 0x7f) // TODO: disambiguate meaning
		offset = 1
	}
	if uint32(length) > math.MaxUint32 {
		return nil, -1, errors.New("the current implementation doesn't support lengths longer than 0x7fffffff due to node limitations")
	}
	if position+offset+length < 0 || position+offset+length > len(data) {
		return nil, -1, errors.New("the RLP byte array doesn't have enough space to hold an element with the specified length")
	}
	decoded := make([]byte, length)
	copy(decoded, data[position+offset:position+offset+length])
	return &RlpItem{data: decoded}, position + offset + length, nil
}

func (e *RlpTransactionEncoder) getListMetadata(data []byte, position int, numericFirstByte byte) (int, int, error) {
	var length, offset int
	isSmallList := numericFirstByte <= minimumListSizeInBytes+smallRlpListMaxSize
	if isSmallList {
		length = int(numericFirstByte-minimumListSizeInBytes) + 1
		offset = 1
	} else {
		bytesNeededToRepresentAmount := int(numericFirstByte - rlpEncodingPrefixBaseNumber)
		amountOfEncodedDataBytes, err := e.bytesToLength(data, position+1, bytesNeededToRepresentAmount)
		if err != nil {
			return 0, 0, fmt.Errorf("%w: failed to determine amount of encoded data bytes", err)
		}
		length = 1 + int(bytesNeededToRepresentAmount) + amountOfEncodedDataBytes
		offset = 1 + bytesNeededToRepresentAmount
	}
	return length, offset, nil
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
	// Since there are no nested lists (there's some sort of check when determining that this is a list - it assures no nesting),
	// we can safely assume that decode2 will return the leaf elements of the list.
	decodedContent, err := rlpTransactionEncoder.decode2(content)
	if err != nil {
		return fmt.Errorf("%w: failed to decode list content", err)
	}
	l.elements = decodedContent
	return nil
}

type RlpEntity interface {
	IsList() bool
	GetData() []byte
	GetOffset() int
	GetElements(*RlpTransactionEncoder) ([]RlpEntity, error)
}
