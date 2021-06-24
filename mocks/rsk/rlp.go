// Code generated by mockery 2.7.5. DO NOT EDIT.

package rsk

import (
	big "math/big"

	mock "github.com/stretchr/testify/mock"
)

// TransactionEncoder is an autogenerated mock type for the TransactionEncoder type
type TransactionEncoder struct {
	mock.Mock
}

// EncodeTransaction provides a mock function with given fields: nonce, gas, receiverAddress, gasPrice, value, data, ecdsaSignatureV, ecdsaSignatureR, ecdsaSignatureS
func (_m *TransactionEncoder) EncodeTransaction(nonce uint64, gas uint64, receiverAddress string, gasPrice *big.Int, value *big.Int, data []byte, ecdsaSignatureV *big.Int, ecdsaSignatureR *big.Int, ecdsaSignatureS *big.Int) ([]byte, error) {
	ret := _m.Called(nonce, gas, receiverAddress, gasPrice, value, data, ecdsaSignatureV, ecdsaSignatureR, ecdsaSignatureS)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(uint64, uint64, string, *big.Int, *big.Int, []byte, *big.Int, *big.Int, *big.Int) []byte); ok {
		r0 = rf(nonce, gas, receiverAddress, gasPrice, value, data, ecdsaSignatureV, ecdsaSignatureR, ecdsaSignatureS)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(uint64, uint64, string, *big.Int, *big.Int, []byte, *big.Int, *big.Int, *big.Int) error); ok {
		r1 = rf(nonce, gas, receiverAddress, gasPrice, value, data, ecdsaSignatureV, ecdsaSignatureR, ecdsaSignatureS)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
