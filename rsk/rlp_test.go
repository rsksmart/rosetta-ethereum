package rsk

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestRlpTransactionEncoder_EncodeTransaction(t *testing.T) {
	type args struct {
		rlpTransactionParameters *RlpTransactionParameters
	}
	testEcdsaSignatureR, _ := new(big.Int).SetString("0x84007fdcb62e921eaedc37f7d6eab8c7290f29bf994a21642e1bf16631aef1c3", HexadecimalBase)
	testEcdsaSignatureS, _ := new(big.Int).SetString("0x3fe112900a4dcebbeda46537c301f39ce7e02e0d7a063ce0bd878dbb21c7f50d", HexadecimalBase)
	tests := []struct {
		name             string
		args             args
		isResultExpected func([]byte) bool
		wantErr          bool
	}{
		{
			name: "Long transaction is encoded as expected",
			args: args{
				rlpTransactionParameters: &RlpTransactionParameters{
					Nonce:           1,
					Gas:             21000,
					ReceiverAddress: "0x6e88dd4c85edde75ae906f6165cec292794fc8d9",
					GasPrice:        big.NewInt(20000000000),
					Value:           big.NewInt(10000000000000000),
					Data:            []byte{},
					EcdsaSignatureV: big.NewInt(27),
					EcdsaSignatureR: testEcdsaSignatureR,
					EcdsaSignatureS: testEcdsaSignatureS,
					ChainID:         TestnetChainID,
				},
			},
			isResultExpected: func(result []byte) bool {
				return hex.EncodeToString(result) == "f86b018504a817c800825208946e88dd4c85edde75ae906f6165cec292794fc8d9872386f26fc10000801ba084007fdcb62e921eaedc37f7d6eab8c7290f29bf994a21642e1bf16631aef1c3a03fe112900a4dcebbeda46537c301f39ce7e02e0d7a063ce0bd878dbb21c7f50d"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &RlpTransactionEncoder{}
			got, err := e.EncodeTransaction(tt.args.rlpTransactionParameters)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeTransaction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.isResultExpected(got) {
				t.Errorf("EncodeTransaction() unexpected result")
				return
			}

		})
	}
}
