package objects

import "testing"

func TestToken_Equals(t *testing.T) {
	_ = &Token{
		Label: "Token1",
		Pin: "1234",
		SoPin: "1234",
		Objects: make(CryptoObjects),
	}
}