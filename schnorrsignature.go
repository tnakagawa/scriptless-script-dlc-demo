// schnorrsignature
package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

// Sign returns value.
// s = r + H(R,P,m)p
func Sign(r *big.Int, R, P *btcec.PublicKey, m []byte, p *big.Int) *big.Int {
	e := Hash(R.SerializeCompressed(), P.SerializeCompressed(), m)
	return new(big.Int).Mod(new(big.Int).Add(r, new(big.Int).Mul(e, p)), btcec.S256().N)
}

// Verify returns result.
// sG =? R + H(R,P,m)P
func Verify(s *big.Int, R, P *btcec.PublicKey, m []byte) error {
	sG := new(btcec.PublicKey)
	sG.X, sG.Y = btcec.S256().ScalarBaseMult(s.Bytes())
	h := Hash(R.SerializeCompressed(), P.SerializeCompressed(), m)
	hP := new(btcec.PublicKey)
	hP.X, hP.Y = btcec.S256().ScalarMult(P.X, P.Y, h.Bytes())
	RhP := SumPubs(R, hP)
	if !sG.IsEqual(RhP) {
		return fmt.Errorf("No match. sG : %x \n  , R + H(R||P||m)P : %x",
			sG.SerializeCompressed(), RhP.SerializeCompressed())
	}
	return nil
}

// Hash returns hash value.
func Hash(bss ...[]byte) *big.Int {
	s := sha256.New()
	for _, bs := range bss {
		s.Write(bs)
	}
	bs := s.Sum(nil)
	return new(big.Int).Mod(new(big.Int).SetBytes(bs), btcec.S256().N)
}
