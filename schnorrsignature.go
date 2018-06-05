// schnorrsignature
package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

// Sign returns value.
// s = r - H(R,P,m)p
func Sign(r *big.Int, R, P *btcec.PublicKey, m []byte, p *big.Int) *big.Int {
	e := H(R, P, m)
	return new(big.Int).Mod(new(big.Int).Sub(r, new(big.Int).Mul(e, p)), btcec.S256().N)
}

// Verify returns result.
// sG =? R - H(R,P,m)P
func Verify(s *big.Int, R, P *btcec.PublicKey, m []byte) error {
	sG := new(btcec.PublicKey)
	sG.X, sG.Y = btcec.S256().ScalarBaseMult(s.Bytes())
	h := H(R, P, m)
	h = new(big.Int).Mod(new(big.Int).Neg(h), btcec.S256().N)
	hP := new(btcec.PublicKey)
	hP.X, hP.Y = btcec.S256().ScalarMult(P.X, P.Y, h.Bytes())
	RhP := SumPubs(R, hP)
	if !sG.IsEqual(RhP) {
		return fmt.Errorf("No match. sG : %x , R - H(R||P||m)P : %x",
			sG.SerializeCompressed(), RhP.SerializeCompressed())
	}
	return nil
}

// H returns hash value.
func H(R, P *btcec.PublicKey, m []byte) *big.Int {
	s := sha256.New()
	s.Write(R.SerializeUncompressed())
	s.Write(P.SerializeUncompressed())
	s.Write(m)
	hash := s.Sum(nil)
	h := new(big.Int).SetBytes(hash)
	h = new(big.Int).Mod(h, btcec.S256().N)
	return h
}
