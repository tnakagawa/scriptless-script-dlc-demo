// oracle
package main

import (
	"crypto/sha256"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

// Commit computes commit value.
// s = c - H(O,m)o
func Commit(c *big.Int, O *btcec.PublicKey, m []byte, o *big.Int) *big.Int {
	h := Ho(O, m)
	return new(big.Int).Mod(new(big.Int).Sub(c, new(big.Int).Mul(h, o)), btcec.S256().N)
}

// MsgKey returns message publickey.
// C - H(O,m)O
func MsgKey(C, O *btcec.PublicKey, m []byte) *btcec.PublicKey {
	h := Ho(O, m)
	h = new(big.Int).Mod(new(big.Int).Neg(h), btcec.S256().N)
	hO := new(btcec.PublicKey)
	hO.X, hO.Y = btcec.S256().ScalarMult(O.X, O.Y, h.Bytes())
	return SumPubs(C, hO)
}

// Ho returns hash value.
func Ho(O *btcec.PublicKey, m []byte) *big.Int {
	s := sha256.New()
	s.Write(O.SerializeUncompressed())
	s.Write(m)
	hash := s.Sum(nil)
	h := new(big.Int).SetBytes(hash)
	h = new(big.Int).Mod(h, btcec.S256().N)
	return h
}
