// oracle
package main

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

// Commit computes commit value.
// s = k - H(R,m)x
func Commit(k *big.Int, R *btcec.PublicKey, m []byte, x *big.Int) *big.Int {
	h := Hash(R.SerializeCompressed(), m)
	return new(big.Int).Mod(new(big.Int).Sub(k, new(big.Int).Mul(h, x)), btcec.S256().N)
}

// MsgKey returns message publickey.
// R - Hash(R,m)P
func MsgKey(R, P *btcec.PublicKey, m []byte) *btcec.PublicKey {
	h := Hash(R.SerializeCompressed(), m)
	h = new(big.Int).Mod(new(big.Int).Neg(h), btcec.S256().N)
	hP := new(btcec.PublicKey)
	hP.X, hP.Y = btcec.S256().ScalarMult(P.X, P.Y, h.Bytes())
	return SumPubs(R, hP)
}
