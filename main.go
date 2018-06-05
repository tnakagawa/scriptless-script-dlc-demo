// scriptless-script-dlc-demo project main.go
package main

import (
	"fmt"

	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

func main() {
	// DLC
	fmt.Println("DLC")
	fmt.Println()
	// Alice public and private key is
	// A = aG
	a, A := KeyGen()
	// Bob public and private key is
	// B = bG
	b, B := KeyGen()

	fmt.Printf("Alice  public key : %x\n", A.SerializeCompressed())
	fmt.Printf("Bob    public key : %x\n", B.SerializeCompressed())
	fmt.Println()

	// Fund
	// Alice and Bob each send 1 BTC to Fund.
	// Fund address is
	// P = A + B
	P := SumPubs(A, B)

	fmt.Printf("Fund   public key : %x\n", P.SerializeCompressed())
	fmt.Println()

	// Oracle
	// Olivia(Oracle) announces X or Y after N days.
	// Olivia(Oracle) public and private key is
	// O = oG
	o, O := KeyGen()
	// After N days constract key is.
	// C = cG
	c, C := KeyGen()
	// Message is X or Y.
	// m : {X,Y}
	// Olivia publish O, C and m : {X,Y}.
	X := []byte("x")
	Y := []byte("y")

	fmt.Printf("Oracle public key : %x\n", O.SerializeCompressed())
	fmt.Printf("Contract key : %x\n", C.SerializeCompressed())
	fmt.Printf("Message X : %x\n", X)
	fmt.Printf("Message Y : %x\n", Y)
	fmt.Println()

	// Contract
	// Alice and Bob contract.
	// If Olivia announces X, then Alice get 1.5 BTC and Bob get 0.5 BTC.
	// If Olivia announces Y, then Alice get 0.5 BTC and Bob get 1.5 BTC.

	// transaction
	// Make all transactions.
	// This case is two.
	tmpl := "Input [0]: Fund\nOutput[0]: A -> %.1f BTC\nOutput[1]: B -> %.1f BTC"

	// This transaction is tx1.
	// Input [0]: Fund
	// Output[0]: A -> 1.5 BTC
	// Output[1]: B -> 0.5 BTC
	tx1 := []byte(fmt.Sprintf(tmpl, 1.5, 0.5))

	// This transaction is tx2.
	// Input [0]: Fund
	// Output[0]: A -> 0.5 BTC
	// Output[1]: B -> 1.5 BTC
	tx2 := []byte(fmt.Sprintf(tmpl, 0.5, 1.5))

	fmt.Println("Contract")
	fmt.Printf("- tx1 -\n%s\n", tx1)
	fmt.Printf("- tx2 -\n%s\n", tx2)
	fmt.Println()

	// random point
	// Alice and Bob make random points for the number of transactions.
	// This case is two. ( tx1 and tx2 )

	// Alice random points
	// Ra1 = ra1G
	// Ra2 = ra2G
	ra1, Ra1 := KeyGen()
	ra2, Ra2 := KeyGen()
	fmt.Println("Alice random points")
	fmt.Printf("Ra1 : %x\n", Ra1.SerializeCompressed())
	fmt.Printf("Ra2 : %x\n", Ra2.SerializeCompressed())
	fmt.Println()

	// Bob random points
	// Rb1 = rb1G
	// Rb2 = rb2G
	rb1, Rb1 := KeyGen()
	rb2, Rb2 := KeyGen()
	fmt.Println("Bob random points")
	fmt.Printf("Rb1 : %x\n", Rb1.SerializeCompressed())
	fmt.Printf("Rb2 : %x\n", Rb2.SerializeCompressed())
	fmt.Println()

	// Alice and Bob mutually agree Ra1 , Ra2 , Rb1 and Rb2.
	fmt.Println("Alice and Bob mutually agree Ra1 , Ra2 , Rb1 and Rb2.")
	fmt.Println()
	fmt.Println("Step1 : Alice send commitments to Bob.")
	hra1 := Hcom(Ra1)
	fmt.Printf("Alice -- Hcom(Ra1) --> Bob : %x\n", hra1)
	hra2 := Hcom(Ra2)
	fmt.Printf("Alice -- Hcom(Ra2) --> Bob : %x\n", hra2)
	fmt.Println()
	fmt.Println("Step2 : Bob send commitments to Alice.")
	hrb1 := Hcom(Rb1)
	fmt.Printf("Bob -- Hcom(Rb1) --> Alice : %x\n", hrb1)
	hrb2 := Hcom(Rb2)
	fmt.Printf("Bob -- Hcom(Rb2) --> Alice : %x\n", hrb2)
	fmt.Println()
	fmt.Println("Step3 : Alice send random points to Bob.")
	fmt.Printf("Alice -- Ra1 --> Bob : %x\n", Ra1.SerializeCompressed())
	fmt.Printf("Alice -- Ra2 --> Bob : %x\n", Ra2.SerializeCompressed())
	fmt.Printf("Bob check Ra1 : %v\n", IsEqualBs(hra1, Hcom(Ra1)))
	fmt.Printf("Bob check Ra2 : %v\n", IsEqualBs(hra2, Hcom(Ra2)))
	fmt.Println()
	fmt.Println("Step4: Bob send random points to Alice.")
	fmt.Printf("Bob -- Rb1 --> Alice : %x\n", Rb1.SerializeCompressed())
	fmt.Printf("Bob -- Rb2 --> Alice : %x\n", Rb2.SerializeCompressed())
	fmt.Printf("Alice check Rb1 : %v\n", IsEqualBs(hrb1, Hcom(Rb1)))
	fmt.Printf("Alice check Rb2 : %v\n", IsEqualBs(hrb2, Hcom(Rb2)))
	fmt.Println()

	// contract point
	// Alice and Bob compute
	// Cx = C - H(O,X)O
	// Cy = C - H(O,Y)O
	Cx := MsgKey(C, O, X)
	Cy := MsgKey(C, O, Y)
	fmt.Println("Contract point")
	fmt.Printf("Cx = C - H(O,X)O : %x\n", Cx.SerializeCompressed())
	fmt.Printf("Cy = C - H(O,Y)O : %x\n", Cy.SerializeCompressed())
	fmt.Println()

	// pre sign
	// Alice computes
	// s1a = ra1 - H(Ra1+Rb1+Cx,A+B,tx1)a
	// s2a = ra2 - H(Ra2+Rb2+Cy,A+B,tx2)a
	R1 := SumPubs(Ra1, Rb1, Cx)
	R2 := SumPubs(Ra2, Rb2, Cx)
	s1a := Sign(ra1, R1, P, tx1, a)
	s2a := Sign(ra2, R2, P, tx2, a)
	fmt.Println("Pre sign")
	fmt.Println("Alice computes")
	fmt.Println("s1a = ra1 - H(Ra1+Rb1+Cx,A+B,tx1)a")
	fmt.Println("s2a = ra2 - H(Ra2+Rb2+Cy,A+B,tx2)a")

	// Alice send s1a and s2a to Bob.
	fmt.Printf("Alice -- s1a --> Bob : %x\n", s1a)
	fmt.Printf("Alice -- s2a --> Bob : %x\n", s2a)
	fmt.Println()

	// Bob computes
	// s1b = rb1 - H(Ra1+Rb1+Cx,A+B,tx1)b
	// s2b = rb2 - H(Ra2+Rb2+Cy,A+B,tx2)b
	s1b := Sign(rb1, R1, P, tx1, b)
	s2b := Sign(rb2, R2, P, tx2, b)
	fmt.Println("Bob computes")
	fmt.Println("s1b = rb1 - H(Ra1+Rb1+Cx,A+B,tx1)b")
	fmt.Println("s2b = rb2 - H(Ra2+Rb2+Cy,A+B,tx2)b")

	// Bob send s1b and s2b to Alice.
	fmt.Printf("Bob -- s1b --> Alice : %x\n", s1b)
	fmt.Printf("Bob -- s2b --> Alice : %x\n", s2b)
	fmt.Println()

	// N days ago
	// Olivia computes
	// cx = c - H(O,X)o
	cx := Commit(c, O, X, o)

	// Olivia publish cx and X.
	fmt.Println("Oracle commit")
	fmt.Printf("message X : %x\n", X)
	fmt.Printf("commit    : %x\n", cx)
	fmt.Println()

	// Alice or Bob compute
	// s = s1a + s1b + cx
	// R = Ra1 + Rb1 + Cx
	s := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Add(s1a, s1b), cx), btcec.S256().N)
	R := SumPubs(Ra1, Rb1, Cx)
	fmt.Println("Alice compute")
	fmt.Println("s = s1a + s1b + cx")
	fmt.Println("R = Ra1 + Rb1 + Cx")
	// Alice or Bob send Transaction tx1 with (s,R).
	fmt.Printf("(s,R)=(%x,%x)\n", s, R.SerializeCompressed())
	fmt.Println()

	fmt.Println("Verify")
	fmt.Println("sG =? R - H(R,P,tx1)P")
	err := Verify(s, R, P, tx1)
	if err != nil {
		fmt.Printf("Fail : %+v\n", err)
		return
	}
	fmt.Println("Success!")

}

// KeyGen returns a private/public key pair.
func KeyGen() (*big.Int, *btcec.PublicKey) {
	x, _ := rand.Int(rand.Reader, btcec.S256().N)
	pri, pub := btcec.PrivKeyFromBytes(btcec.S256(), x.Bytes())
	return pri.D, pub
}

// SumPubs sum public keys.
func SumPubs(Pubs ...*btcec.PublicKey) *btcec.PublicKey {
	S := new(btcec.PublicKey)
	for i, P := range Pubs {
		if i == 0 {
			S.X, S.Y = P.X, P.Y
		} else {
			S.X, S.Y = btcec.S256().Add(S.X, S.Y, P.X, P.Y)
		}
	}
	return S
}

// Hcom returns hash value.
func Hcom(R *btcec.PublicKey) []byte {
	s := sha256.New()
	s.Write(R.SerializeCompressed())
	return s.Sum(nil)
}

// IsEqualBs returns true if they match.
func IsEqualBs(bs1, bs2 []byte) bool {
	if len(bs1) != len(bs2) {
		return false
	}
	for i, b := range bs1 {
		if b != bs2[i] {
			return false
		}
	}
	return true
}
