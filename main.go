// scriptless-script-dlc-demo project main.go
package main

import (
	"fmt"

	"crypto/rand"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

func main() {
	// DLC
	fmt.Println("DLC")
	fmt.Println()
	// Alice public and private key is
	// Pa = xaG
	xa, Pa := KeyGen()

	// Bob public and private key is
	// Pb = xbG
	xb, Pb := KeyGen()

	fmt.Printf("Alice  public key : Pa %x\n", Pa.SerializeCompressed())
	fmt.Printf("Bob    public key : Pb %x\n", Pb.SerializeCompressed())

	// Fund
	// Alice and Bob each send 1 BTC to Fund.
	// Fund address is P .

	// c = Hash(Pa || Pb)
	c := Hash(Pa.SerializeCompressed(), Pb.SerializeCompressed())
	// μa = Hash(c || 0x01)
	mua := Hash(c.Bytes(), []byte{0x01})
	// μb = Hash(c || 0x02)
	mub := Hash(c.Bytes(), []byte{0x02})
	// P = μaPa + μbPb
	P := SumPubs(MulPub(mua, Pa), MulPub(mub, Pb))

	fmt.Println("P = μaPa + μbPb")
	fmt.Printf("Fund   public key : P  %x\n", P.SerializeCompressed())
	fmt.Println()

	// Oracle
	// Olivia(Oracle) announces m] or my after n days.
	// Olivia(Oracle) public and private key is
	// Po = xoG
	xo, Po := KeyGen()
	// Contract key for after n days is
	// Rn = knG
	kn, Rn := KeyGen()
	// Message is
	// m : {mx , my}
	mx := []byte("x")
	my := []byte("y")

	// Olivia publish Po, Rn and m : {mx , my} .
	fmt.Printf("Oracle public key : Po %x\n", Po.SerializeCompressed())
	fmt.Printf("Contract key      : Rn %x\n", Rn.SerializeCompressed())
	fmt.Printf("Message mx : %x\n", mx)
	fmt.Printf("Message my : %x\n", my)
	fmt.Println()

	// Contract
	// Alice and Bob contract.
	// If Olivia announces mx, then Alice get 1.5 BTC and Bob get 0.5 BTC.
	// If Olivia announces my, then Alice get 0.5 BTC and Bob get 1.5 BTC.

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

	fmt.Println("Step1")
	fmt.Println("Alice creates random points and send hash value to Bob.")
	// Rax = raxG
	rax, Rax := KeyGen()
	// Ray = rayG
	ray, Ray := KeyGen()
	// hRa = Hash(Rax || Ray)
	hRa := Hash(Rax.SerializeCompressed(), Ray.SerializeCompressed())
	fmt.Printf("Rax : %x\n", Rax.SerializeCompressed())
	fmt.Printf("Ray : %x\n", Ray.SerializeCompressed())
	fmt.Printf("Alice -- hRa --> Bob : %x\n", hRa)
	fmt.Println()

	// Bob creates random points and send hash value to Alice.
	fmt.Println("Bob creates random points and send hash value to Alice.")
	// Rbx = rbxG
	rbx, Rbx := KeyGen()
	// Rby = rbyG
	rby, Rby := KeyGen()
	// hRb = Hash(Rbx || Rby)
	hRb := Hash(Rbx.SerializeCompressed(), Rby.SerializeCompressed())
	fmt.Printf("Rbx : %x\n", Rbx.SerializeCompressed())
	fmt.Printf("Rby : %x\n", Rby.SerializeCompressed())
	fmt.Printf("Bob -- hRb --> Alice : %x\n", hRb)
	fmt.Println()

	fmt.Println("Step2")
	fmt.Println("Alice sends random points to Bob.")
	fmt.Printf("Alice -- Rax --> Bob : %x\n", Rax.SerializeCompressed())
	fmt.Printf("Alice -- Ray --> Bob : %x\n", Ray.SerializeCompressed())
	fmt.Println()

	fmt.Println("Bob sends random points to Alice.")
	fmt.Printf("Bob -- Rbx --> Alice : %x\n", Rbx.SerializeCompressed())
	fmt.Printf("Bob -- Rby --> Alice : %x\n", Rby.SerializeCompressed())
	fmt.Println()

	fmt.Println("Step3")
	fmt.Println("Alice checks if the hash value is equal to the random points.")
	fmt.Printf("hRb =? Hash(Rbx || Rby) : %v\n", hRb.Cmp(Hash(Rbx.SerializeCompressed(), Rby.SerializeCompressed())) == 0)
	fmt.Println()

	fmt.Println("Bob checks if the hash value is equal to the random points.")
	fmt.Printf("hRa =? Hash(Rax || Ray) : %v\n", hRa.Cmp(Hash(Rax.SerializeCompressed(), Ray.SerializeCompressed())) == 0)
	fmt.Println()

	fmt.Println("Alice and Bob agree Rax , Ray , Rbx and Rby.")
	fmt.Println()

	fmt.Println("contract point")
	// Alice and Bob compute
	// Cx = Rn - Hash(Rn || mx)Po
	Cx := MsgKey(Rn, Po, mx)
	// Cy = Rn - Hash(Rn || my)Po
	Cy := MsgKey(Rn, Po, my)
	fmt.Printf("Cx = Rn - Hash(Rn || mx)Po : %x\n", Cx.SerializeCompressed())
	fmt.Printf("Cy = Rn - Hash(Rn || my)Po : %x\n", Cy.SerializeCompressed())
	fmt.Println()

	fmt.Println("pre sign")
	// Alice computes
	// sax = rax + Hash((Rax+Rbx+Cx) || P || tx1)μaxa
	sax := Sign(rax, SumPubs(Rax, Rbx, Cx), P, tx1, Muls(mua, xa))
	// say = ray + Hash((Ray+Rby+Cy) || P || tx2)μaxa
	say := Sign(ray, SumPubs(Ray, Rby, Cy), P, tx2, Muls(mua, xa))
	// Alice sends sax and say to Bob.
	fmt.Printf("Alice -- sax --> Bob : %x\n", sax)
	fmt.Printf("Alice -- say --> Bob : %x\n", say)
	fmt.Println()

	// Bob computes
	// sbx = rbx + Hash((Rax+Rbx+Cx) || P || tx1)μbxb
	sbx := Sign(rbx, SumPubs(Rax, Rbx, Cx), P, tx1, Muls(mub, xb))
	// sby = rby + Hash((Ray+Rby+Cy) || P || tx2)μbxb
	sby := Sign(rby, SumPubs(Ray, Rby, Cy), P, tx2, Muls(mub, xb))
	// Bob sends sbx and sby to Alice.
	fmt.Printf("Bob -- sbx --> Alice : %x\n", sbx)
	fmt.Printf("Bob -- sby --> Alice : %x\n", sby)
	fmt.Println()

	// Alice checks
	fmt.Println("Alice checks")
	var left *btcec.PublicKey
	var right *btcec.PublicKey
	var ha *big.Int
	// sbxG =? Rbx + Hash((Rax+Rbx+Cx) || P || tx1)μbPb
	left = new(btcec.PublicKey)
	left.X, left.Y = btcec.S256().ScalarBaseMult(sbx.Bytes())
	ha = Hash(SumPubs(Rax, Rbx, Cx).SerializeCompressed(), P.SerializeCompressed(), tx1)
	right = SumPubs(Rbx, MulPub(ha, MulPub(mub, Pb)))
	fmt.Printf("sbxG =? Rbx + Hash((Rax+Rbx+Cx) || P || tx1)μbPb : %v\n", IsEqualBs(left.SerializeCompressed(), right.SerializeCompressed()))
	// sbyG =? Rby + Hash((Rax+Rbx+Cx) || P || tx2)μbPb
	left = new(btcec.PublicKey)
	left.X, left.Y = btcec.S256().ScalarBaseMult(sby.Bytes())
	ha = Hash(SumPubs(Ray, Rby, Cy).SerializeCompressed(), P.SerializeCompressed(), tx2)
	right = SumPubs(Rby, MulPub(Muls(ha, mub), Pb))
	fmt.Printf("sbyG =? Rby + Hash((Ray+Rby+Cy) || P || tx2)μbPb : %v\n", IsEqualBs(left.SerializeCompressed(), right.SerializeCompressed()))

	// Bob checks
	fmt.Println("Bob checks")
	// saxG =? Rax + Hash((Rax+Rbx+Cx) || P || tx1)μaPa
	left = new(btcec.PublicKey)
	left.X, left.Y = btcec.S256().ScalarBaseMult(sax.Bytes())
	ha = Hash(SumPubs(Rax, Rbx, Cx).SerializeCompressed(), P.SerializeCompressed(), tx1)
	right = SumPubs(Rax, MulPub(ha, MulPub(mua, Pa)))
	fmt.Printf("saxG =? Rax + Hash((Rax+Rbx+Cx) || P || tx1)μaPa : %v\n", IsEqualBs(left.SerializeCompressed(), right.SerializeCompressed()))
	// sayG =? Ray + Hash((Rax+Rbx+Cx) || P || tx1)μaPa
	left = new(btcec.PublicKey)
	left.X, left.Y = btcec.S256().ScalarBaseMult(say.Bytes())
	ha = Hash(SumPubs(Ray, Rby, Cy).SerializeCompressed(), P.SerializeCompressed(), tx2)
	right = SumPubs(Ray, MulPub(Muls(ha, mua), Pa))
	fmt.Printf("sayG =? Ray + Hash((Rax+Rbx+Cx) || P || tx2)μaPa : %v\n", IsEqualBs(left.SerializeCompressed(), right.SerializeCompressed()))

	// N days ago
	// Olivia computes
	// sox = kn - Hash(Rn || mx)xo
	sox := Commit(kn, Rn, mx, xo)
	// Olivia publish sox and mx.
	fmt.Println("Olivia publish sox and mx.")
	fmt.Printf("message mx : %x\n", mx)
	fmt.Printf("commit sox : %x\n", sox)
	fmt.Println()

	// Alice or Bob compute
	// s = sax + sbx + sox
	// R = Rax + Rbx + Cx
	s := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Add(sax, sbx), sox), btcec.S256().N)
	R := SumPubs(Rax, Rbx, Cx)
	fmt.Println("Alice or Bob send Transaction tx1 with (s,R).")
	fmt.Printf("(s,R)=(%x,%x)\n", s, R.SerializeCompressed())
	fmt.Println()

	fmt.Println("Verify")
	fmt.Println("sG =? R + H(R,P,tx1)P")
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

// MulPub returns the multiplication of the public key.
func MulPub(x *big.Int, P *btcec.PublicKey) *btcec.PublicKey {
	M := new(btcec.PublicKey)
	M.X, M.Y = btcec.S256().ScalarMult(P.X, P.Y, x.Bytes())
	return M
}

// Muls returns all multiplication mod N.
func Muls(bis ...*big.Int) *big.Int {
	var m *big.Int
	for _, bi := range bis {
		if m == nil {
			m = new(big.Int).SetBytes(bi.Bytes())
			continue
		}
		m = new(big.Int).Mod(new(big.Int).Mul(m, bi), btcec.S256().N)
	}
	return m
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
