// Gophers are fuzzy.
package gophertags

import (
	"crypto/rand"
	"math/big"
	"math/bits"

	r255 "github.com/gtank/ristretto255"
	"golang.org/x/crypto/sha3"
)

// SecretKey is the secret key held by the ultimate recipient of the messages.
// It is used to derive public keys and detection keys for distribution.
// Internally, it's a vector of Ristretto255 scalars (the detection key) and Ristretto255 elements (the public key).
type SecretKey struct {
	sk []*r255.Scalar
	pk []*r255.Element
}

// PublicKey is the public key that will be used to send messages to the recipient.
type PublicKey struct {
	internal []*r255.Element
}

// DetectionKey is given to the adversarial mailbox to test inbound messages for a given recipient.
// Detection keys have an inherent false positive rate set at construction.
type DetectionKey struct {
	internal []*r255.Scalar
}

type Flag struct {
	u           *r255.Element
	y           *r255.Scalar
	ciphertexts *big.Int // as bitvec
}

// NewSecretKey constructs a secret key with a maximum false positive rate of 2^-gamma.
func NewSecretKey(gamma int) *SecretKey {
	key := &SecretKey{
		sk: make([]*r255.Scalar, gamma),
		pk: make([]*r255.Element, gamma),
	}

	randBytes := make([]byte, 64)

	for i := 0; i < gamma; i++ {
		n, err := rand.Read(randBytes)
		if n != 64 || err != nil {
			// If you aren't getting randomness, there's no way the rest of this is going to work.
			// TODO: It would be good to add a function that takes a custom reader for more predictable testing.
			panic("panic! at the keygen")
		}

		key.sk[i] = r255.NewScalar().FromUniformBytes(randBytes)
		key.pk[i] = r255.NewElement().ScalarBaseMult(key.sk[i])
	}

	return key
}

// PublicKey returns a deep copy of the secret key's associated public key.
func (sk *SecretKey) PublicKey() *PublicKey {
	// Language Wars Episode 2: The Lack of the Clones
	// TODO: https://github.com/gtank/ristretto255/issues/35
	pkCopy := make([]*r255.Element, len(sk.pk))
	for i := 0; i < len(pkCopy); i++ {
		byteRepr := sk.pk[i].Encode(nil)
		pkCopy[i] = r255.NewElement()
		_ = pkCopy[i].Decode(byteRepr)
	}
	return &PublicKey{internal: pkCopy}
}

// ExtractDetectionKey produces a detection key with false positive rate 0 <= 2^-n <= 2^-gamma.
// Internally, it's a copy of the first n scalars in the secret key.
func (sk *SecretKey) ExtractDetectionKey(n int) *DetectionKey {
	secrets := make([]*r255.Scalar, n)
	for i := 0; i < n; i++ {
		byteRepr := sk.sk[i].Encode(nil)
		secrets[i] = r255.NewScalar()
		_ = secrets[i].Decode(byteRepr)
	}
	return &DetectionKey{internal: secrets}
}

// hashG3Bit implements H: G^3 -> {0,1} in a manner consistent with the Rust crate `fuzzytags`
func hashG3ToBit(rB, rH, zB *r255.Element) uint {
	digest := sha3.New256()
	digest.Write(rB.Encode(nil))
	digest.Write(rH.Encode(nil))
	digest.Write(zB.Encode(nil))
	return uint(digest.Sum(nil)[0] & 0x01)
}

// hashGVecToScalar hashes a Ristretto element and a bit vector of ciphertexts to a
// Ristretto scalar in a manner consistent with the Rust crate `fuzzytags`.
func hashGVecToScalar(u *r255.Element, bitVec *big.Int) *r255.Scalar {
	// TODO: Recall enough big.Int internals to use Bytes() or FillBytes() here?

	// Pack bits into byte slice of necessary size, implicitly zero-padded to nearest byte.
	byteRepr := make([]byte, 0, bitVec.BitLen()+7/8)
	for _, word := range bitVec.Bits() {
		for i := 0; i < bits.UintSize; i += 8 {
			if len(byteRepr) >= cap(byteRepr) {
				break
			}
			byteRepr = append(byteRepr, byte(word))
			word >>= 8
		}
	}

	digest := sha3.Sum512(u.Encode(byteRepr))
	return r255.NewScalar().FromUniformBytes(digest[:])
}

// GenerateFlag creates a randomized flag ciphertext for the given public key.
func (pk *PublicKey) GenerateFlag() *Flag {
	uniformBytes := make([]byte, 128)
	_, err := rand.Read(uniformBytes)
	if err != nil {
		panic("error sampling scalar entropy")
	}

	// Random group elements
	r := r255.NewScalar().FromUniformBytes(uniformBytes[0:64])
	z := r255.NewScalar().FromUniformBytes(uniformBytes[64:128])
	u := r255.NewElement().ScalarBaseMult(r)
	w := r255.NewElement().ScalarBaseMult(z)

	// TODO need to double check that this actually behaves like I think it does. Specifically check padding.
	bitVec := new(big.Int)

	for i, H := range pk.internal {
		rH := r255.NewElement().ScalarMult(r, H)
		c := hashG3ToBit(u, rH, w) ^ 0x01
		bitVec.SetBit(bitVec, i, c)
	}

	m := hashGVecToScalar(u, bitVec)

	// y = 1/r * (z - m)
	y := r255.NewScalar().Invert(r)
	y.Multiply(y, z.Subtract(z, m)) // smashes z

	return &Flag{u, y, bitVec}
}

// Test returns true if the given flag matches the detection key.
func (dk *DetectionKey) Test(f *Flag) bool {
	// Thanks to Lee Bousfield and Sarah Jamie Lewis, without whom I would also
	// have written a universal tag bug here. See
	// https://git.openprivacy.ca/openprivacy/fuzzytags/commit/e19b99112e3fe70cb92b09db9595d3e05ef26f7c
	if f.u.Equal(r255.NewElement()) == 1 || f.y.Equal(r255.NewScalar()) == 1 {
		return false
	}

	m := hashGVecToScalar(f.u, f.ciphertexts)

	scalars := []*r255.Scalar{m, f.y}
	elements := []*r255.Element{r255.NewElement().Base(), f.u}
	w := r255.NewElement().MultiScalarMult(scalars, elements)

	var pass uint = 0x01

	for i, x_i := range dk.internal {
		xU := r255.NewElement().ScalarMult(x_i, f.u)
		k := hashG3ToBit(f.u, xU, w)
		b := k ^ f.ciphertexts.Bit(i)
		pass = pass & b
	}

	if pass == 0x01 {
		return true
	} else {
		return false
	}
}
