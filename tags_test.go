package gophertags

import (
	"fmt"
	"math"
	"math/big"
	"testing"
	"testing/quick"

	"github.com/gtank/ristretto255"
)

// quickCheckConfig will make each quickcheck test run (1024 * -quickchecks)
// times. The default value of -quickchecks is 100, indicated by 0.
var quickCheckConfig = &quick.Config{MaxCountScale: 16} // 1024 / 16 = 64 quickchecks

func TestSelfConsistency(t *testing.T) {
	sk := NewSecretKey(24)
	pk := sk.PublicKey()
	dsk := sk.ExtractDetectionKey(5)

	detectionCheck := func(x uint64) bool {
		flag := pk.GenerateFlag()
		return dsk.Test(flag)
	}

	if err := quick.Check(detectionCheck, quickCheckConfig); err != nil {
		t.Error("quickcheck: test doesn't work")
	}
}

func TestUniversalValues(t *testing.T) {
	// See https://git.openprivacy.ca/openprivacy/fuzzytags/commit/e19b99112e3fe70cb92b09db9595d3e05ef26f7c

	zeroFlag := &Flag{
		u:           ristretto255.NewElement(),
		y:           ristretto255.NewScalar(),
		ciphertexts: new(big.Int),
	}

	onesFlag := &Flag{
		u:           ristretto255.NewElement(),
		y:           ristretto255.NewScalar(),
		ciphertexts: new(big.Int).SetUint64((1 << 24) - 1),
	}

	sk := NewSecretKey(24)
	dsk := sk.ExtractDetectionKey(5)

	if dsk.Test(zeroFlag) {
		t.Error("Detection key matched with all zero flag")
	}

	if dsk.Test(onesFlag) {
		t.Error("Detection key matched with all ones flag")
	}
}

func TestFalsePositives(t *testing.T) {
	gamma := 8
	numMessages := 1000
	sk := NewSecretKey(gamma)
	dsk := sk.ExtractDetectionKey(3)
	falsePositives := 0

	for i := 0; i < numMessages; i++ {
		sk2 := NewSecretKey(gamma)
		f := sk2.PublicKey().GenerateFlag()
		sk2.ExtractDetectionKey(3).Test(f)

		if dsk.Test(f) {
			falsePositives += 1
		}
	}

	expectedRate := math.Exp2(float64(0 - len(dsk.internal)))
	actualRate := float64(falsePositives) / float64(numMessages)

	fmt.Printf("Expected rate %f, actual rate %f\n", expectedRate, actualRate)
}
