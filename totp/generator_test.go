package totp

import (
	"testing"
	"crypto/sha256"
	"time"
)

type testCase struct{
	UnixTime		int64
	ExpectedCode	string
}

func TestGenerator (t *testing.T) {

	totpGenerator := NewGenerator(
		"3132333435363738393031323334353637383930313233343536373839303132",
		8,
		sha256.New,
	)

	testCases := []testCase{
		testCase{
			UnixTime:		time.Date(1970, time.January, 1, 0, 0, 59, 0, time.UTC).Unix(),
			ExpectedCode: 	"46119246",
		},
	}

	for index, test := range testCases {
		code := totpGenerator.Generate(test.UnixTime)
		if code != test.ExpectedCode {
			t.Fatalf("Failed test case %d", index)
		}
	}

}