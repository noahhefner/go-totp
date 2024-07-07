package totp

import (
	"fmt"
	"crypto/hmac"
	"hash"
	"encoding/hex"
	"strconv"
)

var digits_power = []int{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000}

type TOTPGenerator struct{
	Key 		string
	CodeLength 	int
	Algorithm	func() hash.Hash
}

func (g TOTPGenerator)Generate(unixTime int64) string {
	return generateTOTP256(g.Key, unixTime, g.CodeLength, g.Algorithm)
}


func NewGenerator (key string, codeLength int, algorithm func() hash.Hash) *TOTPGenerator {

	// TODO: Validate args

	return &TOTPGenerator{
		Key: key,
		CodeLength: codeLength,
		Algorithm: algorithm,
	}
}

func generateTOTP256 (key string, unixTime int64, returnDigits int, algo func() hash.Hash) string {

	// calculate steps from unix time start (January 1, 1970)
	// use 30 second step interval
	steps := unixTime / 30
	stepsString := strconv.FormatInt(steps, 10)
	for len(stepsString) < 16 {
		stepsString = "0" + stepsString
	}

	// get the hex in a byte array
	msg := hex_to_bytes(stepsString)
	k := hex_to_bytes(key)
	sha256_hash := hmac_sha(algo, k, msg)

	// put selected bytes into result int
	offset := sha256_hash[len(sha256_hash) - 1] & 0xf;

	binary := (int(sha256_hash[offset]) & 0x7f)   << 24 |
	          (int(sha256_hash[offset+1]) & 0xff) << 16 |
	          (int(sha256_hash[offset+2]) & 0xff) << 8  |
	          (int(sha256_hash[offset+3]) & 0xff)

	otp := binary % digits_power[returnDigits]

	result := strconv.Itoa(int(otp))
	for len(result) < returnDigits {
		result = "0" + result
	}
	return result

}

// Compute HMAC for given algo, key, and message
func hmac_sha (algo func() hash.Hash, key, message []byte) []byte {

	mac := hmac.New(algo, key)
	mac.Write(message)
	return mac.Sum(nil)

}

// convert hex value stored as string to byte array
func hex_to_bytes (hexString string) []byte {

	decoded, err := hex.DecodeString(hexString)
	if err != nil {
		fmt.Println(err)
		panic("Failed to decode hex to bytes")
	}
	return decoded

}