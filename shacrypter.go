package enzoic

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"math"
	"regexp"
	"strconv"
	"strings"
)

const dictionary = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

type HashType int32

const (
	hashTypeSha256 HashType = 5
	hashTypeSha512          = 6
)

// prettier-ignore
var shuffleMap = [][]int32{
	hashTypeSha256: {
		20, 10, 0,
		11, 1, 21,
		2, 22, 12,
		23, 13, 3,
		14, 4, 24,
		5, 25, 15,
		26, 16, 6,
		17, 7, 27,
		8, 28, 18,
		29, 19, 9,
		30, 31,
	},
	hashTypeSha512: {
		42, 21, 0,
		1, 43, 22,
		23, 2, 44,
		45, 24, 3,
		4, 46, 25,
		26, 5, 47,
		48, 27, 6,
		7, 49, 28,
		29, 8, 50,
		51, 30, 9,
		10, 52, 31,
		32, 11, 53,
		54, 33, 12,
		13, 55, 34,
		35, 14, 56,
		57, 36, 15,
		16, 58, 37,
		38, 17, 59,
		60, 39, 18,
		19, 61, 40,
		41, 20, 62,
		63,
	},
}

const roundsDefault = 5000

func ShaCryptEncrypt(plaintext string, salt string) (string, error) {
	saltConf, err := parseSalt(salt)
	if err != nil {
		return "", err
	}
	hash := generateHash(plaintext, saltConf)

	return normalizeSalt(saltConf) + "$" + hash, nil
}

type config struct {
	id            HashType
	saltString    string
	rounds        int
	specifyRounds bool
}

func normalizeSalt(conf config) string {
	parts := []string{"", strconv.Itoa(int(conf.id))}
	if conf.specifyRounds || conf.rounds != roundsDefault {
		parts = append(parts, "rounds="+strconv.Itoa(conf.rounds))
	}
	parts = append(parts, conf.saltString)
	return strings.Join(parts, "$")
}

func parseSalt(salt string) (config, error) {
	roundsMin := 1000
	roundsMax := 999999999

	result := new(config)
	result.rounds = roundsDefault
	result.specifyRounds = false

	parts := strings.Split(salt, "$")
	id, err := strconv.Atoi(parts[1])
	if err != nil {
		return *result, err
	}

	result.id = HashType(id)

	if result.id != hashTypeSha256 && result.id != hashTypeSha512 {
		return *result, errors.New("Only sha256 and sha512 is supported by this library")
	}

	if len(parts) < 2 || len(parts) > 4 {
		return *result, errors.New("Invalid salt string")
	} else if len(parts) > 2 {
		if parts[2][0:7] == "rounds=" {
			rounds, _ := strconv.Atoi(parts[2][7:])
			if rounds >= roundsMin && rounds <= roundsMax {
				result.rounds = rounds
				result.specifyRounds = true
			}
		}

		if len(parts) == 4 && parts[3] != "" {
			result.saltString = parts[3]
		} else {
			// default number of rounds has already been set
			result.saltString = parts[2]
		}
	}

	// sanity-check saltString
	result.saltString = result.saltString[0:int(math.Min(16, float64(len(result.saltString))))]

	matched, _ := regexp.MatchString("[^./0-9A-Za-z]", result.saltString)
	if matched {
		return *result, errors.New("Invalid salt string")
	}

	return *result, nil
}

func generateDigestA(plaintext string, conf config) []byte {
	var digestSize int
	if conf.id == hashTypeSha256 {
		digestSize = 32
	} else {
		digestSize = 64
	}

	var hashTypeA hash.Hash
	var hashTypeB hash.Hash
	if conf.id == hashTypeSha256 {
		hashTypeA = sha256.New()
		hashTypeB = sha256.New()
	} else {
		hashTypeA = sha512.New()
		hashTypeB = sha512.New()
	}

	// steps 1-8
	hashTypeA.Write([]byte(plaintext))
	hashTypeA.Write([]byte(conf.saltString))

	hashTypeB.Write([]byte(plaintext))
	hashTypeB.Write([]byte(conf.saltString))
	hashTypeB.Write([]byte(plaintext))
	digestB := hashTypeB.Sum(nil)

	// step 9
	var plaintextByteLength = len([]byte(plaintext))
	for offset := 0; offset+digestSize < plaintextByteLength; offset += digestSize {
		hashTypeA.Write(digestB)
	}

	// step 10
	var remainder = plaintextByteLength % digestSize
	hashTypeA.Write(digestB[0:remainder])

	// step 11
	binary := strconv.FormatInt(int64(plaintextByteLength), 2)
	binaryArray := strings.Split(binary, "")
	for i, j := 0, len(binaryArray)-1; i < j; i, j = i+1, j-1 {
		binaryArray[i], binaryArray[j] = binaryArray[j], binaryArray[i]
	}

	for i := 0; i < len(binaryArray); i++ {
		if binaryArray[i] == "0" {
			hashTypeA.Write([]byte(plaintext))
		} else {
			hashTypeA.Write(digestB)
		}
	}

	// step 12
	return hashTypeA.Sum(nil)
}

func generateHash(plaintext string, conf config) string {
	var digestSize int
	if conf.id == hashTypeSha256 {
		digestSize = 32
	} else {
		digestSize = 64
	}

	var hashDP hash.Hash
	if conf.id == hashTypeSha256 {
		hashDP = sha256.New()
	} else {
		hashDP = sha512.New()
	}

	// steps 1-12
	digestA := generateDigestA(plaintext, conf)

	// steps 13-15
	plaintextByteLength := len(plaintext)
	for i := 0; i < plaintextByteLength; i++ {
		hashDP.Write([]byte(plaintext))
	}
	digestDP := hashDP.Sum(nil)

	// step 16a
	p := make([]byte, plaintextByteLength)
	for offset := 0; offset+digestSize < plaintextByteLength; offset += digestSize {
		copy(p[offset:], digestDP)
	}

	// step 16b
	remainder := plaintextByteLength % digestSize
	copy(p[plaintextByteLength-remainder:], digestDP[:remainder])

	// step 17-19
	var hashDS hash.Hash
	if conf.id == hashTypeSha256 {
		hashDS = sha256.New()
	} else {
		hashDS = sha512.New()
	}
	step18 := 16 + digestA[0]
	for i := byte(0); i < step18; i++ {
		hashDS.Write([]byte(conf.saltString))
	}
	digestDS := hashDS.Sum(nil)

	// step 20
	s := make([]byte, len(conf.saltString))

	// step 20a
	saltByteLength := len([]byte(conf.saltString))
	for offset := 0; offset+digestSize < saltByteLength; offset += digestSize {
		copy(s[offset:], digestDS)
	}

	// step 20b
	saltRemainder := saltByteLength % digestSize
	copy(s[saltByteLength-saltRemainder:], digestDS[:saltRemainder])

	// step 21
	var hashC hash.Hash
	if conf.id == hashTypeSha256 {
		hashC = sha256.New()
	} else {
		hashC = sha512.New()
	}

	digestC := roundsReduce(digestA, conf.rounds, hashC, p, s)

	// step 22
	return base64Encoder(digestC, shuffleMap[conf.id])
}

func roundsReduce(digestA []byte, rounds int, hashC hash.Hash, p []byte, s []byte) []byte {
	for i := 0; i < rounds; i++ {
		hashC.Reset()

		// steps b-c
		if i%2 == 0 {
			hashC.Write(digestA)
		} else {
			hashC.Write(p)
		}

		// step d
		if i%3 != 0 {
			hashC.Write(s)
		}

		// step e
		if i%7 != 0 {
			hashC.Write(p)
		}

		// steps f-g
		if i%2 != 0 {
			hashC.Write(digestA)
		} else {
			hashC.Write(p)
		}

		digestA = hashC.Sum(nil)
	}

	return digestA
}

func base64Encoder(digest []byte, shuffleMap []int32) string {
	hashVal := ""
	for idx := 0; idx < len(digest); idx += 3 {
		buf := make([]byte, 3)
		buf[0] = digest[shuffleMap[idx]]

		if idx+1 < len(shuffleMap) {
			buf[1] = digest[shuffleMap[idx+1]]
		} else {
			buf[1] = 0
		}

		if idx+2 < len(shuffleMap) {
			buf[2] = digest[shuffleMap[idx+2]]
		} else {
			buf[2] = 0
		}

		hashVal += bufferToBase64(buf)
		//hashVal += base64.RawStdEncoding.EncodeToString(buf)
	}

	// adjust hash length by stripping trailing zeroes induced by base64-encoding
	if len(digest) == 32 {
		return hashVal[0 : len(hashVal)-1]
	} else {
		return hashVal[0 : len(hashVal)-2]
	}
}

func bufferToBase64(buf []byte) string {
	first := buf[0] & 63
	second := ((buf[0] & 192) >> 6) | ((buf[1] & 15) << 2)
	third := ((buf[1] & 240) >> 4) | ((buf[2] & 3) << 4)
	fourth := (buf[2] & 252) >> 2
	return string(dictionary[first]) + string(dictionary[second]) + string(dictionary[third]) + string(dictionary[fourth])
}
