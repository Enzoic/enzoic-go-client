package enzoic

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/jzelinskie/whirlpool"
	"golang.org/x/crypto/md4"
	"hash/crc32"
	"io"
	"math"
	"strconv"
	"strings"
)

func calcPasswordHash(passwordType PasswordType, password string, salt string) (string, error) {
	switch passwordType {
	case BCrypt:
		return calcBCrypt(password, salt)
	case CRC32:
		return calcCRC32(password)
	case CustomAlgorithm1:
		return calcCustomAlgorithm1(password, salt)
	case CustomAlgorithm2:
		return calcMD5(password + salt)
	case IPBoard_MyBB:
		return calcIPBoardHash(password, salt)
	case MD5:
		return calcMD5(password)
	case PHPBB3:
		return calcPHPBB3(password, salt)
	case SHA1:
		return calcSHA1(password)
	case SHA256:
		return calcSHA256(password)
	case SHA512:
		return calcSHA512(password)
	case vBulletinPost3_8_5:
		return calcVBulletinHash(password, salt)
	case vBulletinPre3_8_5:
		return calcVBulletinHash(password, salt)
	case CustomAlgorithm4:
		return calcCustomAlgorithm4(password, salt)
	case MD5Crypt:
		return calcMD5Crypt([]byte(password), []byte(salt))
	case CustomAlgorithm5:
		return calcCustomAlgorithm5(password, salt)
	case DESCrypt:
		return calcDESCrypt(password, salt)
	//case SCrypt:
	//	return calcSCrypt(password, salt)
	case MySQLPre4_1:
		return calcMySQLPre4_1(password)
	case MySQLPost4_1:
		return calcMySQLPost4_1(password)
	case PeopleSoft:
		return calcPeopleSoft(password)
	case PunBB:
		return calcPunBB(password, salt)
	case osCommerce_AEF:
		return calcMD5(salt + password)
	case PartialMD5_20:
		md5hash, err := calcMD5(password)
		return md5hash[0:20], err
	case AVE_DataLife_Diferior:
		md5hash, _ := calcMD5(password)
		return calcMD5(md5hash)
	case DjangoMD5:
		hash, _ := calcMD5(salt + password)
		return "md5$" + salt + "$" + hash, nil
	case DjangoSHA1:
		hash, _ := calcSHA1(salt + password)
		return "sha1$" + salt + "$" + hash, nil
	case PartialMD5_29:
		md5hash, err := calcMD5(password)
		return md5hash[0:29], err
	case PliggCMS:
		sha1hash, err := calcSHA1(salt + password)
		return salt + sha1hash, err // salt is prepended to hash
	case RunCMS_SMF1_1:
		return calcSHA1(salt + password) // salt is username
	case NTLM:
		return calcNTLM(password)
	case SHA1Dash:
		return calcSHA1("--" + salt + "--" + password + "--")
	case SHA384:
		return calcSHA384(password)
	case CustomAlgorithm7:
		return calcCustomAlgorithm7(password, salt)
	case CustomAlgorithm8:
		return calcSHA256(salt + password)
	case CustomAlgorithm9:
		return calcCustomAlgorithm9(password, salt)
	case SHA512Crypt:
		return calcSHA512Crypt(password, salt)
	case CustomAlgorithm10:
		return calcSHA512(password + ":" + salt)
	case SHA256Crypt:
		return calcSHA256Crypt(password, salt)
	case HMACSHA1_SaltAsKey:
		return calcHMACSHA1SaltAsKey(password, salt)
	case AuthMeSHA256:
		return calcAuthMeSHA256(password, salt)
	default:
		return "", nil
	}
}

func calcMD5(password string) (string, error) {
	return fmt.Sprintf("%x", md5.Sum([]byte(password))), nil
}

func calcSHA1(password string) (string, error) {
	return fmt.Sprintf("%x", sha1.Sum([]byte(password))), nil
}

func calcSHA256(password string) (string, error) {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(password))), nil
}

func calcSHA384(password string) (string, error) {
	return fmt.Sprintf("%x", sha512.Sum384([]byte(password))), nil
}

func calcSHA512(password string) (string, error) {
	return fmt.Sprintf("%x", sha512.Sum512([]byte(password))), nil
}

func calcNTLM(password string) (string, error) {
	var bytes []byte

	for _, b := range []byte(password) {
		bytes = append(bytes, b)
		bytes = append(bytes, 0x00)
	}

	h := md4.New()
	h.Write(bytes)
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func calcCRC32(password string) (string, error) {
	return strconv.FormatUint(uint64(crc32.ChecksumIEEE([]byte(password))), 10), nil
}

func calcBCrypt(password string, salt string) (string, error) {
	hashed, err := bcryptHash([]byte(password), []byte(salt))
	return string(hashed), err
}

func calcCustomAlgorithm1(password string, salt string) (string, error) {
	// SHA-512(pass.salt) XOR whirlpool(salt.pass)
	sha512Out := sha512.Sum512([]byte(password + salt))

	h := whirlpool.New()
	_, err := io.WriteString(h, salt+password)
	if err != nil {
		return "", err
	}
	whirlpoolOut := h.Sum(nil)

	finalOut := make([]byte, len(sha512Out))
	for i := range sha512Out {
		finalOut[i] = sha512Out[i] ^ whirlpoolOut[i]
	}

	return fmt.Sprintf("%x", finalOut), nil
}

func calcIPBoardHash(password string, salt string) (string, error) {
	saltHash, _ := calcMD5(salt)
	passwordHash, _ := calcMD5(password)
	return calcMD5(saltHash + passwordHash)
}

const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func calcPHPBB3(password string, salt string) (string, error) {
	if salt[0:3] != "$H$" {
		return "", errors.New("invalid salt for phpbb3")
	}

	count := math.Pow(2, float64(strings.Index(itoa64, salt[3:4])))
	justSalt := salt[4:]

	hash := md5.Sum([]byte(justSalt + password))
	for count > 0 {
		hash = md5.Sum(append(hash[:], []byte(password)...))
		count--
	}

	hashout := ""
	i := 0
	counter := 16

	for i < counter {
		value := uint32(hash[i])
		i++
		hashout += string(itoa64[value&0x3f])

		if i < counter {
			value |= uint32(hash[i]) << 8
		}
		hashout += string(itoa64[(value>>6)&0x3f])

		i += 1
		if i >= counter {
			break
		}

		if i < counter {
			value |= uint32(hash[i]) << 16
		}
		hashout += string(itoa64[(value>>12)&0x3f])

		i += 1
		if i >= counter {
			break
		}
		hashout += string(itoa64[(value>>18)&0x3f])
	}

	return salt + hashout, nil
}

func calcVBulletinHash(password string, salt string) (string, error) {
	hash, _ := calcMD5(password)
	return calcMD5(hash + salt)
}

func calcMD5Crypt(password []byte, rawSalt []byte) (string, error) {
	var md5CryptSwaps = [16]int{12, 6, 0, 13, 7, 1, 14, 8, 2, 15, 9, 3, 5, 10, 4, 11}

	salt := rawSalt[3:]

	d := md5.New()

	d.Write(password)
	d.Write([]byte("$1$"))
	d.Write(salt)

	d2 := md5.New()
	d2.Write(password)
	d2.Write(salt)
	d2.Write(password)

	for i, mixin := 0, d2.Sum(nil); i < len(password); i++ {
		d.Write([]byte{mixin[i%16]})
	}

	for i := len(password); i != 0; i >>= 1 {
		if i&1 == 0 {
			d.Write([]byte{password[0]})
		} else {
			d.Write([]byte{0})
		}
	}

	final := d.Sum(nil)

	for i := 0; i < 1000; i++ {
		d2 := md5.New()
		if i&1 == 0 {
			d2.Write(final)
		} else {
			d2.Write(password)
		}

		if i%3 != 0 {
			d2.Write(salt)
		}

		if i%7 != 0 {
			d2.Write(password)
		}

		if i&1 == 0 {
			d2.Write(password)
		} else {
			d2.Write(final)
		}
		final = d2.Sum(nil)
	}

	result := make([]byte, 0, 22)
	v := uint(0)
	bits := uint(0)
	for _, i := range md5CryptSwaps {
		v |= (uint(final[i]) << bits)
		for bits = bits + 8; bits > 6; bits -= 6 {
			result = append(result, itoa64[v&0x3f])
			v >>= 6
		}
	}
	result = append(result, itoa64[v&0x3f])

	return string(append(append(append([]byte("$1$"), salt...), '$'), result...)), nil
}

func calcCustomAlgorithm4(password string, salt string) (string, error) {
	hash, _ := calcMD5(password)
	return calcBCrypt(hash, salt)
}

func calcCustomAlgorithm5(password string, salt string) (string, error) {
	hash, _ := calcMD5(password + salt)
	return calcSHA256(hash)
}

func calcDESCrypt(password string, salt string) (string, error) {
	return descrypt(password, salt), nil
}

func calcMySQLPre4_1(password string) (string, error) {
	nr := uint(1345345333)
	add := uint(7)
	nr2 := uint(0x12345671)

	for i := 0; i < len(password); i += 1 {
		if password[i] == ' ' || password[i] == '\t' {
			continue
		}

		tmp := uint(password[i])
		nr ^= (((nr & 63) + add) * tmp) + (nr << 8)
		nr2 += (nr2 << 8) ^ nr
		add += tmp
	}

	result1 := nr & ((1 << 31) - 1)
	result2 := nr2 & ((1 << 31) - 1)

	return fmt.Sprintf("%x", result1) + fmt.Sprintf("%x", result2), nil
}

func calcMySQLPost4_1(password string) (string, error) {
	hash := sha1.Sum([]byte(password))
	hash2 := fmt.Sprintf("%x", sha1.Sum(hash[:]))
	return "*" + hash2, nil
}

func calcPeopleSoft(password string) (string, error) {
	var bytes []byte

	for _, b := range []byte(password) {
		bytes = append(bytes, b)
		bytes = append(bytes, 0x00)
	}

	hash := sha1.Sum(bytes)
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

func calcPunBB(password string, salt string) (string, error) {
	hash, _ := calcSHA1(password)
	return calcSHA1(salt + hash)
}

func calcCustomAlgorithm7(password string, salt string) (string, error) {
	derivedSalt, _ := calcSHA1(salt)

	h := hmac.New(sha256.New, []byte("d2e1a4c569e7018cc142e9cce755a964bd9b193d2d31f02d80bb589c959afd7e"))
	h.Write([]byte(derivedSalt + password))
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func calcCustomAlgorithm9(password string, salt string) (string, error) {
	result, _ := calcSHA512(password + salt)

	for i := 0; i < 11; i += 1 {
		result, _ = calcSHA512(result)
	}

	return result, nil
}

func calcHMACSHA1SaltAsKey(password string, salt string) (string, error) {
	h := hmac.New(sha1.New, []byte(salt))
	h.Write([]byte(password))
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func calcSHA256Crypt(password string, salt string) (string, error) {
	return shaCryptEncrypt(password, salt)
}

func calcSHA512Crypt(password string, salt string) (string, error) {
	return shaCryptEncrypt(password, salt)
}

func calcAuthMeSHA256(password string, salt string) (string, error) {
	hash, _ := calcSHA256(password)
	hash2, _ := calcSHA256(hash + salt)
	return "$SHA$" + salt + "$" + hash2, nil
}

func calcArgon2(toHash string, salt string) (string, error) {
	var justSalt []byte
	var err error

	if strings.Index(salt, "$argon2") == 0 {
		saltParts := strings.Split(salt, "$")

		if len(saltParts) == 5 {
			justSalt, err = base64.RawStdEncoding.DecodeString(saltParts[4])
			if err != nil {
				return "", err
			}
		}
	} else {
		justSalt = []byte(salt)
	}

	return fmt.Sprintf("%x", dkey([]byte(toHash), justSalt, 3, 1024, 2, 20)), nil

	// prepend salt and options
	//return "$argon2d$v=19$m=1024,t=3,p=2$" + base64.RawStdEncoding.EncodeToString(justSalt) + "$" + base64Result, nil
}
