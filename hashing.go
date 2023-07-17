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

func CalcPasswordHash(passwordType PasswordType, password string, salt string) (string, error) {
	switch passwordType {
	case BCrypt:
		return CalcBCrypt(password, salt)
	case CRC32:
		return CalcCRC32(password)
	case CustomAlgorithm1:
		return CalcCustomAlgorithm1(password, salt)
	case CustomAlgorithm2:
		return CalcMD5(password + salt)
	case IPBoard_MyBB:
		return CalcIPBoardHash(password, salt)
	case MD5:
		return CalcMD5(password)
	case PHPBB3:
		return CalcPHPBB3(password, salt)
	case SHA1:
		return CalcSHA1(password)
	case SHA256:
		return CalcSHA256(password)
	case SHA512:
		return CalcSHA512(password)
	case vBulletinPost3_8_5:
		return CalcVBulletinHash(password, salt)
	case vBulletinPre3_8_5:
		return CalcVBulletinHash(password, salt)
	case CustomAlgorithm4:
		return CalcCustomAlgorithm4(password, salt)
	case MD5Crypt:
		return CalcMD5Crypt([]byte(password), []byte(salt))
	case CustomAlgorithm5:
		return CalcCustomAlgorithm5(password, salt)
	case DESCrypt:
		return CalcDESCrypt(password, salt)
	//case SCrypt:
	//	return CalcSCrypt(password, salt)
	case MySQLPre4_1:
		return CalcMySQLPre4_1(password)
	case MySQLPost4_1:
		return CalcMySQLPost4_1(password)
	case PeopleSoft:
		return CalcPeopleSoft(password)
	case PunBB:
		return CalcPunBB(password, salt)
	case osCommerce_AEF:
		return CalcMD5(salt + password)
	case PartialMD5_20:
		md5hash, err := CalcMD5(password)
		return md5hash[0:20], err
	case AVE_DataLife_Diferior:
		md5hash, _ := CalcMD5(password)
		return CalcMD5(md5hash)
	case DjangoMD5:
		hash, _ := CalcMD5(salt + password)
		return "md5$" + salt + "$" + hash, nil
	case DjangoSHA1:
		hash, _ := CalcSHA1(salt + password)
		return "sha1$" + salt + "$" + hash, nil
	case PartialMD5_29:
		md5hash, err := CalcMD5(password)
		return md5hash[0:29], err
	case PliggCMS:
		sha1hash, err := CalcSHA1(salt + password)
		return salt + sha1hash, err // salt is prepended to hash
	case RunCMS_SMF1_1:
		return CalcSHA1(salt + password) // salt is username
	case NTLM:
		return CalcNTLM(password)
	case SHA1Dash:
		return CalcSHA1("--" + salt + "--" + password + "--")
	case SHA384:
		return CalcSHA384(password)
	case CustomAlgorithm7:
		return CalcCustomAlgorithm7(password, salt)
	case CustomAlgorithm8:
		return CalcSHA256(salt + password)
	case CustomAlgorithm9:
		return CalcCustomAlgorithm9(password, salt)
	case SHA512Crypt:
		return CalcSHA512Crypt(password, salt)
	case CustomAlgorithm10:
		return CalcSHA512(password + ":" + salt)
	case SHA256Crypt:
		return CalcSHA256Crypt(password, salt)
	case HMACSHA1_SaltAsKey:
		return CalcHMACSHA1SaltAsKey(password, salt)
	case AuthMeSHA256:
		return CalcAuthMeSHA256(password, salt)
	default:
		return "", nil
	}
}

func CalcMD5(password string) (string, error) {
	return fmt.Sprintf("%x", md5.Sum([]byte(password))), nil
}

func CalcSHA1(password string) (string, error) {
	return fmt.Sprintf("%x", sha1.Sum([]byte(password))), nil
}

func CalcSHA256(password string) (string, error) {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(password))), nil
}

func CalcSHA384(password string) (string, error) {
	return fmt.Sprintf("%x", sha512.Sum384([]byte(password))), nil
}

func CalcSHA512(password string) (string, error) {
	return fmt.Sprintf("%x", sha512.Sum512([]byte(password))), nil
}

func CalcNTLM(password string) (string, error) {
	var bytes []byte

	for _, b := range []byte(password) {
		bytes = append(bytes, b)
		bytes = append(bytes, 0x00)
	}

	h := md4.New()
	h.Write(bytes)
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func CalcCRC32(password string) (string, error) {
	return strconv.FormatUint(uint64(crc32.ChecksumIEEE([]byte(password))), 10), nil
}

func CalcBCrypt(password string, salt string) (string, error) {
	hashed, err := BCryptHash([]byte(password), []byte(salt))
	return string(hashed), err
}

func CalcCustomAlgorithm1(password string, salt string) (string, error) {
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

func CalcIPBoardHash(password string, salt string) (string, error) {
	saltHash, _ := CalcMD5(salt)
	passwordHash, _ := CalcMD5(password)
	return CalcMD5(saltHash + passwordHash)
}

const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func CalcPHPBB3(password string, salt string) (string, error) {
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

func CalcVBulletinHash(password string, salt string) (string, error) {
	hash, _ := CalcMD5(password)
	return CalcMD5(hash + salt)
}

func CalcMD5Crypt(password []byte, rawSalt []byte) (string, error) {
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

func CalcCustomAlgorithm4(password string, salt string) (string, error) {
	hash, _ := CalcMD5(password)
	return CalcBCrypt(hash, salt)
}

func CalcCustomAlgorithm5(password string, salt string) (string, error) {
	hash, _ := CalcMD5(password + salt)
	return CalcSHA256(hash)
}

func CalcDESCrypt(password string, salt string) (string, error) {
	return Descrypt(password, salt), nil
}

func CalcMySQLPre4_1(password string) (string, error) {
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

func CalcMySQLPost4_1(password string) (string, error) {
	hash := sha1.Sum([]byte(password))
	hash2 := fmt.Sprintf("%x", sha1.Sum(hash[:]))
	return "*" + hash2, nil
}

func CalcPeopleSoft(password string) (string, error) {
	var bytes []byte

	for _, b := range []byte(password) {
		bytes = append(bytes, b)
		bytes = append(bytes, 0x00)
	}

	hash := sha1.Sum(bytes)
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

func CalcPunBB(password string, salt string) (string, error) {
	hash, _ := CalcSHA1(password)
	return CalcSHA1(salt + hash)
}

func CalcCustomAlgorithm7(password string, salt string) (string, error) {
	derivedSalt, _ := CalcSHA1(salt)

	h := hmac.New(sha256.New, []byte("d2e1a4c569e7018cc142e9cce755a964bd9b193d2d31f02d80bb589c959afd7e"))
	h.Write([]byte(derivedSalt + password))
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func CalcCustomAlgorithm9(password string, salt string) (string, error) {
	result, _ := CalcSHA512(password + salt)

	for i := 0; i < 11; i += 1 {
		result, _ = CalcSHA512(result)
	}

	return result, nil
}

func CalcHMACSHA1SaltAsKey(password string, salt string) (string, error) {
	h := hmac.New(sha1.New, []byte(salt))
	h.Write([]byte(password))
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func CalcSHA256Crypt(password string, salt string) (string, error) {
	return ShaCryptEncrypt(password, salt)
}

func CalcSHA512Crypt(password string, salt string) (string, error) {
	return ShaCryptEncrypt(password, salt)
}

func CalcAuthMeSHA256(password string, salt string) (string, error) {
	hash, _ := CalcSHA256(password)
	hash2, _ := CalcSHA256(hash + salt)
	return "$SHA$" + salt + "$" + hash2, nil
}

func CalcArgon2(toHash string, salt string) (string, error) {
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

	return fmt.Sprintf("%x", DKey([]byte(toHash), justSalt, 3, 1024, 2, 20)), nil

	// prepend salt and options
	//return "$argon2d$v=19$m=1024,t=3,p=2$" + base64.RawStdEncoding.EncodeToString(justSalt) + "$" + base64Result, nil
}
