package hashing

import (
  "encoding/hex"
  b64 "encoding/base64"
  "strings"
  "strconv"

  "crypto/md5"
  "crypto/sha1"
  "crypto/sha256"
  "crypto/sha512"
  "enzoic/argon2"


)

// inidvidual hashing algorithms
func Calculate_md5_hash(plaintext string) string {
    hash := md5.Sum([]byte(plaintext))
    return hex.EncodeToString(hash[:])
} // end Calculate_md5_hash

func Calculate_sha1_hash(plaintext string) string {
    hash := sha1.New()
    hash.Write([]byte(plaintext))
    return hex.EncodeToString(hash.Sum(nil))
} // end Calculate_sha1_hash

func Calculate_sha256_hash(plaintext string) string {
    hash := sha256.New()
    hash.Write([]byte(plaintext))
    return hex.EncodeToString(hash.Sum(nil))
} //end Calculate_sha256_hash

func Calculate_sha512_hash(plaintext string) string {
  hash := sha512.New()
  hash.Write([]byte(plaintext))
  return hex.EncodeToString(hash.Sum(nil))
} // end Calculate_sha512_hash

func Calculate_ipboard_mybb_hash(plaintext, salt string) string {
  pw_hash := Calculate_md5_hash(plaintext)
  salt_hash := Calculate_md5_hash(salt)
  hash := Calculate_md5_hash((salt_hash + pw_hash))
  return hash
} // end Calculate_ipboard_mybb_hash

func Calculate_argon2_hash(plaintext, salt string) (hash_string string) {
  var memory uint32 = 1024
  var time uint32 = 3
  var parallelism uint8 = 2
  //var saltLength uint32
  var keyLength uint32 = 20
  var argon_type string = "d"
  var just_salt []byte
  var formatted_salt string

  //check if salt has encoded settings and process accordingly
  if strings.HasPrefix(salt, "$argon2") {
    formatted_salt = salt
    //change mode if necessary
    if strings.HasPrefix(salt, "$argon2i") {
      argon_type = "i"
    }

    //decode and assign salt parameter components
    salt_components := strings.Split(salt, "$")
    just_salt, _ = b64.StdEncoding.DecodeString(salt_components[4])

    salt_params := strings.Split(salt_components[3], ",")

    for _, param := range salt_params {
      split_param := strings.Split(param, "=")
      switch param_type := split_param[0]; param_type {
      case "m":
        temp_memory, err := strconv.ParseUint(split_param[1], 10, 32)
        memory = uint32(temp_memory)
        if err != nil {
          memory = 1024
        }
      case "t":
        temp_time, err := strconv.ParseUint(split_param[1], 10, 32)
        time = uint32(temp_time)
        if err != nil {
          time = 3
        }
      case "p":
        temp_parallelism, err := strconv.ParseUint(split_param[1], 10, 8)
        parallelism = uint8(temp_parallelism)
        if err != nil {
          parallelism = 2
        }
      case "l":
        temp_keyLength, err := strconv.ParseUint(split_param[1], 10, 32)
        keyLength = uint32(temp_keyLength)
        if err != nil {
          keyLength = 20
        }

      } // end switch

    } // end 'for _, param' loop

  }  else {
      // then the salt did not contain hashing parameters, so just convert the
      // salt string to byte array for passing to the argon2 hash call
      just_salt = []byte(salt)
      //and we need to create an appropirately formatted salt to return
      formatted_salt = "$argon2d$v=19$m=" + string(memory) + ",t=" + string(time) + ",p=" + string(parallelism) + "$" + string(just_salt) + "$"

  } // end if/else for salt processing

  //also cast the plaintext password to a byte string as the argon2 call
  //expects this.
  //note that strings in Go are assumed to be utf-8 encoded, which we rely on here.
  b_plaintext := []byte(plaintext)

  //calculate hash
  if argon_type == "d" {
    hash := argon2.KeyD(b_plaintext, just_salt, time, memory, parallelism, keyLength)
    hash_string := b64.RawStdEncoding.EncodeToString(hash)
    return formatted_salt + hash_string
  } else if argon_type == "i" {
    hash := argon2.KeyI(b_plaintext, just_salt, time, memory, parallelism, keyLength)
    return formatted_salt + b64.RawStdEncoding.EncodeToString(hash)
  } else {
    hash_string = ""
    return hash_string
  }

} // end func Calculate_argon_2_hash8



// enzoic API specific

//func CalculateCredentialHash(username, password, password_salt, argon2_salt string, hash_type int) string {
//}
