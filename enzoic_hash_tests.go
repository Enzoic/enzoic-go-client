package main

import (
  "fmt"
  "enzoic/hashing"
  //"encoding/hex"
  //b64 "encoding/base64"
)

func hash_tests() {
  test_pw := "123456"

  test_md5 := hashing.Calculate_md5_hash(test_pw)
  if test_md5 == "e10adc3949ba59abbe56e057f20f883e" {
    fmt.Println("MD5 test OK")
  } else {
    fmt.Println("MD5 test failed")
  }

  test_sha1 := hashing.Calculate_sha1_hash(test_pw)
  if test_sha1 == "7c4a8d09ca3762af61e59520943dc26494f8941b" {
    fmt.Println("SHA1 test OK")

  } else {
    fmt.Println("SHA1 test failed")
  }

  test_sha256 := hashing.Calculate_sha256_hash(test_pw)
  if test_sha256 == "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92" {
    fmt.Println("SHA-256 test OK")
  } else {
    fmt.Println("SHA-256 test failed")
  }

  test_sha512 := hashing.Calculate_sha512_hash(test_pw)
  if test_sha512 == "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413" {
    fmt.Println("SHA-512 test OK")
  } else {
    fmt.Println("SHA-512 test failed")
  }

  test_ipb_mybb := hashing.Calculate_ipboard_mybb_hash(test_pw, "12345")
  if test_ipb_mybb == "96c06579d8dfc66d81f05aab51a9b284" {
    fmt.Println("IPB/MyBB test OK")
  } else {
    fmt.Println("IPB/MyBB test failed")
  }

  test_argon2_d := hashing.Calculate_argon2_hash(test_pw, "$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$")
  if test_argon2_d == "$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o" {
    fmt.Println("Argon2d test OK")
  } else {
    fmt.Println("Argon2d test failed")
  }

  test_vbulletin_pre := hashing.Calculate_vbulletin_pre_3_8_5_hash(test_pw, "123")
  if test_vbulletin_pre == "77d3b7ed9db7d236b9eac8262d27f6a5" {
    fmt.Println("vBulletin pre-3.8.5 test OK")
  } else {
    fmt.Println("vBulletin pre-3.8.5 test failed")
  }

  test_vbulletin_post := hashing.Calculate_vbulletin_post_3_8_5_hash(test_pw, "123")
  if test_vbulletin_post == "77d3b7ed9db7d236b9eac8262d27f6a5" {
    fmt.Println("vBulletin pre-3.8.5 test OK")
  } else {
    fmt.Println("vBulletin pre-3.8.5 test failed")
  }

  test_bcrypt := hashing.Calculate_bcrypt_hash("12345", "$2y$10$zbQ1lHHWrT5G2qqSmA4r.u")
  if test_bcrypt == "$2y$10$zbQ1lHHWrT5G2qqSmA4r.uPc0h/fq6N/ogx5OEH/VwL9NIJIipM9m" {
    fmt.Println("BCrypt test OK")
  } else {
    fmt.Println("BCrypt test failed")
  }

  test_crc32 := hashing.Calculate_crc32_hash("password")
  if test_crc32 == "901924565" {
    fmt.Println("CRC32 test OK")
  } else {
    fmt.Println("CRC32 test failed")
  }

  test_phpbb3 := hashing.Calculate_phpbb3_hash("123456789", "$H$993WP3hbz")
  if test_phpbb3 == "$H$993WP3hbzy0N22X06wxrCc3800D2p41" {
    fmt.Println("PHPBB3 test OK")
  } else {
    fmt.Println("PHPBB3 test failed")
  }

  test_md5crypt := hashing.Calculate_md5crypt_hash("123456", "$1$4d3c09ea")
  if test_md5crypt == "$1$4d3c09ea$hPwyka2ToWFbLTOq.yFjf." {
    fmt.Println("md5Crypt test OK")
  } else {
    fmt.Println("md5Crypt test failed")
    fmt.Println(test_md5crypt)
  }

} // end func hash_tests


func main() {
  hash_tests()
}
