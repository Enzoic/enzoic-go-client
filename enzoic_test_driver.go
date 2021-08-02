package main

import (
  "fmt"
  "enzoic"
)


var key = "d7f84daff45045e080e62e8f7eb6a9c7"
var secret = "=UuTmZEDrW6c8XBkTZyrZ94NHt1p3pk*"

func main() {
  my_enzoic := enzoic.NewEnzoic(key, secret)


  // Tests for CheckPassword
  is_compromised, err := my_enzoic.CheckPassword("password")
  if is_compromised {
    fmt.Println("CheckPassword Test 1 OK")
  } else {
    fmt.Println("CheckPassword Test 1 FAILED")
    if err != nil {
      fmt.Println(err)
    }
  }
  is_compromised, err = my_enzoic.CheckPassword("definitelynotacompromisedpassword0123")
  if !is_compromised {
    fmt.Println("CheckPassword Test 2 OK")
  } else {
    fmt.Println("CheckPassword Test 2 FAILED")
  }


  // Tests for CheckPasswordEx
  is_compromised,relative_ex, ex_count, err := my_enzoic.CheckPasswordEx("password")
  if is_compromised {
    fmt.Println("CheckPasswordEx Test 1 OK")
    fmt.Printf("Relative Exposure %v, Exposure Count %v \n", relative_ex, ex_count)
  } else {
    fmt.Println("CheckPasswordEx Test 1 FAILED")
  }
  is_compromised,relative_ex, ex_count, err = my_enzoic.CheckPasswordEx("definitelynotacompromisedpassword0123")
  if !is_compromised {
    fmt.Println("CheckPasswordEx Test 2 OK")
  } else {
    fmt.Println("CheckPasswordEx Test 2 FAILED")
  }

  // Test for CheckCredentials

  var hash_types_to_exclude []int
  is_compromised, err = my_enzoic.CheckCredentials("testuser", "password", "0000-00-00T00:00:00.000Z", hash_types_to_exclude)
  fmt.Println(is_compromised)

} // end main (enzoic_test_driver.go)
