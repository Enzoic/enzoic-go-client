package enzoic

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
  "enzoic/hashing"
  "errors"
	"time"
)

// Data Types //

type Enzoic struct {
	CREDENTIALS_API_PATH string
	PASSWORDS_API_PATH   string
	EXPOSURE_API_PATH    string
	ACCOUNTS_API_PATH    string
	ALERTS_SERVICE_PATH  string

	api_key      string
	api_secret   string
	api_base_url string
} //end Enzoic struct


//Passwords API data structures

type EnzoicPasswordsResponse struct {
	Candidates []PasswordCandidate
} //end EnzoicPasswordsResponse struct

type PasswordCandidate struct {
	MD5                       string
	SHA1                      string
	SHA256                    string
	RevealedInExposure        string
	RelativeExposureFrequency int
	ExposureCount             int
} // end PasswordCandidate struct



// Accounts API data structures

type EnzoicAccountResponse struct {
	Salt string
	LastBreachDate string
	PasswordHashesRequired []HashSpec
}

type HashSpec struct {
	HashType int
	Salt string
}


// Exported Functions //


// NewEnzoic
// Create a new instance of Enzoic. (note- use NewEnzoicWithAltEndpoint if you were given a custom endpoint)
// Parameters:
// client_api_key: API key provided by Enzoic for your account.
// client_api_secret: API Secret provided by Enzoic for your account.
// Returns - pointer to Enzoic struct
func NewEnzoic(client_api_key, client_api_secret string) *Enzoic {

	enzoic := new(Enzoic)
	enzoic.CREDENTIALS_API_PATH = "/credentials"
	enzoic.PASSWORDS_API_PATH = "/passwords"
	enzoic.EXPOSURE_API_PATH = "/exposures"
	enzoic.ACCOUNTS_API_PATH = "/accounts"
	enzoic.ALERTS_SERVICE_PATH = "/alert-subscriptions"

	enzoic.api_key = client_api_key
	enzoic.api_secret = client_api_secret
	//use default base url
	enzoic.api_base_url = "https://api.enzoic.com/v1"
	// TODO raise errors for null/empty strings
	return enzoic

} // end func NewEnzoic

// Overloaded constructor for custom endpoints:
// client_api_base_url: If you were provided an alternative API endpoint,
// use New_with_alt_endpoint() and pass in the endpoint with this parameter
func NewEnzoicWithAltEndpoint(client_api_key, client_api_secret,
	                            client_api_base_url string) *Enzoic {

	enzoic := NewEnzoic(client_api_key, client_api_secret)
	enzoic.api_base_url = client_api_base_url

	return enzoic

} //end func NewEnzoicWithAltEndpoint

//CheckPassword checks whether the provided password is in the Enzoic database of known, compromised passwords.
//See: https://www.enzoic.com/docs/passwords-api
// param password: The plaintext password to be checked
// returns: true if the password is a known, compromised password and should not be used
//          err - Error: if any errors were encountered
func (enzoic *Enzoic) CheckPassword(password string) (bool, error) {

	md5 := hashing.Calculate_md5_hash(password)
	sha1 := hashing.Calculate_sha1_hash(password)
	sha256 := hashing.Calculate_sha256_hash(password)

  query_string := "?partial_md5=" + md5[:10] +
                  "&partial_sha1=" + sha1[:10] +
                  "&partial_sha256=" + sha256[:10]

  request_string := enzoic.api_base_url + enzoic.PASSWORDS_API_PATH + query_string

	response := enzoic.makeRestApiGetRequest(request_string)
  defer response.Body.Close()
  status := response.StatusCode

  // status 200 means a list of candidates and metadata was returned
  if status == 200 {
    body, err := ioutil.ReadAll(response.Body)
    if err != nil {
      fmt.Errorf("Error reading Password API response %v", err)
      return false, errors.New("Response Error")
    }
    passwords_response := EnzoicPasswordsResponse{}
    json.Unmarshal([]byte(body), &passwords_response)
    for _, candidate := range passwords_response.Candidates {
      if md5 == candidate.MD5 {
        return true, nil
      } else if sha1 == candidate.SHA1 {
        return true, nil
      } else if sha256 == candidate.SHA256 {
        return true, nil
      }
    } //end for loop
    return false, nil

  // status 404 means the password was not found in the database, thus
  // not compromised
  } else if status == 404 {
    return false, nil
  } else {
    fmt.Errorf("Unexpected response- status code: %d", status)
    return false, errors.New("Unexpected Response")
  }

} // end func CheckPassword

//CheckPasswordEx checks whether the provided password is in the Enzoic database of known, compromised passwords,
// and returns the relative exposure frequency and exposure count.
//See: https://www.enzoic.com/docs/passwords-api
// param password: The plaintext password to be checked
// returns: true if the password is a known, compromised password and should not be used
//					relative_exposure_frequency - int: percentage of total catalogued exposures the password was found in
//          exposure_count - int: number of exposures the password was found in
//					err - Error: if any errors were encountered
func (enzoic *Enzoic) CheckPasswordEx(password string) (exposed bool, relative_exposure, exposure_count int, err error) {

	//initialize return variables
	relative_exposure = 0
	exposure_count = 0

	md5 := hashing.Calculate_md5_hash(password)
	sha1 := hashing.Calculate_sha1_hash(password)
	sha256 := hashing.Calculate_sha256_hash(password)

  query_string := "?partial_md5=" + md5[:10] +
                  "&partial_sha1=" + sha1[:10] +
                  "&partial_sha256=" + sha256[:10]

  request_string := enzoic.api_base_url + enzoic.PASSWORDS_API_PATH + query_string

	response := enzoic.makeRestApiGetRequest(request_string)
  defer response.Body.Close()
  status := response.StatusCode

  // status 200 means a list of candidates and metadata was returned
  if status == 200 {
    body, err := ioutil.ReadAll(response.Body)
    if err != nil {
      fmt.Errorf("Error reading Password API response %v", err)
      return false, relative_exposure, exposure_count, errors.New("Response Error")
    }

    passwords_response := EnzoicPasswordsResponse{}
    json.Unmarshal([]byte(body), &passwords_response)
    for _, candidate := range passwords_response.Candidates {
      if (md5 == candidate.MD5) || (sha1 == candidate.SHA1) || (sha256 == candidate.SHA256) {
				relative_exposure = candidate.RelativeExposureFrequency
				exposure_count = candidate.ExposureCount
        return true, relative_exposure, exposure_count, nil
			}
    } //end for loop
    return false, relative_exposure, exposure_count, nil

  // status 404 means the password was not found in the database, thus
  // not compromised
  } else if status == 404 {
    return false, relative_exposure, exposure_count, nil
  } else {
    fmt.Errorf("Unexpected response- status code: %d", status)
    return false, relative_exposure, exposure_count, errors.New("Unexpected Response")
  }

} // end func CheckPasswordEx


// example date format required - "2021-07-27T03:29:13.000Z"
// if not using the last_check_date argument, pass "0000-00-00T00:00:00.000Z" as
// a string to ensure full execution.
// params: username, password - the credential pair to check
//				 last_check_date - the timestamp (as a string) for the last check performed for this user.
//             If the last check was more recent than the last database update,
//             the check will not be performed, to conserve resources and increase
// 						 performance when checking many users. To ensure full execution for
//             all users, pass the timestamp  "0000-00-00T00:00:00.000Z"
//			   excluded_hash_types - excluding computationally intensive hash types
//         like BCrypt can improve performance (at the cost of security)
//         If you don't wish to exclude any hash types, pass an empty []int slice
// returns: boolean, true if the credential pair is found to be compromised
//          error if an error condition arises, otherwise nil.
func (enzoic *Enzoic) CheckCredentials(username, password, last_check_date string, excluded_hash_types []int) (is_compromised bool, err error){

	request_string := enzoic.api_base_url + enzoic.ACCOUNTS_API_PATH + "?username=" + username
	response := enzoic.makeRestApiGetRequest(request_string)
	defer response.Body.Close()

	status := response.StatusCode
	if status == 404 {
		//this means the username was not found in database at all
		return false, nil
	}

	// status 200 means a list of candidates and metadata was returned
	if status == 200 {

		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Errorf("Error reading Accounts API response %v", err)
			return false, errors.New("Accounts API Response Error")
		}

		account_response := EnzoicAccountResponse{}
		json.Unmarshal([]byte(body), &account_response)

		// convert datetime strings to comparable Time objects
		last_check_date_parsed, err := time.Parse(time.RFC3339, last_check_date)
		last_breach_date_parsed, err := time.Parse(time.RFC3339, account_response.LastBreachDate)
		//if no breaches have been added since the last check, no need to re-query
		if last_check_date_parsed.After(last_breach_date_parsed) {
			return false, nil
		}

		var bcrypt_count int = 0
		for _, hash_spec := range account_response.PasswordHashesRequired {
			if findInt(excluded_hash_types, hash_spec.HashType) {
				continue
			}

			// bcrypt gets far too expensive for good response time if there are many of them to calculate.
      // some mostly garbage accounts have accumulated a number of them in our DB and if we happen to hit one it
      // kills performance, so short circuit out after at most 2 BCrypt hashes
			if ((hash_spec.HashType != 8) || (bcrypt_count <= 2)) {
				fmt.Println(hash_spec.Salt)
			}


		}


  } //end if status == 200

	return true, nil
} // end func CheckCredentials



// non-exported functions

func findInt(my_slice []int, my_val int) bool {
	for _, item := range my_slice {
		if item == my_val {
			return true
		}
	}
	return false
} // end func findInt

func package_json_string(field, value string) []byte {
	json_string := `{"` + field + `":"` + value + `"}`
	return []byte(json_string)
} // end func package_json_string

func (enzoic *Enzoic) makeRestApiGetRequest(url string) *http.Response {
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
    fmt.Errorf("Error forming request: %v", err)
    return nil
	}
	req.SetBasicAuth(enzoic.api_key, enzoic.api_secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	response, err := client.Do(req)
	if err != nil {
    fmt.Errorf("Error making GET request: %v", err)
		return nil
	}
  return response
} // end func make_rest_api_request
