package enzoic

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// API endpoint paths
const (
	credentialsAPIPath                       = "/credentials"
	cleartextCredentialsAPIPath              = "/cleartext-credentials"
	cleartextCredentialsByPartialHashAPIPath = "/cleartext-credentials-by-partial-hash"
	cleartextCredentialsByDomain             = "/cleartext-credentials-by-domain"
	passwordsAPIPath                         = "/passwords"
	exposuresForUsernamesAPIPath             = "/exposures-for-usernames"
	exposuresForDomainAPIPath                = "/exposures-for-domain"
	exposuresForDomainUsersAPIPath           = "/exposures-for-domain-users"
	exposureDetailsAPIPath                   = "/exposure-details"
	accountsAPIPath                          = "/accounts"
	breachMonitoringForUsersAPIPath          = "/breach-monitoring-for-users"
	breachMonitoringForDomainsAPIPath        = "/breach-monitoring-for-domains"
)

type Client struct {
	apiKey     string
	secret     string
	authString string
	baseURL    string
	HttpClient *http.Client
}

// NewClient creates a new instance of the Enzoic Client, taking your API key and secret as parameters.
func NewClient(apiKey, secret string) (*Client, error) {
	return NewClientWithCustomBaseURL(apiKey, secret, "")
}

// NewClientWithCustomBaseURL creates a new instance of the Enzoic Client, taking your API key and secret as parameters.
func NewClientWithCustomBaseURL(apiKey, secret, apiBaseURL string) (*Client, error) {
	if apiKey == "" {
		return nil, errors.New("API Key cannot be empty")
	}
	if secret == "" {
		return nil, errors.New("API Secret cannot be empty")
	}

	if apiBaseURL == "" {
		apiBaseURL = "https://api.enzoic.com/v1"
	}

	client := &http.Client{}
	client.Timeout = 30 * time.Second // default 30 second timeout

	enzoic := &Client{
		apiKey:     apiKey,
		secret:     secret,
		authString: "basic " + base64.StdEncoding.EncodeToString([]byte(apiKey+":"+secret)),
		baseURL:    apiBaseURL,
		HttpClient: client,
	}
	return enzoic, nil
}

// CheckPassword checks whether the password provided in the password parameter is in the Enzoic database of known,
// compromised passwords.  If so it will return true.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/passwords-api
func (e *Client) CheckPassword(password string) (bool, error) {
	revealedInExposure := false
	var relativeExposureFrequency int

	return e.CheckPasswordWithExposure(password, &revealedInExposure, &relativeExposureFrequency)
}

// CheckPasswordHash checks whether the password provided in the passwordHash parameter is in the Enzoic database of known,
// compromised passwords.  If so it will return true.  The passwordHash can be a hash in any of the formats supported
// by the Enzoic Passwords API (PasswordType.MD5, PasswordType.SHA1, PasswordType.SHA256 or PasswordType.NTLM).
// The passwordType parameter should be set to the type of hash being provided using the PasswordType enum.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/passwords-api
func (e *Client) CheckPasswordHash(passwordHash string, hashType PasswordType) (bool, error) {
	var requestObject interface{}

	switch hashType {
	case MD5:
		requestObject = struct {
			PartialMD5 string `json:"partialMD5"`
		}{
			PartialMD5: strings.ToLower(passwordHash[:10]),
		}
	case SHA1:
		requestObject = struct {
			PartialSHA1 string `json:"partialSHA1"`
		}{
			PartialSHA1: strings.ToLower(passwordHash[:10]),
		}
	case SHA256:
		requestObject = struct {
			PartialSHA256 string `json:"partialSHA256"`
		}{
			PartialSHA256: strings.ToLower(passwordHash[:10]),
		}
	case NTLM:
		requestObject = struct {
			PartialNTLM string `json:"partialNTLM"`
		}{
			PartialNTLM: strings.ToLower(passwordHash[:10]),
		}
	default:
		return false, errors.New("Invalid hash type.  Must be MD5, SHA1, SHA256 or NTLM")
	}

	requestBody, err := json.Marshal(requestObject)
	if err != nil {
		return false, err
	}

	resp, body, err := e.makeRestCall("POST", passwordsAPIPath, "", requestBody)
	if err != nil {
		return false, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	} else if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("Failed to check password: %s", resp.Status)
	}

	var responseObj map[string]interface{}
	err = json.Unmarshal(body, &responseObj)
	if err != nil {
		return false, err
	}

	candidates, ok := responseObj["candidates"].([]interface{})
	if !ok {
		return false, errors.New("Invalid response format")
	}

	for _, candidate := range candidates {
		candidateObj := candidate.(map[string]interface{})

		switch hashType {
		case MD5:
			if candidateObj["md5"].(string) == passwordHash {
				return true, nil
			}
		case SHA1:
			if candidateObj["sha1"].(string) == passwordHash {
				return true, nil
			}
		case SHA256:
			if candidateObj["sha256"].(string) == passwordHash {
				return true, nil
			}
		case NTLM:
			if candidateObj["ntlm"].(string) == passwordHash {
				return true, nil
			}
		}
	}

	return false, nil
}

// CheckPasswordWithExposure checks whether the password provided in the password parameter is in the Enzoic database of known,
// compromised passwords.  If so it will return true.  Also updates the revealedInExposures and exposureCount parameters
// with the results of the check, indicating if this is a password which is just weak (revealedInExposure false) or
// was actually exposed in a breach.  The exposureCount parameter will be set to the number of exposures it has been found
// in and can be used as a relative measure of the risk of the password.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/passwords-api
func (e *Client) CheckPasswordWithExposure(password string, revealedInExposure *bool, exposureCount *int) (bool, error) {
	md5, _ := calcMD5(password)
	sha1, _ := calcSHA1(password)
	sha256, _ := calcSHA256(password)

	params := url.Values{}
	params.Set("partial_md5", md5[:10])
	params.Set("partial_sha1", sha1[:10])
	params.Set("partial_sha256", sha256[:10])

	resp, body, err := e.makeRestCall("GET", passwordsAPIPath, params.Encode(), nil)
	if err != nil {
		return false, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	} else if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("Failed to check password: %s", resp.Status)
	}

	var responseObj map[string]interface{}
	err = json.Unmarshal(body, &responseObj)
	if err != nil {
		return false, err
	}

	candidates, ok := responseObj["candidates"].([]interface{})
	if !ok {
		return false, errors.New("Invalid response format")
	}

	for _, candidate := range candidates {
		candidateObj := candidate.(map[string]interface{})
		candidateMD5 := ""
		candidateSHA1 := ""
		candidateSHA256 := ""

		if candidateObj["md5"] != nil {
			candidateMD5 = candidateObj["md5"].(string)
		}
		if candidateObj["sha1"] != nil {
			candidateSHA1 = candidateObj["sha1"].(string)
		}
		if candidateObj["sha256"] != nil {
			candidateSHA256 = candidateObj["sha256"].(string)
		}

		if candidateMD5 == md5 || candidateSHA1 == sha1 || candidateSHA256 == sha256 {
			*revealedInExposure = candidateObj["revealedInExposure"].(bool)
			*exposureCount = int(candidateObj["exposureCount"].(float64))
			return true, nil
		}
	}

	return false, nil
}

// RetrieveCandidatesForPartialPasswordHash is a thin wrapper around the Passwords API call.
// This call is generally redundant with CheckPasswordHash in that it merely returns the hash candidates for the call rather than
// just checking for a match directly in the candidate list and returning a boolean.  In general, there is no reason to
// use this call unless you have a very specialized use case, as CheckPasswordHash can be used instead to simply
// check whether a given password hash is compromised.
//
// The partialPasswordHash parameter can be the first 7 characters of a hash in any of the formats supported
// by the Enzoic Passwords API (PasswordType.MD5, PasswordType.SHA1, PasswordType.SHA256 or PasswordType.NTLM).
// The passwordType parameter should be set to the type of partial hash being provided using the PasswordType enum.
//
// The function will return a list of candidate hashes that match the partial hash provided.
//
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/passwords-api
func (e *Client) RetrieveCandidatesForPartialPasswordHash(partialPasswordHash string, hashType PasswordType) ([]string, error) {
	var requestObject interface{}

	if hashType != MD5 && hashType != SHA1 && hashType != SHA256 && hashType != NTLM {
		return nil, errors.New("Invalid hash type.  Must be MD5, SHA1, SHA256 or NTLM")
	}

	if len(partialPasswordHash) < 7 {
		return nil, errors.New("Partial hash must be at least 7 characters")
	}

	switch hashType {
	case MD5:
		requestObject = struct {
			PartialMD5 string `json:"partialMD5"`
		}{
			PartialMD5: strings.ToLower(partialPasswordHash),
		}
	case SHA1:
		requestObject = struct {
			PartialSHA1 string `json:"partialSHA1"`
		}{
			PartialSHA1: strings.ToLower(partialPasswordHash),
		}
	case SHA256:
		requestObject = struct {
			PartialSHA256 string `json:"partialSHA256"`
		}{
			PartialSHA256: strings.ToLower(partialPasswordHash),
		}
	case NTLM:
		requestObject = struct {
			PartialNTLM string `json:"partialNTLM"`
		}{
			PartialNTLM: strings.ToLower(partialPasswordHash),
		}
	default:
		return nil, errors.New("Invalid hash type.  Must be MD5, SHA1, SHA256 or NTLM")
	}

	requestBody, err := json.Marshal(requestObject)
	if err != nil {
		return nil, err
	}

	resp, body, err := e.makeRestCall("POST", passwordsAPIPath, "", requestBody)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return make([]string, 0), nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to check password: %s", resp.Status)
	}

	var responseObj map[string]interface{}
	err = json.Unmarshal(body, &responseObj)
	if err != nil {
		return nil, err
	}

	candidates, ok := responseObj["candidates"].([]interface{})
	if !ok {
		return nil, errors.New("Invalid response format")
	}

	idx := 0
	results := make([]string, len(candidates))
	for _, candidate := range candidates {
		candidateObj := candidate.(map[string]interface{})

		switch hashType {
		case MD5:
			results[idx] = candidateObj["md5"].(string)
		case SHA1:
			results[idx] = candidateObj["sha1"].(string)
		case SHA256:
			results[idx] = candidateObj["sha256"].(string)
		case NTLM:
			results[idx] = candidateObj["ntlm"].(string)
		}
		idx++
	}

	return results, nil
}

// CheckCredentials checks whether the username/password provided in the parameters are in the Enzoic database of
// compromised user credentials.  If so, it will return true.
func (e *Client) CheckCredentials(username, password string) (bool, error) {
	return e.CheckCredentialsEx(username, password, nil, nil, false)
}

// CheckCredentialsEx checks whether the username/password provided in the parameters are in the Enzoic database of
// compromised user credentials.  If so, it will return true.  It also accepts the following parameters:
//
// lastCheckDate - if provided, the timestamp for the last check you performed for this user.  If the date/time you provide
// for the last check is greater than the timestamp Enzoic has for the last breach affecting this user, the check will
// not be performed.  This can be used to substantially increase performance.  Can be set to nil if no last check was performed
// or the credentials have changed since.
//
// excludeHashTypes - if provided, only credentials which do not include any of the specified hash types will be checked.
// By excluding computationally expensive PasswordTypes, such as BCrypt, it is possible to balance the performance of this
// call against security.  Can be set to empty array if you do not wish to exclude any hash types.
//
// useRawCredentials - if true, the Raw Credentials variant of the Credentials API.  The Raw Credentials version of
// the Credentials API allows you to check usernames and passwords for compromise without passing even a partial hash
// to Enzoic.  This works by pulling down all of the Credentials Hashes Enzoic has for a given username and
// calculating/comparing locally.  The only thing that gets passed to Enzoic in this case is a SHA-256 hash of
// the username.  Raw Credentials requires a separate approval to unlock.  If you're interested in getting
// approved, please contact us through our website.
func (e *Client) CheckCredentialsEx(username, password string, lastCheckDate *time.Time, excludeHashTypes []PasswordType, useRawCredentials bool) (bool, error) {
	usernameHash, _ := calcSHA256(strings.ToLower(username))

	params := url.Values{}
	params.Set("username", usernameHash)
	if useRawCredentials {
		params.Set("includeHashes", "1")
	}

	resp, body, err := e.makeRestCall("GET", accountsAPIPath, params.Encode(), nil)
	if err != nil {
		return false, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	} else if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("Failed to check credentials: %s", resp.Status)
	}

	var accountsResponse AccountsResponse
	err = json.Unmarshal(body, &accountsResponse)
	if err != nil {
		return false, err
	}

	if lastCheckDate != nil && !accountsResponse.LastBreachDate.IsZero() && lastCheckDate.After(accountsResponse.LastBreachDate) {
		return false, nil
	}

	if accountsResponse.CredentialsHashes != nil {
		bcryptCount := 0
		for _, credHashSpec := range accountsResponse.CredentialsHashes {
			hashSpec := PasswordHashSpecification{
				Salt:     credHashSpec.Salt,
				HashType: credHashSpec.HashType,
			}
			if excludeHashTypes != nil && containsPasswordType(excludeHashTypes, hashSpec.HashType) {
				continue
			}

			if hashSpec.HashType != BCrypt || bcryptCount <= 2 {
				if hashSpec.HashType == BCrypt {
					bcryptCount++
				}
				credentialHash := calcCredentialHash(username, password, accountsResponse.Salt, hashSpec)

				if credentialHash != nil && *credentialHash == credHashSpec.CredentialsHash {
					return true, nil
				}
			}
		}
	} else if accountsResponse.PasswordHashesRequired != nil {
		bcryptCount := 0
		var credentialHashes []string
		var queryString strings.Builder

		for _, hashSpec := range accountsResponse.PasswordHashesRequired {
			if excludeHashTypes != nil && containsPasswordType(excludeHashTypes, hashSpec.HashType) {
				continue
			}

			if hashSpec.HashType != BCrypt || bcryptCount <= 2 {
				if hashSpec.HashType == BCrypt {
					bcryptCount++
				}
				credentialHash := calcCredentialHash(username, password, accountsResponse.Salt, hashSpec)

				if credentialHash != nil {
					credentialHashes = append(credentialHashes, *credentialHash)
					if queryString.Len() == 0 {
						queryString.WriteString("?partialHashes=" + (*credentialHash)[:10])
					} else {
						queryString.WriteString("&partialHashes=" + (*credentialHash)[:10])
					}
				}
			}
		}

		if queryString.Len() > 0 {
			credsResp, credsBody, err := e.makeRestCall("GET", credentialsAPIPath, queryString.String(), nil)
			if err != nil {
				return false, err
			}

			if credsResp.StatusCode != http.StatusNotFound {
				var credsResponse map[string]interface{}
				err = json.Unmarshal(credsBody, &credsResponse)
				if err != nil {
					return false, err
				}

				candidateHashes, ok := credsResponse["candidateHashes"].([]interface{})
				if !ok {
					return false, errors.New("Invalid response format")
				}

				for _, candidate := range candidateHashes {
					candidateHash := candidate.(string)
					if containsString(credentialHashes, candidateHash) {
						return true, nil
					}
				}
			}
		}
	}

	return false, nil
}

// GetExposuresForUser returns all of the credentials Exposures that have been found for a given username.  The
// username will be hashed using SHA-256 before being passed to the Enzoic API.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-an-email-address
func (e *Client) GetExposuresForUser(username string) ([]string, error) {
	return e.GetExposuresForUserWithinDateRange(username, time.Time{}, time.Time{})
}

// GetExposuresForUserWithinDateRange returns all of the credentials Exposures that have been found for a given username within a specified range of dates.
// The username will be hashed using SHA-256 before being passed to the Enzoic API.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-an-email-address
func (e *Client) GetExposuresForUserWithinDateRange(username string, startDate time.Time, endDate time.Time) ([]string, error) {
	usernameHash, _ := calcSHA256(strings.ToLower(username))

	additionalParameters := ""
	if startDate != (time.Time{}) {
		additionalParameters += "&startDate=" + startDate.Format("2006-01-02T15:04:05Z")
	}
	if endDate != (time.Time{}) {
		additionalParameters += "&endDate=" + endDate.Format("2006-01-02T15:04:05Z")
	}
	resp, body, err := e.makeRestCall("GET", exposuresForUsernamesAPIPath, "username="+usernameHash+additionalParameters, nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return []string{}, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get exposures: %s", resp.Status)
	}

	var exposuresResponse ExposuresResponse
	err = json.Unmarshal(body, &exposuresResponse)
	if err != nil {
		return nil, err
	}

	return exposuresResponse.Exposures, nil
}

// GetExposedUsersForDomain returns a list of all users for a given email domain who have had credentials revealed in exposures.
// The results of this call are paginated.  pageSize can be any value from 1 to 1000.  If pageSize is not specified, the default is 1000.
// pagingToken is a value returned with each page of results and should be passed into this call to retrieve the next page of results.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-all-email-addresses-in-a-domain
func (e *Client) GetExposedUsersForDomain(domain string, pageSize int, pagingToken string) (*ExposedUsersForDomain, error) {
	return e.GetExposedUsersForDomainWithinDateRange(domain, time.Time{}, time.Time{}, pageSize, pagingToken)
}

// GetExposedUsersForDomainWithinDateRange returns a list of all users for a given email domain who have had credentials revealed in exposures,
// within a specified range of dates.
// The results of this call are paginated.  pageSize can be any value from 1 to 1000.  If pageSize is not specified, the default is 1000.
// pagingToken is a value returned with each page of results and should be passed into this call to retrieve the next page of results.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-all-email-addresses-in-a-domain
func (e *Client) GetExposedUsersForDomainWithinDateRange(domain string, startDate time.Time, endDate time.Time, pageSize int, pagingToken string) (*ExposedUsersForDomain, error) {
	params := url.Values{}
	params.Set("accountDomain", domain)
	if startDate != (time.Time{}) {
		params.Set("startDate", startDate.Format("2006-01-02T15:04:05Z"))
	}
	if endDate != (time.Time{}) {
		params.Set("endDate", endDate.Format("2006-01-02T15:04:05Z"))
	}
	if pageSize > 0 {
		params.Set("pageSize", strconv.Itoa(pageSize))
	}
	if pagingToken != "" {
		params.Set("pagingToken", pagingToken)
	}

	resp, body, err := e.makeRestCall("GET", exposuresForDomainUsersAPIPath, params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get exposures: %s", resp.Status)
	}

	var exposuresResponse ExposedUsersForDomain
	err = json.Unmarshal(body, &exposuresResponse)
	if err != nil {
		return nil, err
	}

	return &exposuresResponse, nil
}

// GetExposuresForDomain returns a list of all exposures found involving users with email addresses from a given domain.
// The result will be an array of exposure IDs which can be used with the GetExposureDetails call to retrieve details.
// The results of this call are paginated.  pageSize can be any value from 1 to 500.  If pageSize is not specified, the default is 100.
// pagingToken is a value returned with each page of results and should be passed into this call to retrieve the next page of results.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-a-domain
func (e *Client) GetExposuresForDomain(domain string, pageSize int, pagingToken string) (*ExposuresForDomain, error) {
	return e.GetExposuresForDomainWithinDateRange(domain, time.Time{}, time.Time{}, pageSize, pagingToken)
}

// GetExposuresForDomainWithinDateRange returns a list of all exposures found involving users with email addresses from a given domain,
// within a given date range.
// The result will be an array of exposure IDs which can be used with the GetExposureDetails call to retrieve details.
// The results of this call are paginated.  pageSize can be any value from 1 to 500.  If pageSize is not specified, the default is 100.
// pagingToken is a value returned with each page of results and should be passed into this call to retrieve the next page of results.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-a-domain
func (e *Client) GetExposuresForDomainWithinDateRange(domain string, startDate time.Time, endDate time.Time, pageSize int, pagingToken string) (*ExposuresForDomain, error) {
	params := url.Values{}
	params.Set("domain", domain)
	if startDate != (time.Time{}) {
		params.Set("startDate", startDate.Format("2006-01-02T15:04:05Z"))
	}
	if endDate != (time.Time{}) {
		params.Set("endDate", endDate.Format("2006-01-02T15:04:05Z"))
	}
	if pageSize > 0 {
		params.Set("pageSize", strconv.Itoa(pageSize))
	}
	if pagingToken != "" {
		params.Set("pagingToken", pagingToken)
	}

	resp, body, err := e.makeRestCall("GET", exposuresForDomainAPIPath, params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return &ExposuresForDomain{Count: 0, Exposures: []string{}, PagingToken: ""}, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get exposures: %s", resp.Status)
	}

	var exposuresResponse ExposuresForDomain
	err = json.Unmarshal(body, &exposuresResponse)
	if err != nil {
		return nil, err
	}

	return &exposuresResponse, nil
}

// GetExposuresForDomainIncludeDetails returns a list of all exposures found involving users with email addresses from a given domain
// with the details for each exposure included inline in the response.
// The results of this call are paginated.  pageSize can be any value from 1 to 500.  If pageSize is not specified, the default is 100.
// pagingToken is a value returned with each page of results and should be passed into this call to retrieve the next page of results.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-a-domain
func (e *Client) GetExposuresForDomainIncludeDetails(domain string, pageSize int, pagingToken string) (*ExposuresForDomainIncludeDetails, error) {
	return e.GetExposuresForDomainWithinDateRangeIncludeDetails(domain, time.Time{}, time.Time{}, pageSize, pagingToken)
}

// GetExposuresForDomainWithinDateRangeIncludeDetails returns a list of all exposures found involving users with email addresses from a given domain
// within a date range, with the details for each exposure included inline in the response.
// The results of this call are paginated.  pageSize can be any value from 1 to 500.  If pageSize is not specified, the default is 100.
// pagingToken is a value returned with each page of results and should be passed into this call to retrieve the next page of results.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-a-domain
func (e *Client) GetExposuresForDomainWithinDateRangeIncludeDetails(domain string, startDate time.Time, endDate time.Time, pageSize int, pagingToken string) (*ExposuresForDomainIncludeDetails, error) {
	params := url.Values{}
	params.Set("domain", domain)
	params.Set("includeExposureDetails", "1")
	if startDate != (time.Time{}) {
		params.Set("startDate", startDate.Format("2006-01-02T15:04:05Z"))
	}
	if endDate != (time.Time{}) {
		params.Set("endDate", endDate.Format("2006-01-02T15:04:05Z"))
	}
	if pageSize > 0 {
		params.Set("pageSize", strconv.Itoa(pageSize))
	}
	if pagingToken != "" {
		params.Set("pagingToken", pagingToken)
	}

	resp, body, err := e.makeRestCall("GET", exposuresForDomainAPIPath, params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return &ExposuresForDomainIncludeDetails{Count: 0, Exposures: []ExposureDetails{}, PagingToken: ""}, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get exposures: %s", resp.Status)
	}

	var exposuresResponse ExposuresForDomainIncludeDetails
	err = json.Unmarshal(body, &exposuresResponse)
	if err != nil {
		return nil, err
	}

	return &exposuresResponse, nil
}

// GetExposureDetails returns the detailed information for a credentials Exposure.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/retrieve-details-for-an-exposure
func (e *Client) GetExposureDetails(exposureID string) (*ExposureDetails, error) {
	resp, body, err := e.makeRestCall("GET", exposureDetailsAPIPath, "?id="+exposureID, nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get exposure details: %s", resp.Status)
	}

	var exposureDetails ExposureDetails
	err = json.Unmarshal(body, &exposureDetails)
	if err != nil {
		return nil, err
	}

	return &exposureDetails, nil
}

// GetUserPasswords returns a list of passwords that Enzoic has found for a specific user.  This call must be enabled
// for your account or you will receive a 403 rejection when attempting to call it.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/credentials-api/cleartext-credentials-api
func (e *Client) GetUserPasswords(username string) (*UserPasswords, error) {
	usernameHash, _ := calcSHA256(username)
	resp, body, err := e.makeRestCall("GET", cleartextCredentialsAPIPath, "username="+usernameHash+"&includePasswords=1", nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		// User not found in the database
		return nil, nil
	} else if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("Call was rejected for the following reason: %s", body)
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get user passwords: %s", resp.Status)
	}

	var result UserPasswords
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetUserPasswordsUsingPartialHash returns a list of passwords that Enzoic has found for a specific user.  This call must be enabled
// for your account or you will receive a 403 rejection when attempting to call it.
// NOTE: THIS VARIANT OF THE CALL CAN BE USED TO PASS A PARTIAL SHA-256 HASH OF THE USERNAME RATHER THAN THE FULL HASH.
// We do not recommend using this variant unless you have compliance requirements that prevent you from passing even
// a hash of a user's email address to a 3rd party, as it will not perform as well as GetUserPasswords, which passes the
// exact hash.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/credentials-api/cleartext-credentials-api
func (e *Client) GetUserPasswordsUsingPartialHash(username string) (*UserPasswords, error) {
	usernameHash, _ := calcSHA256(username)
	partialUsernameHash := usernameHash[0:8]
	resp, body, err := e.makeRestCall("GET", cleartextCredentialsByPartialHashAPIPath, "partialUsernameHash="+partialUsernameHash+"&includePasswords=1", nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		// User not found in the database
		return nil, nil
	} else if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("Call was rejected for the following reason: %s", body)
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get user passwords: %s", resp.Status)
	}

	var candidates UserPasswordsCandidatesFromUsingPartialHash
	err = json.Unmarshal(body, &candidates)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(candidates.Candidates); i++ {
		if candidates.Candidates[i].UsernameHash == usernameHash {
			return &candidates.Candidates[i].UserPasswords, nil
		}
	}

	return nil, nil
}

// Deprecated: GetUserPasswordsWithExposureDetails IS DEPRECATED DUE TO SEVERE PERFORMANCE ISSUES AND WILL BE REMOVED IN A FUTURE RELEASE.
// INSTEAD, USE GetUserPasswords AND LOOKUP EXPOSURE DETAILS AS NECESSARY USING GetExposureDetails.
// GetUserPasswordsWithExposureDetails returns a list of passwords that Enzoic has found for a specific user.  This call must be enabled
// for your account or you will receive a 403 rejection when attempting to call it.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/credentials-api/cleartext-credentials-api
func (e *Client) GetUserPasswordsWithExposureDetails(username string) (*UserPasswordsWithExposureDetails, error) {
	usernameHash, _ := calcSHA256(username)
	resp, body, err := e.makeRestCall("GET", cleartextCredentialsAPIPath, "username="+usernameHash+"&includePasswords=1&includeExposureDetails=1", nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		// User not found in the database
		return nil, nil
	} else if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("Call was rejected for the following reason: %s", body)
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get user passwords: %s", resp.Status)
	}

	var result UserPasswordsWithExposureDetails
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetUserPasswordsByDomain returns a paginated list of credentials in the Enzoic database for all users under a given
// email domain.  This variant of the call takes a domain (e.g. enzoic.com) and returns a list of emails and recovered
// passwords for any email address we've found credentials for in that domain.  This call must be enabled
// for your account or you will receive a 403 rejection when attempting to call it.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/credentials-api/cleartext-credentials-api#cleartext-credentials-by-domain
func (e *Client) GetUserPasswordsByDomain(domain string, pageSize int, pagingToken string) (*UserPasswordsByDomainResponse, error) {
	params := url.Values{}
	if domain != "" {
		params.Set("domain", domain)
	}
	if pageSize > 0 {
		params.Set("pageSize", strconv.Itoa(pageSize))
	}
	if pagingToken != "" {
		params.Set("pagingToken", pagingToken)
	}

	resp, body, err := e.makeRestCall("GET", cleartextCredentialsByDomain, params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		// User not found in the database
		return nil, nil
	} else if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("Call was rejected for the following reason: %s", body)
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get user passwords: %s", resp.Status)
	}

	var result UserPasswordsByDomainResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// AddUserAlertSubscriptions takes an array of email addresses and adds them to the list of users your account monitors
// for new credentials exposures.  The customData parameter can optionally be used with any string value to tag the
// new subscription items with a custom value.  This value will be sent to your webhook when a new alert is found for
// one of these users and can also be used to lookup or delete entries.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#add-breach-alert-subscriptions
func (e *Client) AddUserAlertSubscriptions(usernames []string, customData string) (*AddSubscriptionsResponse, error) {
	usernameHashes := hashUsernameList(usernames)

	var requestObject interface{}
	if customData != "" {
		requestObject = struct {
			UsernameHashes []string `json:"usernameHashes"`
			CustomData     string   `json:"customData"`
		}{
			UsernameHashes: usernameHashes,
			CustomData:     customData,
		}
	} else {
		requestObject = struct {
			UsernameHashes []string `json:"usernameHashes"`
		}{
			UsernameHashes: usernameHashes,
		}
	}

	requestBody, err := json.Marshal(requestObject)
	if err != nil {
		return nil, err
	}

	resp, body, err := e.makeRestCall("POST", breachMonitoringForUsersAPIPath, "", requestBody)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("Failed to add alert subscriptions: %s", resp.Status)
	}

	var result AddSubscriptionsResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// AddUserAlertSubscriptionsWithSpecifiedWebhook takes an array of email addresses and adds them to the list of users your account monitors
// for new credentials exposures.  The customData parameter can optionally be used with any string value to tag the
// new subscription items with a custom value.  This value will be sent to your webhook when a new alert is found for
// one of these users and can also be used to lookup or delete entries.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#add-breach-alert-subscriptions
func (e *Client) AddUserAlertSubscriptionsWithSpecifiedWebhook(usernames []string, customData string, webhookID string) (*AddSubscriptionsResponse, error) {
	usernameHashes := hashUsernameList(usernames)

	var requestObject interface{}
	if customData != "" {
		requestObject = struct {
			UsernameHashes []string `json:"usernameHashes"`
			CustomData     string   `json:"customData"`
			WebhookID      string   `json:"webhookID"`
		}{
			UsernameHashes: usernameHashes,
			CustomData:     customData,
			WebhookID:      webhookID,
		}
	} else {
		requestObject = struct {
			UsernameHashes []string `json:"usernameHashes"`
			WebhookID      string   `json:"webhookID"`
		}{
			UsernameHashes: usernameHashes,
			WebhookID:      webhookID,
		}
	}

	requestBody, err := json.Marshal(requestObject)
	if err != nil {
		return nil, err
	}

	resp, body, err := e.makeRestCall("POST", breachMonitoringForUsersAPIPath, "", requestBody)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("Failed to add alert subscriptions: %s", resp.Status)
	}

	var result AddSubscriptionsResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteUserAlertSubscriptions takes an array of email addresses you wish to remove from monitoring for new credentials
// exposures.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#remove-breach-alert-subscriptions
func (e *Client) DeleteUserAlertSubscriptions(usernames []string) (*DeleteSubscriptionsResponse, error) {
	var requestObject interface{}
	requestObject = struct {
		UsernameHashes []string `json:"usernameHashes"`
	}{
		UsernameHashes: hashUsernameList(usernames),
	}

	requestBody, err := json.Marshal(requestObject)
	if err != nil {
		return nil, err
	}

	resp, body, err := e.makeRestCall("DELETE", breachMonitoringForUsersAPIPath, "", requestBody)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to delete alert subscriptions: %s", resp.Status)
	}

	var result DeleteSubscriptionsResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteUserAlertSubscriptions takes a customData value and deletes all alert subscriptions that have that value.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#remove-breach-alert-subscriptions
func (e *Client) DeleteUserAlertSubscriptionsByCustomData(customData string) (*DeleteSubscriptionsResponse, error) {
	var requestObject interface{}
	requestObject = struct {
		CustomData string `json:"usernameCustomData"`
	}{
		CustomData: customData,
	}

	requestBody, err := json.Marshal(requestObject)
	if err != nil {
		return nil, err
	}

	resp, body, err := e.makeRestCall("DELETE", breachMonitoringForUsersAPIPath, "", requestBody)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to delete alert subscriptions: %s", resp.Status)
	}

	var result DeleteSubscriptionsResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetUserAlertSubscriptions returns a list of all the users your account is monitoring for new credentials exposures.
// The results of this call are paginated.  pageSize can be any value from 1 to 1000.  If pageSize is not specified, the default is 1000.
// pagingToken is a value returned with each page of results and should be passed into this call to retrieve the next page of results.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#retrieve-current-breach-alert-subscriptions
func (e *Client) GetUserAlertSubscriptions(pageSize int, pagingToken string) (*GetSubscriptionsResponse, error) {
	return e.GetUserAlertSubscriptionsByCustomData("", pageSize, pagingToken)
}

// GetUserAlertSubscriptionsWithExtendedInfo returns a list of all the users your account is monitoring for new credentials exposures,
// along with extended information such as the Webhook that will be called for each and custom data string for each.
// The results of this call are paginated.  pageSize can be any value from 1 to 1000.  If pageSize is not specified, the default is 1000.
// pagingToken is a value returned with each page of results and should be passed into this call to retrieve the next page of results.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#retrieve-current-breach-alert-subscriptions
func (e *Client) GetUserAlertSubscriptionsWithExtendedInfo(pageSize int, pagingToken string) (*GetSubscriptionsWithExtendedInfoResponse, error) {
	return e.GetUserAlertSubscriptionsByCustomDataWithExtendedInfo("", pageSize, pagingToken)
}

// GetUserAlertSubscriptionsByCustomData returns a list of all the users your account is monitoring for new credentials exposures with
// the provided customData value.
// The results of this call are paginated.  pageSize can be any value from 1 to 1000.  If pageSize is not specified, the default is 1000.
// pagingToken is a value returned with each page of results and should be passed into this call to retrieve the next page of results.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#retrieve-current-breach-alert-subscriptions
func (e *Client) GetUserAlertSubscriptionsByCustomData(customData string, pageSize int, pagingToken string) (*GetSubscriptionsResponse, error) {
	params := url.Values{}
	if customData != "" {
		params.Set("usernameCustomData", customData)
	}
	if pageSize > 0 {
		params.Set("pageSize", strconv.Itoa(pageSize))
	}
	if pagingToken != "" {
		params.Set("pagingToken", pagingToken)
	}

	resp, body, err := e.makeRestCall("GET", breachMonitoringForUsersAPIPath, params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return &GetSubscriptionsResponse{Count: 0, UsernameHashes: []string{}, PagingToken: ""}, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get exposures: %s", resp.Status)
	}

	var subscriptionsResponse GetSubscriptionsResponse
	err = json.Unmarshal(body, &subscriptionsResponse)
	if err != nil {
		return nil, err
	}

	return &subscriptionsResponse, nil
}

// GetUserAlertSubscriptionsByCustomDataWithExtendedInfo returns a list of all the users your account is monitoring for new credentials exposures with
// the provided customData value, along with extended information such as the Webhook that will be called for each and custom data string for each.
// The results of this call are paginated.  pageSize can be any value from 1 to 1000.  If pageSize is not specified, the default is 1000.
// pagingToken is a value returned with each page of results and should be passed into this call to retrieve the next page of results.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#retrieve-current-breach-alert-subscriptions
func (e *Client) GetUserAlertSubscriptionsByCustomDataWithExtendedInfo(customData string, pageSize int, pagingToken string) (*GetSubscriptionsWithExtendedInfoResponse, error) {
	params := url.Values{}
	if customData != "" {
		params.Set("usernameCustomData", customData)
	}
	if pageSize > 0 {
		params.Set("pageSize", strconv.Itoa(pageSize))
	}
	if pagingToken != "" {
		params.Set("pagingToken", pagingToken)
	}
	params.Set("includeExtendedInfo", "1")

	resp, body, err := e.makeRestCall("GET", breachMonitoringForUsersAPIPath, params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return &GetSubscriptionsWithExtendedInfoResponse{Count: 0, UsernameHashes: []UsernameHashWithExtendedInfo{}, PagingToken: ""}, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get subscriptions: %s", resp.Status)
	}

	var subscriptionsResponse GetSubscriptionsWithExtendedInfoResponse
	err = json.Unmarshal(body, &subscriptionsResponse)
	if err != nil {
		return nil, err
	}

	return &subscriptionsResponse, nil
}

// IsUserSubscribedForAlerts takes a username and returns true if the user is subscribed for alerts, false otherwise.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#retrieve-current-breach-alert-subscriptions
func (e *Client) IsUserSubscribedForAlerts(username string) (bool, error) {
	usernameHash, _ := calcSHA256(username)
	resp, _, err := e.makeRestCall("GET", breachMonitoringForUsersAPIPath, "usernameHash="+usernameHash, nil)
	if err != nil {
		return false, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	} else if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("Failed to check subscription status: %s", resp.Status)
	} else {
		return true, nil
	}
}

// AddDomainAlertSubscriptions takes an array of domains (e.g. enzoic.com) and adds them to the list of domains your account monitors
// for new credentials exposures.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#add-breach-alert-subscriptions
func (e *Client) AddDomainAlertSubscriptions(domains []string) (*AddSubscriptionsResponse, error) {
	requestObject := struct {
		Domains []string `json:"domains"`
	}{
		Domains: domains,
	}

	return callAddDomainAlertSubscription(e, requestObject)
}

// AddDomainAlertSubscriptionsWithCustomData takes an array of domains (e.g. enzoic.com) and adds them to the list of domains your account monitors
// for new credentials exposures, along with a customData parameter to later identify them.
// The customData parameter is typically used to store an ID value that uniquely identifies the monitored domain(s) in your
// system.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#add-breach-alert-subscriptions
func (e *Client) AddDomainAlertSubscriptionsWithCustomData(domains []string, customData string) (*AddSubscriptionsResponse, error) {
	requestObject := struct {
		Domains    []string `json:"domains"`
		CustomData string   `json:"customData"`
	}{
		Domains:    domains,
		CustomData: customData,
	}

	return callAddDomainAlertSubscription(e, requestObject)
}

// AddDomainAlertSubscriptionsWithSpecifiedWebhook takes an array of domains (e.g. enzoic.com) and adds them to the
// list of domains your account monitors for new credentials exposures.
// This variant of the call allows you to specify a webhook ID to send alerts to, if you
// have multiple webhooks configured and wish to send alerts for these domains to one other than the default.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#add-breach-alert-subscriptions
func (e *Client) AddDomainAlertSubscriptionsWithSpecifiedWebhook(domains []string, webhookID string) (*AddSubscriptionsResponse, error) {
	requestObject := struct {
		Domains   []string `json:"domains"`
		WebhookID string   `json:"webhookID"`
	}{
		Domains:   domains,
		WebhookID: webhookID,
	}

	return callAddDomainAlertSubscription(e, requestObject)
}

// AddDomainAlertSubscriptionsWithSpecifiedWebhookAndCustomData takes an array of domains (e.g. enzoic.com) and adds them to the
// list of domains your account monitors for new credentials exposures, along with a customData parameter to later identify them.
// The customData parameter is typically used to store an ID value that uniquely identifies the monitored domain(s) in your
// system.
// This variant of the call allows you to specify a webhook ID to send alerts to, if you
// have multiple webhooks configured and wish to send alerts for these domains to one other than the default.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#add-breach-alert-subscriptions
func (e *Client) AddDomainAlertSubscriptionsWithSpecifiedWebhookAndCustomData(domains []string, webhookID string, customData string) (*AddSubscriptionsResponse, error) {
	requestObject := struct {
		Domains    []string `json:"domains"`
		WebhookID  string   `json:"webhookID"`
		CustomData string   `json:"customData"`
	}{
		Domains:    domains,
		WebhookID:  webhookID,
		CustomData: customData,
	}

	return callAddDomainAlertSubscription(e, requestObject)
}

// DeleteDomainAlertSubscriptions takes an array of domains you wish to remove from monitoring for new credentials exposures.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#remove-breach-alert-subscriptions
func (e *Client) DeleteDomainAlertSubscriptions(domains []string) (*DeleteSubscriptionsResponse, error) {
	requestObject := struct {
		Domains []string `json:"domains"`
	}{
		Domains: domains,
	}

	requestBody, err := json.Marshal(requestObject)
	if err != nil {
		return nil, err
	}

	resp, body, err := e.makeRestCall("DELETE", breachMonitoringForDomainsAPIPath, "", requestBody)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to delete alert subscriptions: %s", resp.Status)
	}

	var result DeleteSubscriptionsResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteDomainAlertSubscriptionsByCustomData takes a customData string that was used when adding domains for monitoring
// and deletes any subscribed domains that have that customData value.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#remove-breach-alert-subscriptions
func (e *Client) DeleteDomainAlertSubscriptionsByCustomData(customData string) (*DeleteSubscriptionsResponse, error) {
	requestObject := struct {
		CustomData string `json:"customData"`
	}{
		CustomData: customData,
	}

	requestBody, err := json.Marshal(requestObject)
	if err != nil {
		return nil, err
	}

	resp, body, err := e.makeRestCall("DELETE", breachMonitoringForDomainsAPIPath, "", requestBody)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to delete alert subscriptions: %s", resp.Status)
	}

	var result DeleteSubscriptionsResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetDomainAlertSubscriptions returns a list of all the domains your account is monitoring for new credentials exposures.
// The results of this call are paginated.  pageSize can be any value from 1 to 1000.  If pageSize is not specified, the default is 1000.
// pagingToken is a value returned with each page of results and should be passed into this call to retrieve the next page of results.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#retrieve-current-breach-alert-subscriptions
func (e *Client) GetDomainAlertSubscriptions(pageSize int, pagingToken string) (*GetDomainSubscriptionsResponse, error) {
	params := url.Values{}
	params.Set("domains", "1")
	if pageSize > 0 {
		params.Set("pageSize", strconv.Itoa(pageSize))
	}
	if pagingToken != "" {
		params.Set("pagingToken", pagingToken)
	}

	resp, body, err := e.makeRestCall("GET", breachMonitoringForDomainsAPIPath, params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return &GetDomainSubscriptionsResponse{Count: 0, Domains: []string{}, PagingToken: ""}, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get exposures: %s", resp.Status)
	}

	var subscriptionsResponse GetDomainSubscriptionsResponse
	err = json.Unmarshal(body, &subscriptionsResponse)
	if err != nil {
		return nil, err
	}

	return &subscriptionsResponse, nil
}

// GetDomainAlertSubscriptionsWithExtendedInfo returns a list of all the domains your account is monitoring for new credentials exposures,
// along with extended information such as the Webhook that will be called for each.
// The results of this call are paginated.  pageSize can be any value from 1 to 1000.  If pageSize is not specified, the default is 1000.
// pagingToken is a value returned with each page of results and should be passed into this call to retrieve the next page of results.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#retrieve-current-breach-alert-subscriptions
func (e *Client) GetDomainAlertSubscriptionsWithExtendedInfo(pageSize int, pagingToken string) (*GetDomainSubscriptionsWithExtendedInfoResponse, error) {
	params := url.Values{}
	params.Set("domains", "1")
	if pageSize > 0 {
		params.Set("pageSize", strconv.Itoa(pageSize))
	}
	if pagingToken != "" {
		params.Set("pagingToken", pagingToken)
	}
	params.Set("includeWebhookInfo", "1")

	resp, body, err := e.makeRestCall("GET", breachMonitoringForDomainsAPIPath, params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return &GetDomainSubscriptionsWithExtendedInfoResponse{Count: 0, Domains: []DomainWithExtendedInfo{}, PagingToken: ""}, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get subscriptions: %s", resp.Status)
	}

	var subscriptionsResponse GetDomainSubscriptionsWithExtendedInfoResponse
	err = json.Unmarshal(body, &subscriptionsResponse)
	if err != nil {
		return nil, err
	}

	return &subscriptionsResponse, nil
}

// GetDomainAlertSubscriptionsWithExtendedInfoByCustomData returns a list of all the domains your account is monitoring for new credentials exposures that match a customData value,
// along with extended information such as the Webhook that will be called for each.
// The results of this call are paginated.  pageSize can be any value from 1 to 1000.  If pageSize is not specified, the default is 1000.
// pagingToken is a value returned with each page of results and should be passed into this call to retrieve the next page of results.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#retrieve-current-breach-alert-subscriptions
func (e *Client) GetDomainAlertSubscriptionsByCustomData(customData string, pageSize int, pagingToken string) (*GetDomainSubscriptionsWithExtendedInfoResponse, error) {
	params := url.Values{}
	params.Set("customData", customData)
	if pageSize > 0 {
		params.Set("pageSize", strconv.Itoa(pageSize))
	}
	if pagingToken != "" {
		params.Set("pagingToken", pagingToken)
	}
	params.Set("includeWebhookInfo", "1")

	resp, body, err := e.makeRestCall("GET", breachMonitoringForDomainsAPIPath, params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return &GetDomainSubscriptionsWithExtendedInfoResponse{Count: 0, Domains: []DomainWithExtendedInfo{}, PagingToken: ""}, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get subscriptions: %s", resp.Status)
	}

	var subscriptionsResponse GetDomainSubscriptionsWithExtendedInfoResponse
	err = json.Unmarshal(body, &subscriptionsResponse)
	if err != nil {
		return nil, err
	}

	return &subscriptionsResponse, nil
}

// IsDomainSubscribedForAlerts takes a domain and returns true if the domain is subscribed for alerts, false otherwise.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#retrieve-current-breach-alert-subscriptions
func (e *Client) IsDomainSubscribedForAlerts(domain string) (bool, error) {
	resp, _, err := e.makeRestCall("GET", breachMonitoringForDomainsAPIPath, "domain="+domain, nil)
	if err != nil {
		return false, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	} else if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("Failed to check subscription status: %s", resp.Status)
	} else {
		return true, nil
	}
}

func containsPasswordType(types []PasswordType, t PasswordType) bool {
	for _, passwordType := range types {
		if passwordType == t {
			return true
		}
	}
	return false
}

func calcCredentialHash(username, password, salt string, spec PasswordHashSpecification) *string {
	passwordHash, _ := CalcPasswordHash(spec.HashType, password, spec.Salt)
	if passwordHash != "" {
		argon2Hash, _ := calcArgon2(fmt.Sprintf("%s$%s", username, passwordHash), salt)
		hash := argon2Hash[strings.LastIndex(argon2Hash, "$")+1:]
		return &hash
	}
	return nil
}

func containsString(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func hashUsernameList(usernames []string) []string {
	var usernameHashes []string
	for _, username := range usernames {
		usernameHash, _ := calcSHA256(username)
		usernameHashes = append(usernameHashes, usernameHash)
	}
	return usernameHashes
}

func (e *Client) makeRestCall(method, endpoint string, params string, body []byte) (*http.Response, []byte, error) {
	apiUrl := ""
	if params != "" && strings.Index(params, "?") == 0 {
		apiUrl = fmt.Sprintf("%s%s%s", e.baseURL, endpoint, params)
	} else {
		apiUrl = fmt.Sprintf("%s%s?%s", e.baseURL, endpoint, params)
	}

	req, err := http.NewRequest(method, apiUrl, strings.NewReader(string(body)))
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Authorization", e.authString)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.HttpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	responseBody, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, nil, err
	}

	return resp, responseBody, nil
}

func callAddDomainAlertSubscription[T any](client *Client, requestObject T) (*AddSubscriptionsResponse, error) {
	requestBody, err := json.Marshal(requestObject)
	if err != nil {
		return nil, err
	}

	resp, body, err := client.makeRestCall("POST", breachMonitoringForDomainsAPIPath, "", requestBody)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("Failed to add alert subscriptions: %s", resp.Status)
	}

	var result AddSubscriptionsResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}
