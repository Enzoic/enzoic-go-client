package enzoic

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	CredentialsAPIPath = "/credentials"
	PasswordsAPIPath   = "/passwords"
	ExposuresAPIPath   = "/exposures"
	AccountsAPIPath    = "/accounts"
	AlertsServicePath  = "/alert-subscriptions"
)

type Client struct {
	apiKey     string
	secret     string
	authString string
	baseURL    string
	httpClient *http.Client
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
	enzoic := &Client{
		apiKey:     apiKey,
		secret:     secret,
		authString: "basic " + base64.StdEncoding.EncodeToString([]byte(apiKey+":"+secret)),
		baseURL:    apiBaseURL,
		httpClient: client,
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

// CheckPasswordWithExposure checks whether the password provided in the password parameter is in the Enzoic database of known,
// compromised passwords.  If so it will return true.  Also updates the revealedInExposures and exposureCount parameters
// with the results of the check, indicating if this is a password which is just weak (revealedInExposure false) or
// was actually exposed in a breach.  The exposureCount parameter will be set to the number of exposures it has been found
// in and can be used as a relative measure of the risk of the password.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/passwords-api
func (e *Client) CheckPasswordWithExposure(password string, revealedInExposure *bool, exposureCount *int) (bool, error) {
	md5, _ := CalcMD5(password)
	sha1, _ := CalcSHA1(password)
	sha256, _ := CalcSHA256(password)

	params := url.Values{}
	params.Set("partial_md5", md5[:10])
	params.Set("partial_sha1", sha1[:10])
	params.Set("partial_sha256", sha256[:10])

	//apiUrl := fmt.Sprintf("%s%s?%s", e.baseURL, PasswordsAPIPath, params.Encode())
	resp, err := e.makeRestCall("GET", PasswordsAPIPath, params.Encode(), nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	} else if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("Failed to check password: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
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
		candidateMD5 := candidateObj["md5"].(string)
		candidateSHA1 := candidateObj["sha1"].(string)
		candidateSHA256 := candidateObj["sha256"].(string)

		if candidateMD5 == md5 || candidateSHA1 == sha1 || candidateSHA256 == sha256 {
			*revealedInExposure = candidateObj["revealedInExposure"].(bool)
			*exposureCount = int(candidateObj["exposureCount"].(float64))
			return true, nil
		}
	}

	return false, nil
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
	usernameHash, _ := CalcSHA256(strings.ToLower(username))

	params := url.Values{}
	params.Set("username", usernameHash)
	if useRawCredentials {
		params.Set("includeHashes", "1")
	}

	resp, err := e.makeRestCall("GET", AccountsAPIPath, params.Encode(), nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	} else if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("Failed to check credentials: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
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
			credsResp, err := e.makeRestCall("GET", CredentialsAPIPath, queryString.String(), nil)
			if err != nil {
				return false, err
			}
			defer credsResp.Body.Close()

			if credsResp.StatusCode != http.StatusNotFound {
				credsBody, err := ioutil.ReadAll(credsResp.Body)
				if err != nil {
					return false, err
				}

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
	usernameHash, _ := CalcSHA256(strings.ToLower(username))

	resp, err := e.makeRestCall("GET", ExposuresAPIPath, "username="+usernameHash, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []string{}, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get exposures: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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
	params := url.Values{}
	params.Set("accountDomain", domain)
	if pageSize > 0 {
		params.Set("pageSize", strconv.Itoa(pageSize))
	}
	if pagingToken != "" {
		params.Set("pagingToken", pagingToken)
	}

	resp, err := e.makeRestCall("GET", ExposuresAPIPath, params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get exposures: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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
	params := url.Values{}
	params.Set("domain", domain)
	if pageSize > 0 {
		params.Set("pageSize", strconv.Itoa(pageSize))
	}
	if pagingToken != "" {
		params.Set("pagingToken", pagingToken)
	}

	resp, err := e.makeRestCall("GET", ExposuresAPIPath, params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &ExposuresForDomain{Count: 0, Exposures: []string{}, PagingToken: ""}, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get exposures: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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
	params := url.Values{}
	params.Set("domain", domain)
	params.Set("includeExposureDetails", "1")
	if pageSize > 0 {
		params.Set("pageSize", strconv.Itoa(pageSize))
	}
	if pagingToken != "" {
		params.Set("pagingToken", pagingToken)
	}

	resp, err := e.makeRestCall("GET", ExposuresAPIPath, params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &ExposuresForDomainIncludeDetails{Count: 0, Exposures: []ExposureDetails{}, PagingToken: ""}, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get exposures: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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
	resp, err := e.makeRestCall("GET", ExposuresAPIPath, "?id="+exposureID, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get exposure details: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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
	usernameHash, _ := CalcSHA256(username)
	resp, err := e.makeRestCall("GET", AccountsAPIPath, "username="+usernameHash+"&includePasswords=1", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// User not found in the database
		return nil, nil
	} else if resp.StatusCode == http.StatusForbidden {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("Call was rejected for the following reason: %s", body)
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get user passwords: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result UserPasswords
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

	resp, err := e.makeRestCall("POST", AlertsServicePath, "", requestBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("Failed to add alert subscriptions: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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

	resp, err := e.makeRestCall("DELETE", AlertsServicePath, "", requestBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to delete alert subscriptions: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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

	resp, err := e.makeRestCall("DELETE", AlertsServicePath, "", requestBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to delete alert subscriptions: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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

	resp, err := e.makeRestCall("GET", AlertsServicePath, params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &GetSubscriptionsResponse{Count: 0, UsernameHashes: []string{}, PagingToken: ""}, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get exposures: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var subscriptionsResponse GetSubscriptionsResponse
	err = json.Unmarshal(body, &subscriptionsResponse)
	if err != nil {
		return nil, err
	}

	return &subscriptionsResponse, nil
}

// IsUserSubscribedForAlerts takes a username and returns true if the user is subscribed for alerts, false otherwise.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#retrieve-current-breach-alert-subscriptions
func (e *Client) IsUserSubscribedForAlerts(username string) (bool, error) {
	usernameHash, _ := CalcSHA256(username)
	resp, err := e.makeRestCall("GET", AlertsServicePath, "usernameHash="+usernameHash, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

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

	requestBody, err := json.Marshal(requestObject)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRestCall("POST", AlertsServicePath, "", requestBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("Failed to add alert subscriptions: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result AddSubscriptionsResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
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

	resp, err := e.makeRestCall("DELETE", AlertsServicePath, "", requestBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to delete alert subscriptions: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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

	resp, err := e.makeRestCall("GET", AlertsServicePath, params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &GetDomainSubscriptionsResponse{Count: 0, Domains: []string{}, PagingToken: ""}, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get exposures: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var subscriptionsResponse GetDomainSubscriptionsResponse
	err = json.Unmarshal(body, &subscriptionsResponse)
	if err != nil {
		return nil, err
	}

	return &subscriptionsResponse, nil
}

// IsDomainSubscribedForAlerts takes a domain and returns true if the domain is subscribed for alerts, false otherwise.
// see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#retrieve-current-breach-alert-subscriptions
func (e *Client) IsDomainSubscribedForAlerts(domain string) (bool, error) {
	resp, err := e.makeRestCall("GET", AlertsServicePath, "domain="+domain, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

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
		argon2Hash, _ := CalcArgon2(fmt.Sprintf("%s$%s", username, passwordHash), salt)
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
		usernameHash, _ := CalcSHA256(username)
		usernameHashes = append(usernameHashes, usernameHash)
	}
	return usernameHashes
}

func (e *Client) makeRestCall(method, endpoint string, params string, body []byte) (*http.Response, error) {
	apiUrl := ""
	if params != "" && strings.Index(params, "?") == 0 {
		apiUrl = fmt.Sprintf("%s%s%s", e.baseURL, endpoint, params)
	} else {
		apiUrl = fmt.Sprintf("%s%s?%s", e.baseURL, endpoint, params)
	}

	req, err := http.NewRequest(method, apiUrl, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", e.authString)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
