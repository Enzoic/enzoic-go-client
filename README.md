# Enzoic Go Client Library

## TOC

This README covers the following topics:

- [Installation](#installation)
- [Create Enzoic Client](#create-enzoic-client)
- [Passwords API Examples](#passwords-api-examples)
- [Credentials API Examples](#credentials-api-examples)
- [Exposures API Examples](#exposures-api-examples)
- [Breach Monitoring by User API Examples](#breach-monitoring-by-user-api-examples)
- [Breach Monitoring by Domain API Examples](#breach-monitoring-by-domain-api-examples)

## Installation

```sh
$ go get github.com/enzoic/enzoic-go-client
```

## Create Enzoic Client

The first step to use the API is to instantiate the Enzoic Client with your API key and secret. 

```go
enzoicClient, err := enzoic.NewClient("API_KEY", "API_SECRET")
if err != nil {panic(err)}
```

## Passwords API Examples

See
https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/passwords-api

```go
// Check whether a password has been compromised
passwordCompromised, err := enzoicClient.CheckPassword("password-to-test")
if err != nil {panic(err)}

if passwordCompromised {
    fmt.Println("Password is compromised")
} else {
    fmt.Println("Password is not compromised")
}
```

## Credentials API Examples

See https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/credentials-api

```go
// Check whether a specific set of credentials are compromised
credsCompromised, err := enzoicClient.CheckCredentials("test@enzoic.com", "password-to-test")
if err != nil {panic(err)}

if credsCompromised {
	fmt.Println("Credentials are compromised")
} else {
	fmt.Println("Credentials are not compromised")
}

// Enhanced version of checkCredentials offering more control over performance.
// The call introduces 3 additional parameters:
//
// lastCheckDate: 
// The timestamp for the last check you performed for this user.
// If the date/time you provide for the last check is greater than the timestamp Enzoic has for the last
// breach affecting this user, the check will not be performed.  This can be used to substantially increase performance.
//
// excludeHashAlgorithms: 
// An array of PasswordTypes to ignore when calculating hashes for the credentials check.   
// By excluding computationally expensive PasswordTypes, such as BCrypt, it is possible to balance the performance of this
// call against security.
//
// useRawCredentials:
// For accounts that have been approved for raw credentials access, this changes the way Enzoic identifies compromised
// credentials.  Rather than passing partial hashes of the calculated credentials up to the Enzoic API, it will instead 
// pull all credentials that Enzoic has for that user and compares them locally.  This can be important for customers 
// who have some sensitivity or compliance issues with passing even partial credential hashes to a third party.
//

// this would be a stored value for last time we checked these credentials
lastCheckDate := time.Date(2018, 3, 1, 0, 0, 0, 0, time.UTC) 
credsCompromised, err = enzoicClient.CheckCredentialsEx("test@enzoic.com", "password-to-test", &lastCheckDate, 
	[]enzoic.PasswordType {BCrypt, SCrypt}, false)
if err != nil {panic(err)}

if credsCompromised {
    fmt.Println("Credentials are compromised")
} else {
    fmt.Println("Credentials are not compromised")
}

// get all passwords Enzoic has for the specified user.  Your account must have approval to call this API.
// returns results per 
//https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/credentials-api/cleartext-credentials-api
userPasswords, err := enzoicClient.GetUserPasswordsWithExposureDetails("eicar_0@enzoic.com")
if err != nil {panic(err)}

// print user passwords
for i := 0; i < len(userPasswords.Passwords); i+= 1 {
    fmt.Println("Password: " + userPasswords.Passwords[i].Password)
}
```

## Exposures API Examples

See https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api

```go
// get all exposures for the given user
exposuresForUser, err := enzoicClient.GetExposuresForUser("test@enzoic.com")
if err != nil {panic(err)}
fmt.Println(exposuresForUser.Count, "exposures found for test@enzoic.com")

// now get the full details for the first exposure returned in the list
exposureDetails, err := enzoicClient.GetExposureDetails(exposuresForUser.Exposures[0])
if err != nil {panic(err)}
fmt.Println("First exposure for test@enzoic.com was", exposureDetails.Title)

// get all exposures for a given domain
// returns paged results per 
//https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-a-domain
exposuresForDomain, err := enzoicClient.GetExposuresForDomainIncludeDetails("enzoic.com", 20, "")
if err != nil {panic(err)}

// print first page of results
for i := 0; i < len(exposuresForDomain.Exposures); i+= 1 {
    fmt.Println("Domain Exposure: " + exposuresForDomain.Exposures[i].Title)
}

// get second page of results 
if (exposuresForDomain.PagingToken != "") {
    exposuresForDomain, err = enzoicClient.GetExposuresForDomainIncludeDetails("enzoic.com", 20, exposuresForDomain.PagingToken)
    if err != nil {panic(err)}
	// process second page of results, etc.
}

// get all users exposed for a given domain
// returns paged results per 
//https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-all-email-addresses-in-a-domain
exposedUsersForDomain, err := enzoicClient.GetExposedUsersForDomain("enzoic.com", 20, "")
if err != nil {panic(err)}

// print first page of results
for i := 0; i < len(exposedUsersForDomain.Users); i+= 1 {
    fmt.Println("Exposed User: " + exposedUsersForDomain.Users[i].Username)
}

// if pagingToken present, get next page of results
if (exposedUsersForDomain.PagingToken != "") {
    exposedUsersForDomain, err = enzoicClient.GetExposedUsersForDomain("enzoic.com", 20, exposedUsersForDomain.PagingToken)
    if err != nil {panic(err)}
    // process second page of results, etc.
}
```

## Breach Monitoring by User API Examples

See https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user

```go
// couple of email addresses you wish to monitor
usernames := []string{"eicar_0@enzoic.com", "eicar_1@enzoic.com"}

// subscribe for alerts for these users
addResponse, err := enzoicClient.AddUserAlertSubscriptions(usernames, "exampleCustomData")
if err != nil {panic(err)}

fmt.Println("New subscriptions added: " + strconv.Itoa(addResponse.Added))
fmt.Println("Subscriptions already existing: " + strconv.Itoa(addResponse.AlreadyExisted))

// delete subscriptions for these users
deleteResponse, err := enzoicClient.DeleteUserAlertSubscriptions(usernames)
if err != nil {panic(err)}

fmt.Println("Subscriptions deleted: " + strconv.Itoa(deleteResponse.Deleted))
fmt.Println("Subscriptions not found: " + strconv.Itoa(deleteResponse.NotFound))

// by default, alerts will go to your default webhook on your account.  Specify an alternate Webhook to send the alerts to
// by providing its ID
addResponse, err := enzoicClient.AddUserAlertSubscriptionsWithSpecifiedWebhook(usernames, "exampleCustomData", "668db147aa97bb620c171388")
if err != nil {panic(err)}
 
// check whether a user is already subscribed
subscribed, err := enzoicClient.IsUserSubscribedForAlerts(usernames[0])
if err != nil {panic(err)}

if (subscribed) {
    fmt.Println("User already subscribed")
} else {
    fmt.Println("User not already subscribed")
}

// get all users subscribed for alerts on this account 
// returns paged results per https://www.enzoic.com/docs-exposure-alerts-service-api/#get-exposure-subscriptions
subscriptionsResponse, err := enzoicClient.GetUserAlertSubscriptionsWithExtendedInfo(4 /* page size */, "" /* paging token - empty on first call */)
if err != nil {panic(err)}

// print first page of results
for i := 0; i < len(subscriptionsResponse.UsernameHashes); i += 1 {
   fmt.Println("Username Hash: " + subscriptionsResponse.UsernameHashes[i].UsernameHash)
   fmt.Println("Webhook ID: " + subscriptionsResponse.UsernameHashes[i].WebhookID)
   fmt.Println("Webhook URL: " + subscriptionsResponse.UsernameHashes[i].WebhookURL)
}

// if PagingToken present, get next page of results
if subscriptionsResponse.PagingToken != "" {
    subscriptionsResponse, err = enzoicClient.GetUserAlertSubscriptions(4, subscriptionsResponse.PagingToken)
	// process second page of results, etc.
}
```

## Breach Monitoring by Domain API Examples

See https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain

```go
// test domains for alert subscriptions
domains := []string{"testdomain1.com", "testdomain2.com"}

// subscribe for alerts for these domains
addResponse, err = enzoicClient.AddDomainAlertSubscriptions(domains)
if err != nil {panic(err)}

fmt.Println("New subscriptions added: " + strconv.Itoa(addResponse.Added))
fmt.Println("Subscriptions already existing: " + strconv.Itoa(addResponse.AlreadyExisted))

// delete subscriptions for these domains
deleteResponse, err = enzoicClient.DeleteDomainAlertSubscriptions(domains)
if err != nil {panic(err)}

fmt.Println("Subscriptions deleted: " + strconv.Itoa(deleteResponse.Deleted))
fmt.Println("Subscriptions not found: " + strconv.Itoa(deleteResponse.NotFound))

// by default, alerts will go to your default webhook on your account.  Specify an alternate Webhook to send the alerts to
// by providing its ID
addResponse, err = enzoicClient.AddDomainAlertSubscriptionsWithSpecifiedWebhook(domains, "668db147aa97bb620c171388")
if err != nil {panic(err)}

fmt.Println("New subscriptions added: " + strconv.Itoa(addResponse.Added))
fmt.Println("Subscriptions already existing: " + strconv.Itoa(addResponse.AlreadyExisted))

// check whether a domain is already subscribed
subscribed, err = enzoicClient.IsDomainSubscribedForAlerts(domains[0])
if err != nil {panic(err)}

if subscribed {
    fmt.Println("Domain already subscribed")
} else {
    fmt.Println("Domain not already subscribed")
}    

// get all domains subscribed for alerts on this account 
// returns pages results per https://www.enzoic.com/docs-exposure-alerts-service-api/#get-exposure-subscriptions-domains
domainSubsResponse, err = enzoicClient.GetDomainAlertSubscriptionsWithExtendedInfo(4 /* page size */, "" /* paging token - empty on first call */)
if err != nil {panic(err)}

// print first page of results
for i := 0; i < len(domainSubsResponse.Domains); i += 1 {
   fmt.Println("Domain: " + domainSubsResponse.Domains[i].Domain)
   fmt.Println("Webhook ID: " + domainSubsResponse.Domains[i].WebhookID) 
   fmt.Println("Webhook URL: " + domainSubsResponse.Domains[i].WebhookURL)
}

// if pagingToken present, get next page of results
if domainSubsResponse.PagingToken != "" {
    domainSubsResponse, err = enzoicClient.GetDomainAlertSubscriptions(4, domainSubsResponse.PagingToken)
    // process second page of results, etc.
}
```

