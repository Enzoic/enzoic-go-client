package example

import (
	"fmt"
	"github.com/enzoic/enzoic-go-client"
	"os"
	"strconv"
	"time"
)

func example() {
	enzoicClient, err := enzoic.NewClient(os.Getenv("PP_API_KEY"), os.Getenv("PP_API_SECRET"))
	if err != nil {
		panic(err)
	}

	////////////////////////////////// Passwords API Examples //////////////////////////////////
	// Check whether a password has been compromised
	passwordCompromised, err := enzoicClient.CheckPassword("password-to-test")
	if err != nil {
		panic(err)
	}

	if passwordCompromised {
		fmt.Println("Password is compromised")
	} else {
		fmt.Println("Password is not compromised")
	}

	///////////////////////////////// Credentials API Examples /////////////////////////////////

	// Check whether a specific set of credentials are compromised
	credsCompromised, err := enzoicClient.CheckCredentials("test@enzoic.com", "password-to-test")
	if err != nil {
		panic(err)
	}

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
		[]enzoic.PasswordType{enzoic.BCrypt, enzoic.SCrypt}, false)
	if err != nil {
		panic(err)
	}

	if credsCompromised {
		fmt.Println("Credentials are compromised")
	} else {
		fmt.Println("Credentials are not compromised")
	}

	////////////////////////////////// Exposures API Examples //////////////////////////////////

	// get all exposures for the given user
	//var exposuresForUser []string
	exposuresForUser, err := enzoicClient.GetExposuresForUser("eicar_0@enzoic.com")
	if err != nil {
		panic(err)
	}
	fmt.Println(len(exposuresForUser), "exposures found for eicar_0@enzoic.com")

	// now get the full details for the first exposure returned in the list
	exposureDetails, err := enzoicClient.GetExposureDetails(exposuresForUser[0])
	if err != nil {
		panic(err)
	}
	fmt.Println("First exposure for test@enzoic.com was", exposureDetails.Title)

	// get all exposures for a given domain
	// returns paged results per https://www.enzoic.com/docs-exposures-api/#get-exposures-for-domain
	exposuresForDomain, err := enzoicClient.GetExposuresForDomainIncludeDetails("enzoic.com", 20, "")
	if err != nil {
		panic(err)
	}

	// print first page of results
	for i := 0; i < len(exposuresForDomain.Exposures); i += 1 {
		fmt.Println("Domain Exposure: " + exposuresForDomain.Exposures[i].Title)
	}

	// get second page of results
	if exposuresForDomain.PagingToken != "" {
		exposuresForDomain, err = enzoicClient.GetExposuresForDomainIncludeDetails("enzoic.com", 20, exposuresForDomain.PagingToken)
		if err != nil {
			panic(err)
		}
		// process second page of results, etc.
	}

	// get all users exposed for a given domain
	// returns paged results per https://www.enzoic.com/docs-exposures-api/#get-exposed-users-for-domain
	exposedUsersForDomain, err := enzoicClient.GetExposedUsersForDomain("enzoic.com", 20, "")
	if err != nil {
		panic(err)
	}

	// print first page of results
	for i := 0; i < len(exposedUsersForDomain.Users); i += 1 {
		fmt.Println("Exposed User: " + exposedUsersForDomain.Users[i].Username)
	}

	// if pagingToken present, get next page of results
	if exposedUsersForDomain.PagingToken != "" {
		exposedUsersForDomain, err = enzoicClient.GetExposedUsersForDomain("enzoic.com", 20, exposedUsersForDomain.PagingToken)
		if err != nil {
			panic(err)
		}
		// process second page of results, etc.
	}

	////////////////////////////// Breach Monitoring API Examples //////////////////////////////

	// couple of email addresses you wish to monitor
	usernames := []string{"eicar_0@enzoic.com", "eicar_1@enzoic.com"}

	// subscribe for alerts for these users
	addResponse, err := enzoicClient.AddUserAlertSubscriptions(usernames, "exampleCustomData")
	if err != nil {
		panic(err)
	}

	fmt.Println("New subscriptions added: " + strconv.Itoa(addResponse.Added))
	fmt.Println("Subscriptions already existing: " + strconv.Itoa(addResponse.AlreadyExisted))

	// delete subscriptions for these users
	deleteResponse, err := enzoicClient.DeleteUserAlertSubscriptions(usernames)
	if err != nil {
		panic(err)
	}

	fmt.Println("Subscriptions deleted: " + strconv.Itoa(deleteResponse.Deleted))
	fmt.Println("Subscriptions not found: " + strconv.Itoa(deleteResponse.NotFound))

	// check whether a user is already subscribed
	subscribed, err := enzoicClient.IsUserSubscribedForAlerts(usernames[0])
	if err != nil {
		panic(err)
	}

	if subscribed {
		fmt.Println("User already subscribed")
	} else {
		fmt.Println("User not already subscribed")
	}

	// get all users subscribed for alerts on this account
	// returns paged results per https://www.enzoic.com/docs-exposure-alerts-service-api/#get-exposure-subscriptions
	subscriptionsResponse, err := enzoicClient.GetUserAlertSubscriptions(4 /* page size */, "" /* paging token - empty on first call */)
	if err != nil {
		panic(err)
	}

	// print first page of results
	for i := 0; i < len(subscriptionsResponse.UsernameHashes); i += 1 {
		fmt.Println("Username Hash: " + subscriptionsResponse.UsernameHashes[i])
	}

	// if PagingToken present, get next page of results
	if subscriptionsResponse.PagingToken != "" {
		subscriptionsResponse, err = enzoicClient.GetUserAlertSubscriptions(4, subscriptionsResponse.PagingToken)
		// process second page of results, etc.
	}

	// test domains for alert subscriptions
	domains := []string{"testdomain1.com", "testdomain2.com"}

	// subscribe for alerts for these domains
	addResponse, err = enzoicClient.AddDomainAlertSubscriptions(domains)
	if err != nil {
		panic(err)
	}

	fmt.Println("New subscriptions added: " + strconv.Itoa(addResponse.Added))
	fmt.Println("Subscriptions already existing: " + strconv.Itoa(addResponse.AlreadyExisted))

	// delete subscriptions for these domains
	deleteResponse, err = enzoicClient.DeleteDomainAlertSubscriptions(domains)
	if err != nil {
		panic(err)
	}

	fmt.Println("Subscriptions deleted: " + strconv.Itoa(deleteResponse.Deleted))
	fmt.Println("Subscriptions not found: " + strconv.Itoa(deleteResponse.NotFound))

	// check whether a domain is already subscribed
	subscribed, err = enzoicClient.IsDomainSubscribedForAlerts(domains[0])
	if err != nil {
		panic(err)
	}

	if subscribed {
		fmt.Println("Domain already subscribed")
	} else {
		fmt.Println("Domain not already subscribed")
	}

	// get all domains subscribed for alerts on this account
	// returns pages results per https://www.enzoic.com/docs-exposure-alerts-service-api/#get-exposure-subscriptions-domains
	domainSubsResponse, err := enzoicClient.GetDomainAlertSubscriptions(4 /* page size */, "" /* paging token - empty on first call */)
	if err != nil {
		panic(err)
	}

	// print first page of results
	for i := 0; i < len(domainSubsResponse.Domains); i += 1 {
		fmt.Println("Domain: " + domainSubsResponse.Domains[i])
	}

	// if pagingToken present, get next page of results
	if domainSubsResponse.PagingToken != "" {
		domainSubsResponse, err = enzoicClient.GetDomainAlertSubscriptions(4, domainSubsResponse.PagingToken)
		// process second page of results, etc.
	}
}
