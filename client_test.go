package enzoic

import (
	"fmt"
	"gopkg.in/stretchr/testify.v1/assert"
	"log"
	"os"
	"slices"
	"testing"
	"time"
)

func TestEnzoic_CheckPassword(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	isCompromised, err := enzoicClient.CheckPassword("hashcat")
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, isCompromised)

	isCompromised, err = enzoicClient.CheckPassword("definitely_not_compromised_and_never_will_be_a9a90149-307d-4ec6-9132-23008d5080ae")
	if err != nil {
		log.Fatal(err)
	}
	assert.False(t, isCompromised)
}

func TestEnzoic_CheckPasswordHash(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	isCompromised, err := enzoicClient.CheckPasswordHash("8743b52063cd84097a65d1633f5c74f5", MD5)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, isCompromised)

	isCompromised, err = enzoicClient.CheckPasswordHash("b4b9b02e6f09a9bd760f388b67351e2b", NTLM)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, isCompromised)

	isCompromised, err = enzoicClient.CheckPasswordHash("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", MD5)
	if err != nil {
		log.Fatal(err)
	}
	assert.False(t, isCompromised)
}

func TestEnzoic_CheckPasswordWithExposure(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	revealedInExposure := false
	var exposureCount int
	isCompromised, err := enzoicClient.CheckPasswordWithExposure("password", &revealedInExposure, &exposureCount)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, isCompromised)
	assert.True(t, revealedInExposure)
	assert.True(t, exposureCount > 0)

	isCompromised, err = enzoicClient.CheckPasswordWithExposure("`!(&,<:{`>", &revealedInExposure, &exposureCount)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, isCompromised)
	assert.False(t, revealedInExposure)
	assert.Equal(t, exposureCount, 0)
}

func TestEnzoic_RetrieveCandidatesForPartialPasswordHash(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	candidates, err := enzoicClient.RetrieveCandidatesForPartialPasswordHash("8743b52", MD5)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, len(candidates) > 0)
	assert.True(t, slices.Contains(candidates, "8743b52ec575aeef17d9e8ec01012fab"))

	candidates, err = enzoicClient.RetrieveCandidatesForPartialPasswordHash("b4b9b02", NTLM)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, len(candidates) > 0)
	assert.True(t, slices.Contains(candidates, "b4b9b0202d6cfd7484172460469338ce"))
}

func TestEnzoic_CheckCredentials(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	isCompromised, _ := enzoicClient.CheckCredentials("test@passwordping.com", "123456")
	assert.True(t, isCompromised)

	isCompromised, _ = enzoicClient.CheckCredentials("test@passwordping.com", "notvalid")
	assert.False(t, isCompromised)

	isCompromised, _ = enzoicClient.CheckCredentials("testpwdpng445", "testpwdpng4452")
	assert.True(t, isCompromised)

	isCompromised, _ = enzoicClient.CheckCredentials("testpwdpng445", "notvalid")
	assert.False(t, isCompromised)
}

func TestEnzoic_CheckCredentialsEx(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	isCompromised, _ := enzoicClient.CheckCredentialsEx("testpwdpng445", "testpwdpng4452", nil, []PasswordType{vBulletinPost3_8_5}, false)
	assert.False(t, isCompromised)

	lastCheckDate := time.Date(2018, 3, 1, 0, 0, 0, 0, time.UTC)
	isCompromised, _ = enzoicClient.CheckCredentialsEx("testpwdpng445", "testpwdpng4452", &lastCheckDate, nil, false)
	assert.False(t, isCompromised)
}

func TestEnzoic_GetExposuresForUser(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	exposures, _ := enzoicClient.GetExposuresForUser("@@bogus-username@@")
	assert.Equal(t, 0, len(exposures))

	exposures, _ = enzoicClient.GetExposuresForUser("eicar_type0@enzoic.com")
	assert.Equal(t, 1, len(exposures))
	assert.Equal(t, []string{
		"5d97d14faa8feb16b0f9fd5f",
	}, exposures)
}

func TestEnzoic_GetExposuresForUserWithinDateRange(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	exposures, _ := enzoicClient.GetExposuresForUserWithinDateRange("@@bogus-username@@",
		time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2011, 1, 1, 0, 0, 0, 0, time.UTC))
	assert.Equal(t, 0, len(exposures))

	exposures, _ = enzoicClient.GetExposuresForUserWithinDateRange("eicar_type0@enzoic.com",
		time.Date(2019, 10, 4, 0, 0, 0, 0, time.UTC),
		time.Date(2019, 10, 5, 0, 0, 0, 0, time.UTC))
	assert.Equal(t, 1, len(exposures))
	assert.Equal(t, []string{
		"5d97d14faa8feb16b0f9fd5f",
	}, exposures)
}

func TestEnzoic_GetExposureDetails(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	exposureDetails, _ := enzoicClient.GetExposureDetails("111111111111111111111111")
	assert.Nil(t, exposureDetails)

	exposureDetails, _ = enzoicClient.GetExposureDetails("5820469ffdb8780510b329cc")
	expectedTime := time.Date(2012, 3, 1, 0, 0, 0, 0, time.UTC)
	expectedDateAdded := time.Date(2016, time.November, 7, 9, 17, 19, 0, time.UTC)
	assert.Equal(t, &ExposureDetails{
		ID:              "5820469ffdb8780510b329cc",
		Title:           "last.fm",
		Category:        "Music",
		Date:            &expectedTime,
		Entries:         81967007,
		PasswordType:    "MD5",
		ExposedData:     []string{"Emails", "Passwords", "Usernames", "Website Activity"},
		DomainsAffected: 1219053,
		DateAdded:       &expectedDateAdded,
		SourceURLs:      []string{},
	}, exposureDetails)
}

func TestEnzoic_GetUserPasswords(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	userPasswords, _ := enzoicClient.GetUserPasswords("eicar_0@enzoic.com")
	assert.Equal(t, &UserPasswords{
		LastBreachDate: time.Date(2022, time.October, 14, 7, 2, 40, 0, time.UTC),
		Passwords: []PasswordDetails{
			{
				HashType:  0,
				Password:  "password123",
				Salt:      "",
				Exposures: []string{"634908d2e0513eb0788aa0b9", "634908d06715cc1b5b201a1a"},
			},
			{
				HashType:  0,
				Password:  "g0oD_on3",
				Salt:      "",
				Exposures: []string{"634908d2e0513eb0788aa0b9"},
			},
			{
				HashType:  0,
				Password:  "Easy2no",
				Salt:      "",
				Exposures: []string{"634908d26715cc1b5b201a1d"},
			},
			{
				HashType:  0,
				Password:  "123456",
				Salt:      "",
				Exposures: []string{"63490990e0513eb0788aa0d1", "634908d0e0513eb0788aa0b5"},
			},
		},
	}, userPasswords)

	userPasswords, _ = enzoicClient.GetUserPasswords("eicar_type8@enzoic.com")
	assert.Equal(t, &UserPasswords{
		LastBreachDate: time.Date(2022, time.May, 3, 5, 12, 43, 0, time.UTC),
		Passwords: []PasswordDetails{
			{
				HashType:  8,
				Password:  "$2a$10$LuodKoFv1YoTRpRBHjfeJ.HsMNx6Ln/Qo/jlSHDa6XpWm/SYoSroG",
				Salt:      "$2a$10$LuodKoFv1YoTRpRBHjfeJ.",
				Exposures: []string{"6270b9cb0323b3bb8faed96c"},
			},
			{
				HashType:  8,
				Password:  "$2y$04$dgoRREIMJItkLVH7xpSpo.tqkpEM5J/JU9HB4LNO9eD/aygJN3dZ2",
				Salt:      "$2y$04$dgoRREIMJItkLVH7xpSpo.",
				Exposures: []string{"6270b9cb0323b3bb8faed96c"},
			},
		},
	}, userPasswords)

	// test account without permissions
	enzoicClient, _ = NewClient(os.Getenv("PP_API_KEY_2"), os.Getenv("PP_API_SECRET_2"))
	userPasswords2, err := enzoicClient.GetUserPasswords("eicar_0@enzoic.com")
	assert.Equal(t, "Call was rejected for the following reason: Your account is not allowed to make this call.  Please contact sales@enzoic.com.", err.Error())
	assert.Nil(t, userPasswords2)
}

func TestEnzoic_GetUserPasswordsUsingPartialHash(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	userPasswords, _ := enzoicClient.GetUserPasswordsUsingPartialHash("eicar_0@enzoic.com")
	assert.Equal(t, &UserPasswords{
		LastBreachDate: time.Date(2022, time.October, 14, 7, 2, 40, 0, time.UTC),
		Passwords: []PasswordDetails{
			{
				HashType:  0,
				Password:  "password123",
				Salt:      "",
				Exposures: []string{"634908d2e0513eb0788aa0b9", "634908d06715cc1b5b201a1a"},
			},
			{
				HashType:  0,
				Password:  "g0oD_on3",
				Salt:      "",
				Exposures: []string{"634908d2e0513eb0788aa0b9"},
			},
			{
				HashType:  0,
				Password:  "Easy2no",
				Salt:      "",
				Exposures: []string{"634908d26715cc1b5b201a1d"},
			},
			{
				HashType:  0,
				Password:  "123456",
				Salt:      "",
				Exposures: []string{"63490990e0513eb0788aa0d1", "634908d0e0513eb0788aa0b5"},
			},
		},
	}, userPasswords)

	userPasswords, _ = enzoicClient.GetUserPasswordsUsingPartialHash("eicar_type8@enzoic.com")
	assert.Equal(t, &UserPasswords{
		LastBreachDate: time.Date(2022, time.May, 3, 5, 12, 43, 0, time.UTC),
		Passwords: []PasswordDetails{
			{
				HashType:  8,
				Password:  "$2a$10$LuodKoFv1YoTRpRBHjfeJ.HsMNx6Ln/Qo/jlSHDa6XpWm/SYoSroG",
				Salt:      "$2a$10$LuodKoFv1YoTRpRBHjfeJ.",
				Exposures: []string{"6270b9cb0323b3bb8faed96c"},
			},
			{
				HashType:  8,
				Password:  "$2y$04$dgoRREIMJItkLVH7xpSpo.tqkpEM5J/JU9HB4LNO9eD/aygJN3dZ2",
				Salt:      "$2y$04$dgoRREIMJItkLVH7xpSpo.",
				Exposures: []string{"6270b9cb0323b3bb8faed96c"},
			},
		},
	}, userPasswords)

	// test account without permissions
	enzoicClient, _ = NewClient(os.Getenv("PP_API_KEY_2"), os.Getenv("PP_API_SECRET_2"))
	userPasswords2, err := enzoicClient.GetUserPasswords("eicar_0@enzoic.com")
	assert.Equal(t, "Call was rejected for the following reason: Your account is not allowed to make this call.  Please contact sales@enzoic.com.", err.Error())
	assert.Nil(t, userPasswords2)
}

func TestEnzoic_GetUserPasswordsWithExposureDetails(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	userPasswords, _ := enzoicClient.GetUserPasswordsWithExposureDetails("eicar_8@enzoic.com")
	expectedDate := time.Date(2010, time.January, 1, 7, 0, 0, 0, time.UTC)
	expectedAddDate := time.Date(2017, time.April, 8, 2, 7, 44, 0, time.UTC)
	assert.Equal(t, &UserPasswordsWithExposureDetails{
		LastBreachDate: time.Date(2017, time.April, 8, 2, 7, 44, 0, time.UTC),
		Passwords: []PasswordDetailsWithExposureDetails{
			{
				HashType: 8,
				Password: "$2a$04$yyJQsNrcBeTRgYNf4HCTxefTL9n7rFYywPxdXU9YRRTgkaZaNkgyu",
				Salt:     "$2a$04$yyJQsNrcBeTRgYNf4HCTxe",
				Exposures: []ExposureDetails{
					{
						ID:              "58e845f04d6db222103001df",
						Title:           "passwordping.com test breach BCrypt",
						Category:        "Testing Ignore",
						Date:            &expectedDate,
						Entries:         1,
						PasswordType:    "BCrypt",
						ExposedData:     []string{"Emails", "Passwords"},
						DomainsAffected: 1,
						DateAdded:       &expectedAddDate,
						SourceURLs:      []string{},
					},
				},
			},
		},
	}, userPasswords)
}

func TestEnzoic_GetUserPasswordsByDomain(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	userPasswords, _ := enzoicClient.GetUserPasswordsByDomain("enzoic.com", 0, "")
	//expectedDate := time.Date(2010, time.January, 1, 7, 0, 0, 0, time.UTC)
	//expectedAddDate := time.Date(2017, time.April, 8, 2, 7, 44, 0, time.UTC)
	assert.Equal(t, 99, userPasswords.Count)
	assert.Equal(t, "", userPasswords.PagingToken)
	assert.Equal(t, 99, len(userPasswords.Users))
	assert.Equal(t, UsersWithPasswordsByDomain{
		Username: "eicar_8@enzoic.com",
		Passwords: []PasswordDetails{
			{
				HashType:  8,
				Password:  "$2a$04$yyJQsNrcBeTRgYNf4HCTxefTL9n7rFYywPxdXU9YRRTgkaZaNkgyu",
				Salt:      "$2a$04$yyJQsNrcBeTRgYNf4HCTxe",
				Exposures: []string{"58e845f04d6db222103001df"},
			},
		},
	}, userPasswords.Users[6])
}

func TestEnzoic_GetExposedUsersForDomain(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	exposedUsersForDomain, _ := enzoicClient.GetExposedUsersForDomain("@@bogus-domain@@", 0, "")
	assert.Equal(t, ExposedUsersForDomain{
		Count:       0,
		Users:       []ExposedUserForDomain{},
		PagingToken: "",
	}, *exposedUsersForDomain)

	exposedUsersForDomain, _ = enzoicClient.GetExposedUsersForDomain("email.tst", 2, "")
	assert.Equal(t, ExposedUsersForDomain{
		Count: 12,
		Users: []ExposedUserForDomain{
			{
				Username:  "sample@email.tst",
				Exposures: []string{"57dc11964d6db21300991b78", "57ffcf3c1395c80b30dd4429", "5805029914f33808dc802ff7", "598e5b844eb6d82ea07c5783", "59bbf691e5017d2dc8a96eab", "59bc2016e5017d2dc8bdc36a", "59bebae9e5017d2dc85fc2ab", "59f36f8c4eb6d85ba0bee09c", "5bcf9af3e5017d07201e2149", "5c4f818bd3cef70e983dda1e"},
			},
			{
				Username:  "xxxxxxxxxx@email.tst",
				Exposures: []string{"5805029914f33808dc802ff7"},
			},
		},
		PagingToken: "58055cd814f3380a94324adc",
	}, *exposedUsersForDomain)

	exposedUsersForDomain, _ = enzoicClient.GetExposedUsersForDomain("email.tst", 2, "58055cd814f3380a94324adc")
	assert.Equal(t, ExposedUsersForDomain{
		Count: 12,
		Users: []ExposedUserForDomain{
			{Username: "cbeiqvf@email.tst", Exposures: []string{"5805029914f33808dc802ff7"}},
			{Username: "yjybey@email.tst", Exposures: []string{"5805029914f33808dc802ff7"}}},
		PagingToken: "580bf3cafdb8780bb001abcb",
	}, *exposedUsersForDomain)
}

func TestEnzoic_GetExposedUsersForDomainWithinDateRange(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	exposedUsersForDomain, _ := enzoicClient.GetExposedUsersForDomainWithinDateRange("@@bogus-domain@@",
		time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2011, 1, 1, 0, 0, 0, 0, time.UTC),
		0, "")
	assert.Equal(t, ExposedUsersForDomain{
		Count:       0,
		Users:       []ExposedUserForDomain{},
		PagingToken: "",
	}, *exposedUsersForDomain)

	exposedUsersForDomain, _ = enzoicClient.GetExposedUsersForDomainWithinDateRange("email.tst",
		time.Date(2016, 10, 17, 0, 0, 0, 0, time.UTC),
		time.Date(2016, 10, 18, 0, 0, 0, 0, time.UTC),
		2, "")

	assert.Equal(t, ExposedUsersForDomain{
		Count: 12,
		Users: []ExposedUserForDomain{
			{
				Username:  "sample@email.tst",
				Exposures: []string{"5805029914f33808dc802ff7"},
			},
			{
				Username:  "xxxxxxxxxx@email.tst",
				Exposures: []string{"5805029914f33808dc802ff7"},
			},
		},
		PagingToken: "58055cd814f3380a94324adc",
	}, *exposedUsersForDomain)

	exposedUsersForDomain, _ = enzoicClient.GetExposedUsersForDomainWithinDateRange("email.tst",
		time.Date(2016, 10, 17, 0, 0, 0, 0, time.UTC),
		time.Date(2016, 10, 18, 0, 0, 0, 0, time.UTC),
		2, "58055cd814f3380a94324adc")
	assert.Equal(t, ExposedUsersForDomain{
		Count: 12,
		Users: []ExposedUserForDomain{
			{Username: "cbeiqvf@email.tst", Exposures: []string{"5805029914f33808dc802ff7"}},
			{Username: "yjybey@email.tst", Exposures: []string{"5805029914f33808dc802ff7"}}},
		PagingToken: "580bf3cafdb8780bb001abcb",
	}, *exposedUsersForDomain)
}

func TestEnzoic_GetExposuresForDomain(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	exposuresForDomain, _ := enzoicClient.GetExposuresForDomain("@@bogus-domain@@", 0, "")
	assert.Equal(t, ExposuresForDomain{
		Count:       0,
		Exposures:   []string{},
		PagingToken: "",
	}, *exposuresForDomain)

	exposuresForDomain, _ = enzoicClient.GetExposuresForDomain("email.tst", 2, "")
	assert.Equal(t, ExposuresForDomain{
		Count:       10,
		Exposures:   []string{"57ffcf3c1395c80b30dd4429", "57dc11964d6db21300991b78"},
		PagingToken: "5837c338ec4d280e25c6310d",
	}, *exposuresForDomain)

	exposuresForDomain, _ = enzoicClient.GetExposuresForDomain("email.tst", 2, "5837c338ec4d280e25c6310d")
	assert.Equal(t, ExposuresForDomain{
		Count:       10,
		Exposures:   []string{"5805029914f33808dc802ff7", "598e5b844eb6d82ea07c5783"},
		PagingToken: "598e5b8b4eb6d82ea07c5b39",
	}, *exposuresForDomain)
}

func TestEnzoic_GetExposuresForDomainWithinDateRange(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	exposuresForDomain, _ := enzoicClient.GetExposuresForDomainWithinDateRange("@@bogus-domain@@",
		time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2011, 1, 1, 0, 0, 0, 0, time.UTC),
		0, "")
	assert.Equal(t, ExposuresForDomain{
		Count:       0,
		Exposures:   []string{},
		PagingToken: "",
	}, *exposuresForDomain)

	exposuresForDomain, _ = enzoicClient.GetExposuresForDomainWithinDateRange("email.tst",
		time.Date(2016, 10, 13, 0, 0, 0, 0, time.UTC),
		time.Date(2016, 10, 14, 0, 0, 0, 0, time.UTC),
		2, "")
	assert.Equal(t, ExposuresForDomain{
		Count:       1,
		Exposures:   []string{"57ffcf3c1395c80b30dd4429"},
		PagingToken: "",
	}, *exposuresForDomain)
}

func TestEnzoic_GetExposuresForDomainIncludeDetails(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	exposuresForDomain, _ := enzoicClient.GetExposuresForDomainIncludeDetails("@@bogus-domain@@", 0, "")
	assert.Equal(t, ExposuresForDomainIncludeDetails{
		Count:       0,
		Exposures:   []ExposureDetails{},
		PagingToken: "",
	}, *exposuresForDomain)

	exposuresForDomain, _ = enzoicClient.GetExposuresForDomainIncludeDetails("email.tst", 2, "")
	expectedDate1 := time.Date(2015, time.May, 1, 0, 0, 0, 0, time.UTC)
	expectedDateAdded1 := time.Date(2016, time.September, 16, 15, 36, 54, 0, time.UTC)
	expectedDate2 := time.Date(2012, time.December, 31, 0, 0, 0, 0, time.UTC)
	expectedDateAdded2 := time.Date(2016, time.October, 13, 18, 15, 24, 0, time.UTC)
	assert.Equal(t, ExposuresForDomainIncludeDetails{
		Count: 10,
		Exposures: []ExposureDetails{
			{
				ID:              "57dc11964d6db21300991b78",
				Title:           "funsurveys.net",
				Entries:         5123,
				Date:            &expectedDate1,
				Category:        "Marketing",
				PasswordType:    "Cleartext",
				ExposedData:     []string{"Emails", "Passwords"},
				DateAdded:       &expectedDateAdded1,
				SourceURLs:      []string{},
				DomainsAffected: 683,
			},
			{
				ID:              "57ffcf3c1395c80b30dd4429",
				Title:           "linkedin.com",
				Entries:         165286357,
				Date:            &expectedDate2,
				Category:        "Social Media",
				PasswordType:    "SHA1",
				ExposedData:     []string{"Emails", "Passwords"},
				DateAdded:       &expectedDateAdded2,
				SourceURLs:      []string{},
				DomainsAffected: 10073082,
			},
		},
		PagingToken: "5837c338ec4d280e25c6310d",
	}, *exposuresForDomain)

	exposuresForDomain, _ = enzoicClient.GetExposuresForDomainIncludeDetails("email.tst", 2, "5837c338ec4d280e25c6310d")
	expectedDate1 = time.Date(2016, time.August, 1, 0, 0, 0, 0, time.UTC)
	expectedDateAdded1 = time.Date(2016, time.October, 17, 16, 55, 53, 0, time.UTC)
	expectedDate2 = time.Date(2012, time.July, 1, 6, 0, 0, 0, time.UTC)
	expectedDateAdded2 = time.Date(2017, time.August, 12, 1, 36, 4, 0, time.UTC)
	assert.Equal(t, ExposuresForDomainIncludeDetails{
		Count: 10,
		Exposures: []ExposureDetails{
			{
				ID:              "5805029914f33808dc802ff7",
				Title:           "exploit.in database compilation",
				Entries:         649187883,
				Date:            &expectedDate1,
				Category:        "Unspecified",
				PasswordType:    "Cleartext",
				ExposedData:     []string{"Emails", "Passwords"},
				DateAdded:       &expectedDateAdded1,
				SourceURLs:      []string{},
				DomainsAffected: 9441219,
			},
			{
				ID:       "598e5b844eb6d82ea07c5783",
				Title:    "anonjdb",
				Entries:  706,
				Date:     &expectedDate2,
				Category: "Hacking", PasswordType: "MD5",
				ExposedData:     []string{"Emails", "Passwords", "Usernames"},
				DateAdded:       &expectedDateAdded2,
				SourceURLs:      []string{},
				DomainsAffected: 110,
			},
		},
		PagingToken: "598e5b8b4eb6d82ea07c5b39",
	}, *exposuresForDomain)
}

func TestEnzoic_GetExposuresForDomainWithinDateRangeIncludeDetails(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	exposuresForDomain, _ := enzoicClient.GetExposuresForDomainWithinDateRangeIncludeDetails("@@bogus-domain@@",
		time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2011, 1, 1, 0, 0, 0, 0, time.UTC),
		0, "")
	assert.Equal(t, ExposuresForDomainIncludeDetails{
		Count:       0,
		Exposures:   []ExposureDetails{},
		PagingToken: "",
	}, *exposuresForDomain)

	exposuresForDomain, _ = enzoicClient.GetExposuresForDomainWithinDateRangeIncludeDetails("email.tst",
		time.Date(2016, 10, 13, 0, 0, 0, 0, time.UTC),
		time.Date(2016, 10, 14, 0, 0, 0, 0, time.UTC),
		2, "")
	expectedDate2 := time.Date(2012, time.December, 31, 0, 0, 0, 0, time.UTC)
	expectedDateAdded2 := time.Date(2016, time.October, 13, 18, 15, 24, 0, time.UTC)
	assert.Equal(t, ExposuresForDomainIncludeDetails{
		Count: 1,
		Exposures: []ExposureDetails{
			{
				ID:              "57ffcf3c1395c80b30dd4429",
				Title:           "linkedin.com",
				Entries:         165286357,
				Date:            &expectedDate2,
				Category:        "Social Media",
				PasswordType:    "SHA1",
				ExposedData:     []string{"Emails", "Passwords"},
				DateAdded:       &expectedDateAdded2,
				SourceURLs:      []string{},
				DomainsAffected: 10073082,
			},
		},
		PagingToken: "",
	}, *exposuresForDomain)
}

func TestEnzoic_AddUserAlertSubscriptions(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	testUsers := []string{
		"eicar_1@enzoic.com",
		"eicar_0@enzoic.com",
	}

	// delete them just in case they were left behind by previous test
	enzoicClient.DeleteUserAlertSubscriptions(testUsers)

	response, _ := enzoicClient.AddUserAlertSubscriptions(testUsers, "")
	assert.Equal(t, 2, response.Added)
	assert.Equal(t, 0, response.AlreadyExisted)
}

func TestEnzoic_AddUserAlertSubscriptionsWithSpecifiedWebhook(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	testUsers := []string{
		"eicar_1@enzoic.com",
		"eicar_0@enzoic.com",
	}

	// delete them just in case they were left behind by previous test
	enzoicClient.DeleteUserAlertSubscriptions(testUsers)

	response, _ := enzoicClient.AddUserAlertSubscriptionsWithSpecifiedWebhook(testUsers, "", "668db147aa97bb620c171388")
	assert.Equal(t, 2, response.Added)
	assert.Equal(t, 0, response.AlreadyExisted)
}

func TestEnzoic_AddUserAlertSubscriptionsV2(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	testUsers := []UserAlertSubscription{
		{EmailAddress: "eicar_1@enzoic.com", CustomData: "unit-test-go-1"},
		{EmailAddress: "eicar_0@enzoic.com", CustomData: "unit-test-go-2"},
	}

	// delete them just in case they were left behind by previous test
	enzoicClient.DeleteUserAlertSubscriptions([]string{testUsers[0].EmailAddress, testUsers[1].EmailAddress})
	enzoicClient.DeleteUserAlertSubscriptionsByCustomData("unit-test-go-1")
	enzoicClient.DeleteUserAlertSubscriptionsByCustomData("unit-test-go-2")

	response, _ := enzoicClient.AddUserAlertSubscriptionsV2(testUsers, "")
	assert.Equal(t, 2, response.Added)
	assert.Equal(t, 0, response.AlreadyExisted)

	// make sure it works with no customData specified
	testUsersNoCustomData := []UserAlertSubscription{
		{EmailAddress: "eicar_1@enzoic.com"},
		{EmailAddress: "eicar_0@enzoic.com"},
	}

	// clear out previous test data
	enzoicClient.DeleteUserAlertSubscriptions([]string{testUsers[0].EmailAddress, testUsers[1].EmailAddress})
	enzoicClient.DeleteUserAlertSubscriptionsByCustomData("unit-test-go-1")
	enzoicClient.DeleteUserAlertSubscriptionsByCustomData("unit-test-go-2")

	responseNoCustomData, _ := enzoicClient.AddUserAlertSubscriptionsV2(testUsersNoCustomData, "")
	assert.Equal(t, 2, responseNoCustomData.Added)
	assert.Equal(t, 0, responseNoCustomData.AlreadyExisted)

	// clear out previous test data
	enzoicClient.DeleteUserAlertSubscriptions([]string{testUsers[0].EmailAddress, testUsers[1].EmailAddress})
	enzoicClient.DeleteUserAlertSubscriptionsByCustomData("unit-test-go-1")
	enzoicClient.DeleteUserAlertSubscriptionsByCustomData("unit-test-go-2")

	// make sure it works with a webhook specified
	responseCustomWebhook, _ := enzoicClient.AddUserAlertSubscriptionsV2(testUsers, "668db147aa97bb620c171388")
	assert.Equal(t, 2, responseCustomWebhook.Added)
	assert.Equal(t, 0, responseCustomWebhook.AlreadyExisted)

}

func TestEnzoic_DeleteUserAlertSubscriptions(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	testUsers := []string{
		"eicar_1@enzoic.com",
		"eicar_0@enzoic.com",
	}

	// clear out previous test data
	enzoicClient.DeleteUserAlertSubscriptions(testUsers)
	enzoicClient.DeleteUserAlertSubscriptionsByCustomData("unit-test-go-1")
	enzoicClient.DeleteUserAlertSubscriptionsByCustomData("unit-test-go-2")

	// add test subscriptions
	enzoicClient.AddUserAlertSubscriptions(testUsers, "")

	response, _ := enzoicClient.DeleteUserAlertSubscriptions(testUsers)
	assert.Equal(t, 2, response.Deleted)
	assert.Equal(t, 0, response.NotFound)
}

func TestEnzoic_DeleteUserAlertSubscriptionsByCustomData(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	testUsers := []string{
		"eicar_1@enzoic.com",
		"eicar_0@enzoic.com",
	}

	// add test subscriptions
	enzoicClient.DeleteUserAlertSubscriptions(testUsers)
	enzoicClient.AddUserAlertSubscriptions(testUsers, "testing")

	response, _ := enzoicClient.DeleteUserAlertSubscriptionsByCustomData("testing")
	assert.Equal(t, 2, response.Deleted)
	assert.Equal(t, 0, response.NotFound)
}

func TestEnzoic_IsUserSubscribedForAlerts(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	testUsers := []string{
		"eicar_1@enzoic.com",
		"eicar_0@enzoic.com",
	}

	// add test subscriptions
	enzoicClient.AddUserAlertSubscriptions(testUsers, "")

	response, _ := enzoicClient.IsUserSubscribedForAlerts(testUsers[0])
	assert.True(t, response)

	response, _ = enzoicClient.IsUserSubscribedForAlerts(testUsers[1])
	assert.True(t, response)

	response, _ = enzoicClient.IsUserSubscribedForAlerts("not_a_monitored_user@enzoic.com")
	assert.False(t, response)
}

func TestEnzoic_GetUserAlertSubscriptionsByCustomData(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	testUsers := []string{
		"eicar_1@enzoic.com",
		"eicar_0@enzoic.com",
	}

	// add test subscriptions
	enzoicClient.DeleteUserAlertSubscriptions(testUsers)
	response2, _ := enzoicClient.AddUserAlertSubscriptions(testUsers, "unit-test-go")
	assert.Equal(t, 2, response2.Added)

	response, err := enzoicClient.GetUserAlertSubscriptionsByCustomData("unit-test-go", 1, "")
	assert.Nil(t, err)
	assert.Equal(t, GetSubscriptionsResponse{
		UsernameHashes: []string{"1697bf210b5725683faa7467099bdd4df07091d96dc2d114cf379df0290afcb1"},
		Count:          2,
		PagingToken:    response.PagingToken,
	}, *response)

	response, _ = enzoicClient.GetUserAlertSubscriptionsByCustomData("unit-test-go", 1, response.PagingToken)
	assert.Equal(t, GetSubscriptionsResponse{
		UsernameHashes: []string{"705bce557110384a4ce76aa9c33a12af14ac1eee3978ac3076f866aa0d84f07a"},
		Count:          2,
		PagingToken:    "",
	}, *response)
}

func TestEnzoic_GetUserAlertSubscriptionsByCustomDataWithExtendedInfo(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	testUsers := []string{
		"eicar_1@enzoic.com",
		"eicar_0@enzoic.com",
	}

	// add test subscriptions
	enzoicClient.DeleteUserAlertSubscriptions(testUsers)
	response2, _ := enzoicClient.AddUserAlertSubscriptions(testUsers, "unit-test-go")
	assert.Equal(t, 2, response2.Added)

	response, err := enzoicClient.GetUserAlertSubscriptionsByCustomDataWithExtendedInfo("unit-test-go", 1, "")
	assert.Nil(t, err)
	assert.Equal(t, GetSubscriptionsWithExtendedInfoResponse{
		UsernameHashes: []UsernameHashWithExtendedInfo{
			{
				UsernameHash: "1697bf210b5725683faa7467099bdd4df07091d96dc2d114cf379df0290afcb1",
				CustomData:   "unit-test-go",
				WebhookID:    "668d9784b79968eab0657905",
				WebhookURL:   "https://api.passwordping.com/webhook",
			},
		},
		Count:       2,
		PagingToken: response.PagingToken,
	}, *response)

	response, _ = enzoicClient.GetUserAlertSubscriptionsByCustomDataWithExtendedInfo("unit-test-go", 1, response.PagingToken)
	assert.Equal(t, GetSubscriptionsWithExtendedInfoResponse{
		UsernameHashes: []UsernameHashWithExtendedInfo{
			{
				UsernameHash: "705bce557110384a4ce76aa9c33a12af14ac1eee3978ac3076f866aa0d84f07a",
				CustomData:   "unit-test-go",
				WebhookID:    "668d9784b79968eab0657905",
				WebhookURL:   "https://api.passwordping.com/webhook",
			},
		},
		Count:       2,
		PagingToken: "",
	}, *response)
}

func TestEnzoic_AddDomainAlertSubscriptions(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	testDomains := []string{
		"testadddomain1.com",
		"testadddomain2.com",
	}

	// delete them just in case they were left behind by previous test
	enzoicClient.DeleteDomainAlertSubscriptions(testDomains)

	response, _ := enzoicClient.AddDomainAlertSubscriptions(testDomains)
	assert.Equal(t, 2, response.Added)
	assert.Equal(t, 0, response.AlreadyExisted)
}

func TestEnzoic_AddDomainAlertSubscriptionsWithCustomData(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	testDomains := []string{
		"testadddomain1.com",
		"testadddomain2.com",
	}

	// delete them just in case they were left behind by previous test
	enzoicClient.DeleteDomainAlertSubscriptions(testDomains)

	response, _ := enzoicClient.AddDomainAlertSubscriptionsWithCustomData(testDomains, "testSubs")
	assert.Equal(t, 2, response.Added)
	assert.Equal(t, 0, response.AlreadyExisted)
}

func TestEnzoic_AddDomainAlertSubscriptionsWithSpecifiedWebhook(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	testDomains := []string{
		"testadddomain1.com",
		"testadddomain2.com",
	}

	// delete them just in case they were left behind by previous test
	enzoicClient.DeleteDomainAlertSubscriptions(testDomains)

	response, _ := enzoicClient.AddDomainAlertSubscriptionsWithSpecifiedWebhook(testDomains, "668db147aa97bb620c171388")
	assert.Equal(t, 2, response.Added)
	assert.Equal(t, 0, response.AlreadyExisted)
}

func TestEnzoic_AddDomainAlertSubscriptionsWithSpecifiedWebhookAndCustomData(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	testDomains := []string{
		"testadddomain1.com",
		"testadddomain2.com",
	}

	// delete them just in case they were left behind by previous test
	enzoicClient.DeleteDomainAlertSubscriptions(testDomains)

	response, _ := enzoicClient.AddDomainAlertSubscriptionsWithSpecifiedWebhookAndCustomData(testDomains, "668db147aa97bb620c171388", "testSubs")
	assert.Equal(t, 2, response.Added)
	assert.Equal(t, 0, response.AlreadyExisted)
}

func TestEnzoic_AddDomainAlertSubscriptionsV2(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	testDomains := []DomainAlertSubscription{
		{Domain: "testadddomain1.com", CustomData: "testSub1"},
		{Domain: "testadddomain2.com", CustomData: "testSub2"},
	}

	// delete them just in case they were left behind by previous test
	enzoicClient.DeleteDomainAlertSubscriptions([]string{testDomains[0].Domain, testDomains[1].Domain})

	response, _ := enzoicClient.AddDomainAlertSubscriptionsV2(testDomains, "")
	assert.Equal(t, 2, response.Added)
	assert.Equal(t, 0, response.AlreadyExisted)

	// make sure it works with no customData specified
	testDomains2 := []DomainAlertSubscription{
		{Domain: "testadddomain1.com"},
		{Domain: "testadddomain2.com"},
	}

	// clear out previous test data
	enzoicClient.DeleteDomainAlertSubscriptions([]string{testDomains[0].Domain, testDomains[1].Domain})

	response2, _ := enzoicClient.AddDomainAlertSubscriptionsV2(testDomains2, "")
	assert.Equal(t, 2, response2.Added)
	assert.Equal(t, 0, response2.AlreadyExisted)

	// clear out previous test data
	enzoicClient.DeleteDomainAlertSubscriptions([]string{testDomains[0].Domain, testDomains[1].Domain})

	// make sure it works with a webhook specified
	response3, _ := enzoicClient.AddDomainAlertSubscriptionsV2(testDomains2, "668db147aa97bb620c171388")
	assert.Equal(t, 2, response3.Added)
	assert.Equal(t, 0, response3.AlreadyExisted)
}

func TestEnzoic_DeleteDomainAlertSubscriptions(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	testDomains := []string{
		"testadddomain1.com",
		"testadddomain2.com",
	}

	// add test subscriptions
	enzoicClient.AddDomainAlertSubscriptions(testDomains)

	response, _ := enzoicClient.DeleteDomainAlertSubscriptions(testDomains)
	assert.Equal(t, 2, response.Deleted)
	assert.Equal(t, 0, response.NotFound)
}

func TestEnzoic_DeleteDomainAlertSubscriptionsByCustomData(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	testDomains := []string{
		"testadddomain1.com",
		"testadddomain2.com",
	}

	// add test subscriptions
	enzoicClient.AddDomainAlertSubscriptionsWithCustomData(testDomains, "testSubs")

	response, _ := enzoicClient.DeleteDomainAlertSubscriptionsByCustomData("testSubs")
	assert.Equal(t, 2, response.Deleted)
	assert.Equal(t, 0, response.NotFound)
}

func TestEnzoic_IsDomainSubscribedForAlerts(t *testing.T) {
	enzoicClient := GetEnzoicClient()

	testDomains := []string{
		"testadddomain1.com",
		"testadddomain2.com",
	}

	// add test subscriptions
	enzoicClient.AddDomainAlertSubscriptions(testDomains)

	response, _ := enzoicClient.IsDomainSubscribedForAlerts(testDomains[0])
	assert.True(t, response)

	response, _ = enzoicClient.IsDomainSubscribedForAlerts(testDomains[1])
	assert.True(t, response)

	response, _ = enzoicClient.IsDomainSubscribedForAlerts("not_a_monitored_user_domain.com")
	assert.False(t, response)
}

func TestEnzoic_GetDomainAlertSubscriptions(t *testing.T) {
	enzoicClient, _ := NewClient(os.Getenv("PP_API_KEY"), os.Getenv("PP_API_SECRET"))

	testDomains := []string{
		"testadddomain1.com",
		"testadddomain2.com",
	}

	// clean out existing subscriptions
	getResponse, _ := enzoicClient.GetDomainAlertSubscriptions(100, "")
	enzoicClient.DeleteDomainAlertSubscriptions(getResponse.Domains)

	// add test subscriptions
	response2, err := enzoicClient.AddDomainAlertSubscriptions(testDomains)
	assert.Nil(t, err)
	assert.Equal(t, 2, response2.Added)

	response, err := enzoicClient.GetDomainAlertSubscriptions(1, "")
	assert.Nil(t, err)
	assert.Equal(t, GetDomainSubscriptionsResponse{
		Domains:     []string{"testadddomain1.com"},
		Count:       2,
		PagingToken: response.PagingToken,
	}, *response)

	response, _ = enzoicClient.GetDomainAlertSubscriptions(1, response.PagingToken)
	assert.Equal(t, GetDomainSubscriptionsResponse{
		Domains:     []string{"testadddomain2.com"},
		Count:       2,
		PagingToken: "",
	}, *response)
}

func TestEnzoic_GetDomainAlertSubscriptionsWithExtendedInfo(t *testing.T) {
	enzoicClient, _ := NewClient(os.Getenv("PP_API_KEY"), os.Getenv("PP_API_SECRET"))

	testDomains := []string{
		"testadddomain1.com",
		"testadddomain2.com",
	}

	// clean out existing subscriptions
	getResponse, _ := enzoicClient.GetDomainAlertSubscriptions(100, "")
	enzoicClient.DeleteDomainAlertSubscriptions(getResponse.Domains)

	// add test subscriptions
	response2, err := enzoicClient.AddDomainAlertSubscriptions(testDomains)
	assert.Nil(t, err)
	assert.Equal(t, 2, response2.Added)

	response, err := enzoicClient.GetDomainAlertSubscriptionsWithExtendedInfo(1, "")
	assert.Nil(t, err)
	assert.Equal(t, GetDomainSubscriptionsWithExtendedInfoResponse{
		Domains: []DomainWithExtendedInfo{
			{
				Domain:     "testadddomain1.com",
				WebhookID:  "668d9784b79968eab0657905",
				WebhookURL: "https://api.passwordping.com/webhook",
				CustomData: "",
			},
		},
		Count:       2,
		PagingToken: response.PagingToken,
	}, *response)

	response, _ = enzoicClient.GetDomainAlertSubscriptionsWithExtendedInfo(1, response.PagingToken)
	assert.Equal(t, GetDomainSubscriptionsWithExtendedInfoResponse{
		Domains: []DomainWithExtendedInfo{
			{
				Domain:     "testadddomain2.com",
				WebhookID:  "668d9784b79968eab0657905",
				WebhookURL: "https://api.passwordping.com/webhook",
				CustomData: "",
			},
		},
		Count:       2,
		PagingToken: "",
	}, *response)
}

func TestEnzoic_GetDomainAlertSubscriptionsByCustomData(t *testing.T) {
	enzoicClient, _ := NewClient(os.Getenv("PP_API_KEY"), os.Getenv("PP_API_SECRET"))

	testDomains := []string{
		"testadddomain1.com",
		"testadddomain2.com",
	}

	// clean out existing subscriptions
	getResponse, _ := enzoicClient.GetDomainAlertSubscriptions(100, "")
	enzoicClient.DeleteDomainAlertSubscriptions(getResponse.Domains)

	// add test subscriptions
	response2, err := enzoicClient.AddDomainAlertSubscriptionsWithCustomData(testDomains, "testSubs")
	assert.Nil(t, err)
	assert.Equal(t, 2, response2.Added)

	response, err := enzoicClient.GetDomainAlertSubscriptionsByCustomData("testSubs", 1, "")
	assert.Nil(t, err)
	assert.Equal(t, GetDomainSubscriptionsWithExtendedInfoResponse{
		Domains: []DomainWithExtendedInfo{
			{
				Domain:     "testadddomain1.com",
				WebhookID:  "668d9784b79968eab0657905",
				WebhookURL: "https://api.passwordping.com/webhook",
				CustomData: "testSubs",
			},
		},
		Count:       2,
		PagingToken: response.PagingToken,
	}, *response)

	response, _ = enzoicClient.GetDomainAlertSubscriptionsWithExtendedInfo(1, response.PagingToken)
	assert.Equal(t, GetDomainSubscriptionsWithExtendedInfoResponse{
		Domains: []DomainWithExtendedInfo{
			{
				Domain:     "testadddomain2.com",
				WebhookID:  "668d9784b79968eab0657905",
				WebhookURL: "https://api.passwordping.com/webhook",
				CustomData: "testSubs",
			},
		},
		Count:       2,
		PagingToken: "",
	}, *response)
}

func TestEnzoic(t *testing.T) {
	enzoicClient, err := NewClient(os.Getenv("PP_API_KEY"), os.Getenv("PP_API_SECRET"))
	if err != nil {
		panic(err)
	}

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
		[]PasswordType{BCrypt, SCrypt}, false)
	if err != nil {
		panic(err)
	}

	if credsCompromised {
		fmt.Println("Credentials are compromised")
	} else {
		fmt.Println("Credentials are not compromised")
	}

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
}

func GetEnzoicClient() *Client {
	enzoicClient, err := NewClient(os.Getenv("PP_API_KEY"), os.Getenv("PP_API_SECRET"))
	if err != nil {
		panic(err)
	}
	return enzoicClient
}
