package enzoic

import "time"

type CredentialsHashSpecification struct {
	Salt            string
	HashType        PasswordType
	CredentialsHash string
}

type PasswordHashSpecification struct {
	Salt     string
	HashType PasswordType
}

type AccountsResponse struct {
	LastBreachDate         time.Time
	CredentialsHashes      []CredentialsHashSpecification
	PasswordHashesRequired []PasswordHashSpecification
	Salt                   string
}

type ExposuresResponse struct {
	Count     int      `json:"count"`
	Exposures []string `json:"exposures"`
}

type ExposureDetails struct {
	ID              string     `json:"id"`
	Title           string     `json:"title"`
	Entries         int64      `json:"entries"`
	Date            *time.Time `json:"date"`
	Category        string     `json:"category"`
	PasswordType    string     `json:"passwordType"`
	ExposedData     []string   `json:"exposedData"`
	DateAdded       *time.Time `json:"dateAdded"`
	SourceURLs      []string   `json:"sourceURLs"`
	DomainsAffected int        `json:"domainsAffected"`
}

type PasswordDetails struct {
	HashType  PasswordType `json:"hashType"`
	Password  string       `json:"password"`
	Salt      string       `json:"salt"`
	Exposures []string     `json:"exposures"`
}

type PasswordDetailsWithExposureDetails struct {
	HashType  PasswordType      `json:"hashType"`
	Password  string            `json:"password"`
	Salt      string            `json:"salt"`
	Exposures []ExposureDetails `json:"exposures"`
}

type UserPasswords struct {
	LastBreachDate time.Time         `json:"lastBreachDate"`
	Passwords      []PasswordDetails `json:"passwords"`
}

type UserPasswordsCandidatesFromUsingPartialHash struct {
	Candidates []UserPasswordsCandidateFromUsingPartialHash `json:"candidates"`
}

type UserPasswordsCandidateFromUsingPartialHash struct {
	UsernameHash string `json:"usernameHash"`
	UserPasswords
}

type UserPasswordsWithExposureDetails struct {
	LastBreachDate time.Time                            `json:"lastBreachDate"`
	Passwords      []PasswordDetailsWithExposureDetails `json:"passwords"`
}

type ExposedUserForDomain struct {
	Username  string   `json:"username"`
	Exposures []string `json:"exposures"`
}

type ExposedUsersForDomain struct {
	Count       int                    `json:"count"`
	Users       []ExposedUserForDomain `json:"users"`
	PagingToken string                 `json:"pagingToken"`
}

type ExposuresForDomain struct {
	Count       int      `json:"count"`
	Exposures   []string `json:"exposures"`
	PagingToken string   `json:"pagingToken"`
}

type ExposuresForDomainIncludeDetails struct {
	Count       int               `json:"count"`
	Exposures   []ExposureDetails `json:"exposures"`
	PagingToken string            `json:"pagingToken"`
}

type AddSubscriptionsResponse struct {
	Added          int `json:"added"`
	AlreadyExisted int `json:"alreadyExisted"`
}

type DeleteSubscriptionsResponse struct {
	Deleted  int `json:"deleted"`
	NotFound int `json:"notFound"`
}

type GetSubscriptionsResponse struct {
	Count          int      `json:"count"`
	UsernameHashes []string `json:"usernameHashes"`
	PagingToken    string   `json:"pagingToken"`
}

type GetDomainSubscriptionsResponse struct {
	Count       int      `json:"count"`
	Domains     []string `json:"domains"`
	PagingToken string   `json:"pagingToken"`
}
