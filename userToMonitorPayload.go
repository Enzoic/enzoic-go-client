package enzoic

type UserToMonitorPayload struct {
	UsernameHash string `json:"usernameHash"`
	CustomData   string `json:"customData"`
}
