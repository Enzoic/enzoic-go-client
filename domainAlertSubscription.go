package enzoic

type DomainAlertSubscription struct {
	Domain     string `json:"domain"`
	CustomData string `json:"customData"`
}
