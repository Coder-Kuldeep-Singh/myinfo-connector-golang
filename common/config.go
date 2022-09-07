package common

type AppConfig struct {
	MYINFO_SIGNATURE_CERT_PUBIC_CERT string
	CLIENT_ID                        string
	CLIENT_SECRET                    string
	CLIENT_SECURE_CERT               string
	CLIENT_SECURE_CERT_PASSPHRASE    string
	REDIRECT_URL                     string
	ATTRIBUTES                       string
	ENVIRONMENT                      string
	TOKEN_URL                        string
	PERSON_URL                       string

	// Proxy parameters (OPTIONAL)
	USE_PROXY        string // Indicate whether proxy url is used. i.e Y or N
	PROXY_TOKEN_URL  string // Configure your proxy url here, if any
	PROXY_PERSON_URL string // Configure your proxy url here, if anys
}
