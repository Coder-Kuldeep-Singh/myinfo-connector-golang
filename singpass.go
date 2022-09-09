package myinfoconnectorgolang

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"strings"

	"github.com/mavensingh/myinfo-connector-golang/common"
	"github.com/mavensingh/myinfo-connector-golang/lib"
)

var isInitialized bool

type AppConfig struct {
	MYINFO_SIGNATURE_CERT_PUBIC_CERT string
	CLIENT_ID                        string
	CLIENT_SECRET                    string
	CLIENT_SECURE_CERT               string
	CLIENT_SECURE_CERT_PASSPHRASE    string
	REDIRECT_URL                     string
	PURPOSE                          string
	ATTRIBUTES                       string
	ENVIRONMENT                      string
	TOKEN_URL                        string
	PERSON_URL                       string

	// Proxy parameters (OPTIONAL)
	USE_PROXY        string // Indicate whether proxy url is used. i.e Y or N
	PROXY_TOKEN_URL  string // Configure your proxy url here, if any
	PROXY_PERSON_URL string // Configure your proxy url here, if anys
}

// MyInfoConnector passes the
func MyInfoConnector(appConfig AppConfig) error {
	err := appConfig.CheckConfig()
	if err != nil {
		return err
	}
	isInitialized = true
	return nil
}

func (appConfig AppConfig) CheckConfig() error {
	if strings.TrimSpace(appConfig.MYINFO_SIGNATURE_CERT_PUBIC_CERT) == "" {
		return errors.New(common.ERROR_CONFIGURATION_ATTRIBUTES_NOT_FOUND)
	}
	if strings.TrimSpace(appConfig.CLIENT_ID) == "" {
		return errors.New(common.ERROR_CONFIGURATION_CLIENT_ID_NOT_FOUND)
	}
	if strings.TrimSpace(appConfig.CLIENT_SECRET) == "" {
		return errors.New(common.ERROR_CONFIGURATION_CLIENT_SECRET_NOT_FOUND)
	}
	if strings.TrimSpace(appConfig.REDIRECT_URL) == "" {
		return errors.New(common.ERROR_CONFIGURATION_REDIRECT_URL_NOT_FOUND)
	}
	if strings.TrimSpace(appConfig.CLIENT_SECURE_CERT) == "" {
		return errors.New(common.ERROR_CONFIGURATION_CLIENT_SECURE_CERT_NOT_FOUND)
	}
	if strings.TrimSpace(appConfig.CLIENT_SECURE_CERT_PASSPHRASE) == "" {
		return errors.New(common.ERROR_CONFIGURATION_CLIENT_SECURE_CERT_PASSPHRASE_NOT_FOUND)
	}
	if strings.TrimSpace(appConfig.ENVIRONMENT) == "" {
		return errors.New(common.ERROR_CONFIGURATION_ENVIRONMENT_NOT_FOUND)
	}
	if strings.TrimSpace(appConfig.TOKEN_URL) == "" {
		return errors.New(common.ERROR_CONFIGURATION_TOKEN_URL_NOT_FOUND)
	}
	if strings.TrimSpace(appConfig.PERSON_URL) == "" {
		return errors.New(common.ERROR_CONFIGURATION_PERSON_URL_NOT_FOUND)
	}
	if strings.TrimSpace(appConfig.ATTRIBUTES) == "" {
		return errors.New(common.ERROR_CONFIGURATION_ATTRIBUTES_NOT_FOUND)
	}

	if strings.TrimSpace(appConfig.USE_PROXY) == "Y" {
		if strings.TrimSpace(appConfig.PROXY_TOKEN_URL) == "" {
			return errors.New(common.ERROR_CONFIGURATION_PROXY_TOKEN_URL_NOT_FOUND)
		}
		if strings.TrimSpace(appConfig.PROXY_PERSON_URL) == "" {
			return errors.New(common.ERROR_CONFIGURATION_PROXY_PERSON_URL_NOT_FOUND)
		}
	}
	return nil
}

func (appConfig AppConfig) GetMyInfoPersonData(authCode, state string) ([]byte, error) {
	if !isInitialized {
		return nil, errors.New(common.ERROR_UNKNOWN_NOT_INIT)
	}

	var personData []byte
	var err error

	txnNo, err := lib.GenerateRandomHex(10)
	if err != nil {
		return personData, err
	}

	token, err := appConfig.GetAccessToken(authCode, state)
	if err != nil {
		return personData, err
	}

	var data map[string]interface{}
	err = json.NewDecoder(bytes.NewBuffer(token)).Decode(&data)
	if err != nil {
		return personData, err
	}

	log.Println("TOKEN API RESPONSE: ", data)
	log.Println("ACCESS TOKEN: ", data["access_token"].(string))

	personData, err = appConfig.GetPersonData(data["access_token"].(string), txnNo)
	if err != nil {
		return personData, err
	}

	return personData, nil
}
