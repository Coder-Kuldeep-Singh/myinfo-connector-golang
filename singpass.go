package sinpass

import (
	"errors"
	"strings"

	"github.com/mavensingh/myinfo-connector-golang/common"
	"github.com/mavensingh/myinfo-connector-golang/lib"
)

var isInitialized bool

type MyInfoConfig common.AppConfig

// MyInfoConnector passes the
func MyInfoConnector(appConfig common.AppConfig) error {
	config := MyInfoConfig(appConfig)
	err := config.CheckConfig()
	if err != nil {
		return err
	}
	isInitialized = true
	return nil
}

func (appConfig MyInfoConfig) CheckConfig() error {
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

func (appConfig MyInfoConfig) GetMyInfoPersonData(authCode, state string) (map[string]interface{}, error) {
	if !isInitialized {
		return nil, errors.New(common.ERROR_UNKNOWN_NOT_INIT)
	}

	var personData map[string]interface{}
	var err error

	_, err = lib.GenerateRandomHex(10)
	if err != nil {
		return personData, err
	}

	accessToken, err := appConfig.GetAccessToken(authCode, state)
	if err != nil {
		return personData, err
	}

	return accessToken, nil
}
