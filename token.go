package sinpass

import (
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/mavensingh/myinfo-connector-golang/common"
	"github.com/mavensingh/myinfo-connector-golang/lib"
)

func (appConfig MyInfoConfig) GetAccessToken(authCode string, state string) (map[string]interface{}, error) {
	if !isInitialized {
		return nil, errors.New(common.ERROR_UNKNOWN_NOT_INIT)
	}

	var tokenData map[string]interface{}
	privateKey, err := lib.DecryptPrivateKey(appConfig.CLIENT_SECURE_CERT, appConfig.CLIENT_SECURE_CERT_PASSPHRASE)
	if err != nil {
		return tokenData, err
	}

	resp, err := appConfig.CallTokenAPI(authCode, privateKey, state)
	if err != nil {
		return tokenData, err
	}

	err = lib.Unmarshal(resp, &tokenData)
	if err != nil {
		return tokenData, err
	}

	return tokenData, nil
}

func (appConfig MyInfoConfig) CallTokenAPI(authCode string, privateKey *rsa.PrivateKey, state string) ([]byte, error) {
	if !isInitialized {
		return nil, errors.New(common.ERROR_UNKNOWN_NOT_INIT)
	}

	var response []byte
	var err error

	value := url.Values{}
	value.Set(common.PARAM_REDIRECT_URL, appConfig.REDIRECT_URL)
	value.Set(common.PARAM_CLIENT_ID, appConfig.CLIENT_ID)
	value.Set(common.PARAM_CLIENT_SECRET, appConfig.CLIENT_SECRET)
	value.Set(common.PARAM_CODE, authCode)
	value.Set(common.PARAM_GRANT_TYPE, common.AUTHORIZATION_CODE)

	params := lib.ParamsSort{
		{
			Name:  common.PARAM_GRANT_TYPE,
			Value: common.AUTHORIZATION_CODE,
		},
		{
			Name:  common.PARAM_CLIENT_ID,
			Value: appConfig.CLIENT_ID,
		},
		{
			Name:  common.PARAM_CLIENT_SECRET,
			Value: appConfig.CLIENT_SECRET,
		},
		{
			Name:  common.PARAM_CODE,
			Value: authCode,
		},
		{
			Name:  common.PARAM_REDIRECT_URL,
			Value: appConfig.REDIRECT_URL,
		},
	}

	if strings.TrimSpace(state) != "" {
		value.Set(common.PARAM_STATE, state)
		params = append(params, lib.Params{
			Name:  common.PARAM_STATE,
			Value: state,
		})
	}

	request, err := http.NewRequest(common.HTTP_METHOD_POST, appConfig.TOKEN_URL, strings.NewReader(value.Encode()))
	if err != nil {
		return response, err
	}

	var authHeader string

	if appConfig.ENVIRONMENT == common.SINPASS_SANDBOX_ENVIRONMENT {
		// No Headers
	} else if (appConfig.ENVIRONMENT == common.SINPASS_TEST_ENVIRONMENT) || (appConfig.ENVIRONMENT == common.SINPASS_PRODUCTION_ENVIRONMENT) {
		authHeader, err = lib.GenerateAuthorizationHeader(
			appConfig.TOKEN_URL,
			params,
			common.HTTP_METHOD_POST,
			common.CONTENT_TYPE,
			appConfig.ENVIRONMENT,
			appConfig.CLIENT_ID,
			privateKey,
			appConfig.CLIENT_SECRET,
		)
		if err != nil {
			return response, err
		}
	} else {
		return response, errors.New(common.ERROR_UNKNOWN_AUTH_LEVEL)
	}

	request.Header.Set(common.CONTENT, common.CONTENT_TYPE)
	request.Header.Add(common.CACHE_CONTROL, common.NO_CACHE)
	if authHeader != "" {
		request.Header.Add(common.AUTHORIZATION, authHeader)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	httpResponse, err := client.Do(request)
	if err != nil {
		return response, err
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("%s %d", common.UNEXPECTED_STATUS_CODE, httpResponse.StatusCode)
		return response, errors.New(msg)
	}

	response, err = ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return response, err
	}

	return response, nil
}
