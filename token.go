package myinfoconnectorgolang

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

/*
This method calls the Token API and obtain an "access token" from response,
which can be used to call the Person API for the actual data.
Your application needs to provide a valid "authorisation code"
from the authorise API(callback) in exchange for the valid "access token".
Returns the Access Token API response as []byte which includes all data sent by Access Token API.
*/

func (appConfig AppConfig) GetAccessToken(authCode string, state string) ([]byte, error) {
	if !isInitialized {
		return nil, errors.New(ERROR_UNKNOWN_NOT_INIT)
	}

	var tokenData []byte
	privateKey, err := DecryptPrivateKey(appConfig.CLIENT_SECURE_CERT, appConfig.CLIENT_SECURE_CERT_PASSPHRASE)
	if err != nil {
		return tokenData, err
	}

	tokenData, err = appConfig.CallTokenAPI(authCode, privateKey, state)
	if err != nil {
		return tokenData, err
	}

	return tokenData, nil
}

/*
This method will generate the Authorization Header and call the Token API to retrieve access token.
Returns the full json response as []byte.
*/
func (appConfig AppConfig) CallTokenAPI(authCode string, privateKey *rsa.PrivateKey, state string) ([]byte, error) {
	if !isInitialized {
		return nil, errors.New(ERROR_UNKNOWN_NOT_INIT)
	}

	var response []byte
	var err error

	value := url.Values{}
	value.Set(PARAM_REDIRECT_URL, appConfig.REDIRECT_URL)
	value.Set(PARAM_CLIENT_ID, appConfig.CLIENT_ID)
	value.Set(PARAM_CLIENT_SECRET, appConfig.CLIENT_SECRET)
	value.Set(PARAM_CODE, authCode)
	value.Set(PARAM_GRANT_TYPE, AUTHORIZATION_CODE)

	params := ParamsSort{
		{
			Name:  PARAM_GRANT_TYPE,
			Value: AUTHORIZATION_CODE,
		},
		{
			Name:  PARAM_CLIENT_ID,
			Value: appConfig.CLIENT_ID,
		},
		{
			Name:  PARAM_CLIENT_SECRET,
			Value: appConfig.CLIENT_SECRET,
		},
		{
			Name:  PARAM_CODE,
			Value: authCode,
		},
		{
			Name:  PARAM_REDIRECT_URL,
			Value: appConfig.REDIRECT_URL,
		},
	}

	if strings.TrimSpace(state) != "" {
		value.Set(PARAM_STATE, state)
		params = append(params, Params{
			Name:  PARAM_STATE,
			Value: state,
		})
	}

	request, err := http.NewRequest(HTTP_METHOD_POST, appConfig.TOKEN_URL, strings.NewReader(value.Encode()))
	if err != nil {
		return response, err
	}

	authHeader, err := AuthHeader(
		appConfig.TOKEN_URL,
		params,
		HTTP_METHOD_POST,
		CONTENT_TYPE,
		appConfig.ENVIRONMENT,
		appConfig.CLIENT_ID,
		privateKey,
		appConfig.CLIENT_SECRET,
	)
	if err != nil {
		return response, err
	}

	request.Header.Set(CONTENT, CONTENT_TYPE)
	request.Header.Add(CACHE_CONTROL, NO_CACHE)
	if authHeader != "" {
		request.Header.Add(AUTHORIZATION, authHeader)
	}

	response, err = SendRequest(request)
	if err != nil {
		return response, err
	}

	return response, nil
}
