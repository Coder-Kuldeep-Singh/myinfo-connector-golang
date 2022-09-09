package myinfoconnectorgolang

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/mavensingh/myinfo-connector-golang/common"
	"github.com/mavensingh/myinfo-connector-golang/lib"
)

func (appConfig AppConfig) GetAccessToken(authCode string, state string) ([]byte, error) {
	if !isInitialized {
		return nil, errors.New(common.ERROR_UNKNOWN_NOT_INIT)
	}

	var tokenData []byte
	privateKey, err := lib.DecryptPrivateKey(appConfig.CLIENT_SECURE_CERT, appConfig.CLIENT_SECURE_CERT_PASSPHRASE)
	if err != nil {
		return tokenData, err
	}

	tokenData, err = appConfig.CallTokenAPI(authCode, privateKey, state)
	if err != nil {
		return tokenData, err
	}

	return tokenData, nil
}

func (appConfig AppConfig) CallTokenAPI(authCode string, privateKey *rsa.PrivateKey, state string) ([]byte, error) {
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

	authHeader, err := lib.AuthHeader(
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

	request.Header.Set(common.CONTENT, common.CONTENT_TYPE)
	request.Header.Add(common.CACHE_CONTROL, common.NO_CACHE)
	if authHeader != "" {
		request.Header.Add(common.AUTHORIZATION, authHeader)
	}

	response, err = SendRequest(request)
	if err != nil {
		return response, err
	}

	return response, nil
}
