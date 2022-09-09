package myinfoconnectorgolang

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/mavensingh/myinfo-connector-golang/common"
	"github.com/mavensingh/myinfo-connector-golang/lib"
)

func (appConfig AppConfig) GetPersonData(accessToken, txnNo string) ([]byte, error) {
	if !isInitialized {
		return nil, errors.New(common.ERROR_UNKNOWN_NOT_INIT)
	}

	privateKey, err := lib.DecryptPrivateKey(appConfig.CLIENT_SECURE_CERT, appConfig.CLIENT_SECURE_CERT_PASSPHRASE)
	if err != nil {
		return nil, err
	}

	personData, err := appConfig.GetPersonDataWithKey(accessToken, txnNo, privateKey)
	if err != nil {
		return nil, err
	}

	return personData, nil

}

func (appConfig AppConfig) GetPersonDataWithKey(accessToken, txnNo string, privateKey *rsa.PrivateKey) ([]byte, error) {
	if !isInitialized {
		return nil, errors.New(common.ERROR_UNKNOWN_NOT_INIT)
	}
	var resp []byte

	tokenBytes, err := lib.VerifyJWS(appConfig.MYINFO_SIGNATURE_CERT_PUBIC_CERT, accessToken)
	if err != nil {
		return resp, err
	}

	var data map[string]interface{}
	err = json.NewDecoder(bytes.NewBuffer(tokenBytes)).Decode(&data)
	if err != nil {
		return resp, err
	}

	if data["sub"].(string) != "" {
		personBytes, err := appConfig.CallPersonAPI(data["sub"].(string), accessToken, txnNo, privateKey)
		if err != nil {
			return resp, err
		}
		if appConfig.ENVIRONMENT == common.SINPASS_SANDBOX_ENVIRONMENT {
			err := lib.Unmarshal(personBytes, &resp)
			if err != nil {
				return resp, err
			}
		}

		decryptedRes, err := lib.DecryptJWE(privateKey, string(personBytes))
		if err != nil {
			return resp, err
		}

		decodedData, err := lib.Decode(decryptedRes)
		if err != nil {
			return resp, err
		}

		return decodedData, nil
	}

	return resp, errors.New(common.UINFIN_NOT_FOUND)

}

func (appConfig AppConfig) CallPersonAPI(sub, accessToken, txnNo string, privateKey *rsa.PrivateKey) ([]byte, error) {
	if !isInitialized {
		return nil, errors.New(common.ERROR_UNKNOWN_NOT_INIT)
	}

	var response []byte
	var err error

	callPersonURL := appConfig.PERSON_URL + "/" + sub + "/"

	params := lib.ParamsSort{
		{
			Name:  common.PARAM_CLIENT_ID,
			Value: appConfig.CLIENT_ID,
		},
		{
			Name:  common.PARAM_ATTRIBUTES,
			Value: appConfig.ATTRIBUTES,
		},
	}

	var txnExists bool
	if txnNo != "" {
		params = append(params, lib.Params{
			Name:  common.PARAM_TXNNO,
			Value: txnNo,
		})
		txnExists = true
	}

	authHeader, err := lib.AuthHeader(
		callPersonURL,
		params,
		common.HTTP_METHOD_GET,
		"",
		appConfig.ENVIRONMENT,
		appConfig.CLIENT_ID,
		privateKey,
		appConfig.CLIENT_SECRET,
	)
	if err != nil {
		return response, err
	}

	callPersonURL += "?" + common.PARAM_CLIENT_ID + "=" + appConfig.CLIENT_ID + "&" + common.PARAM_ATTRIBUTES + "=" + appConfig.ATTRIBUTES
	if txnExists {
		callPersonURL += "&" + common.PARAM_TXNNO + "=" + txnNo
	}

	request, err := http.NewRequest(common.HTTP_METHOD_GET, callPersonURL, nil)
	if err != nil {
		return response, err
	}
	request.Header.Set(common.CACHE_CONTROL, common.NO_CACHE)
	if authHeader != "" {
		request.Header.Set(common.AUTHORIZATION, authHeader+","+common.BEARER+" "+accessToken)
	} else {
		request.Header.Set(common.AUTHORIZATION, common.BEARER+" "+accessToken)
	}

	response, err = SendRequest(request)
	if err != nil {
		return response, err
	}

	return response, nil

}
