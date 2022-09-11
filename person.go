package myinfoconnectorgolang

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
)

/*
This method calls the Person API and returns a JSON response with the personal data that was requested.
Your application needs to provide a valid "access token" in exchange for the JSON data.
Once your application receives this JSON data, you can use this data.
Returns the Person Data (Payload decrypted + Signature validated).
*/

func (appConfig AppConfig) GetPersonData(accessToken, txnNo string) ([]byte, error) {
	if !isInitialized {
		return nil, errors.New(ERROR_UNKNOWN_NOT_INIT)
	}

	privateKey, err := DecryptPrivateKey(appConfig.CLIENT_SECURE_CERT, appConfig.CLIENT_SECURE_CERT_PASSPHRASE)
	if err != nil {
		return nil, err
	}

	personData, err := appConfig.GetPersonDataWithKey(accessToken, txnNo, privateKey)
	if err != nil {
		return nil, err
	}

	return personData, nil

}

/*
This method will take in the accessToken from Token API and decode it to get the sub(eg either uinfin or uuid).
It will call the Person API using the token and sub.
It will verify the Person API data's signature and decrypt the result.
Returns decrypted result from calling Person API.
*/
func (appConfig AppConfig) GetPersonDataWithKey(accessToken, txnNo string, privateKey *rsa.PrivateKey) ([]byte, error) {
	if !isInitialized {
		return nil, errors.New(ERROR_UNKNOWN_NOT_INIT)
	}
	var resp []byte

	tokenBytes, err := VerifyJWS(appConfig.MYINFO_SIGNATURE_CERT_PUBIC_CERT, accessToken)
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
		if appConfig.ENVIRONMENT == SINPASS_SANDBOX_ENVIRONMENT {
			err := Unmarshal(personBytes, &resp)
			if err != nil {
				return resp, err
			}
		}

		decryptedRes, err := DecryptJWE(privateKey, string(personBytes))
		if err != nil {
			return resp, err
		}

		decodedData, err := Decode(decryptedRes)
		if err != nil {
			return resp, err
		}

		return decodedData, nil
	}

	return resp, errors.New(UINFIN_NOT_FOUND)

}

/*
This method will generate the Authorization Header and call the Person API to get the encrypted Person Data.
Returns result from calling Person API.
*/
func (appConfig AppConfig) CallPersonAPI(sub, accessToken, txnNo string, privateKey *rsa.PrivateKey) ([]byte, error) {
	if !isInitialized {
		return nil, errors.New(ERROR_UNKNOWN_NOT_INIT)
	}

	var response []byte
	var err error

	callPersonURL := appConfig.PERSON_URL + "/" + sub + "/"

	params := ParamsSort{
		{
			Name:  PARAM_CLIENT_ID,
			Value: appConfig.CLIENT_ID,
		},
		{
			Name:  PARAM_ATTRIBUTES,
			Value: appConfig.ATTRIBUTES,
		},
	}

	var txnExists bool
	if txnNo != "" {
		params = append(params, Params{
			Name:  PARAM_TXNNO,
			Value: txnNo,
		})
		txnExists = true
	}

	authHeader, err := AuthHeader(
		callPersonURL,
		params,
		HTTP_METHOD_GET,
		"",
		appConfig.ENVIRONMENT,
		appConfig.CLIENT_ID,
		privateKey,
		appConfig.CLIENT_SECRET,
	)
	if err != nil {
		return response, err
	}

	callPersonURL += "?" + PARAM_CLIENT_ID + "=" + appConfig.CLIENT_ID + "&" + PARAM_ATTRIBUTES + "=" + appConfig.ATTRIBUTES
	if txnExists {
		callPersonURL += "&" + PARAM_TXNNO + "=" + txnNo
	}

	request, err := http.NewRequest(HTTP_METHOD_GET, callPersonURL, nil)
	if err != nil {
		return response, err
	}
	request.Header.Set(CACHE_CONTROL, NO_CACHE)
	if authHeader != "" {
		request.Header.Set(AUTHORIZATION, authHeader+","+BEARER+" "+accessToken)
	} else {
		request.Header.Set(AUTHORIZATION, BEARER+" "+accessToken)
	}

	response, err = SendRequest(request)
	if err != nil {
		return response, err
	}

	return response, nil

}
