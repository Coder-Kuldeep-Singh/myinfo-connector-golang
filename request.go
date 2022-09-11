package myinfoconnectorgolang

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

/*
This function is a wrapper to make https call.
Returns the response of the hit api.
*/
func SendRequest(request *http.Request) ([]byte, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	httpResponse, err := client.Do(request)
	if err != nil {
		return []byte{}, err
	}
	defer httpResponse.Body.Close()

	response, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return []byte{}, err
	}
	if httpResponse.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("%s %d\nresponse: %s", UNEXPECTED_STATUS_CODE, httpResponse.StatusCode, string(response))
		return []byte{}, errors.New(msg)
	}

	return response, nil
}
