package myinfoconnectorgolang

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/mavensingh/myinfo-connector-golang/common"
)

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
		msg := fmt.Sprintf("%s %d\nresponse: %s", common.UNEXPECTED_STATUS_CODE, httpResponse.StatusCode, string(response))
		return []byte{}, errors.New(msg)
	}

	return response, nil
}
