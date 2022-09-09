package lib

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/mavensingh/myinfo-connector-golang/common"
	"golang.org/x/oauth2/jws"
	"gopkg.in/square/go-jose.v2"
	"software.sslmate.com/src/go-pkcs12"
)

type Params struct {
	Name  string
	Value string
}

type ParamsSort []Params

func (slice ParamsSort) Len() int {
	return len(slice)
}

func (slice ParamsSort) Less(i, j int) bool {
	return slice[i].Name < slice[j].Name
}

func (slice ParamsSort) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func spaceFieldsJoin(str string) string {
	return strings.Join(strings.Fields(str), "")
}

func GenerateSignature(privateKey *rsa.PrivateKey, baseString string) (string, error) {
	h := sha256.New()
	h.Write([]byte(baseString))
	d := h.Sum(nil)

	sigBin, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, d)
	if err != nil {
		return "", err
	}

	encodeSignature := base64.StdEncoding.EncodeToString(sigBin)
	return encodeSignature, nil
}

func GenerateBaseString(httpMethod string, apiURL string, appId string, params ParamsSort, contentType string, nonceValue string, timestamp string) string {
	var defaultAuthHeader = []Params{
		{
			Name:  common.APP_ID,
			Value: appId,
		},
		{
			Name:  common.NONCE,
			Value: nonceValue,
		},
		{
			Name:  common.SIGNATURE_METHOD,
			Value: common.RS256,
		},
		{
			Name:  common.TIMESTAMP,
			Value: timestamp,
		},
	}

	// Remove params unless Content-Type is "application/x-www-form-urlencoded"
	if (httpMethod == common.HTTP_METHOD_POST) && (contentType != common.CONTENT_TYPE) {
		params = ParamsSort{}
	} else {
		params = append(params, defaultAuthHeader...)
	}

	sort.Sort(params)

	var strParams string
	for _, v := range params {
		strParams += fmt.Sprintf("&%s=%s", v.Name, v.Value)
	}

	// concatenate request elements (HTTP method + url + base string parameters)
	baseString := httpMethod + "&" + apiURL + spaceFieldsJoin(strParams)
	return baseString
}

func DecryptPrivateKey(secureCertLocation string, passphrase string) (*rsa.PrivateKey, error) {
	fileData, err := ioutil.ReadFile(secureCertLocation)
	if err != nil {
		return nil, err
	}
	parsedKey, _, _, err := pkcs12.DecodeChain(fileData, passphrase)
	if err != nil {
		return nil, err
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New(common.FAILED_TO_PARSE_RSA_PRIVATE_KEY)
	}

	return privateKey, nil
}

func GenerateRandomHex(count int) (string, error) {
	bytes := make([]byte, count)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	randomHex := hex.EncodeToString(bytes)
	return randomHex, nil
}

func GenerateAuthorizationHeader(apiURL string, params ParamsSort, httpMethod string, contentType string, environment string, appId string, privateKey *rsa.PrivateKey, clientSecret string) (string, error) {
	nonceValue, err := GenerateRandomHex(20)
	if err != nil {
		return "", err
	}
	timestamp := strconv.Itoa(int(time.Now().UnixMilli()))

	if (environment == common.SINPASS_TEST_ENVIRONMENT) || (environment == common.SINPASS_PRODUCTION_ENVIRONMENT) {
		// Only when environment is TEST or PRODUCTION
		baseString := GenerateBaseString(httpMethod, apiURL, appId, params, contentType, nonceValue, timestamp)

		signature, err := GenerateSignature(privateKey, baseString)
		if err != nil {
			return "", err
		}

		strAuthHeader := "PKI_SIGN timestamp=\"" + timestamp +
			"\",nonce=\"" + nonceValue +
			"\",app_id=\"" + appId +
			"\",signature_method=\"RS256\"" +
			",signature=\"" + signature +
			"\""
		return strAuthHeader, nil
	} else {
		return "", nil
	}
}

func Decode(payload string) ([]byte, error) {
	s := strings.Split(payload, ".")
	if len(s) < 2 {
		return nil, errors.New(common.INVALID_TOKEN)
	}

	decodedData, err := base64.RawStdEncoding.DecodeString(s[1])
	if err != nil {
		return nil, err
	}
	return decodedData, err
}

func VerifyJWS(publicCert string, accessToken string) ([]byte, error) {
	keyData, err := ioutil.ReadFile(publicCert)
	if err != nil {
		return nil, err
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return nil, err
	}

	err = jws.Verify(accessToken, key)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(accessToken, ".")
	err = jwt.SigningMethodRS256.Verify(strings.Join(parts[0:2], "."), parts[2], key)
	if err != nil {
		return nil, err
	}

	claimSet, err := Decode(accessToken)
	if err != nil {
		return nil, err
	}
	log.Println("JWS DECODE PASSED")
	return claimSet, nil
}

func DecryptJWE(pemPrivaKey *rsa.PrivateKey, compactJWE string) (string, error) {
	payload, err := jose.ParseEncrypted(compactJWE)
	if err != nil {
		return "", err
	}
	decrypted, err := payload.Decrypt(pemPrivaKey)
	if err != nil {
		return "", err
	}
	fmt.Println("vl", payload, "\nres", string(decrypted), "\nerr", err)

	return string(decrypted), nil
}

func Unmarshal(data []byte, v interface{}) error {
	err := json.Unmarshal(data, v)
	if err != nil {
		return err
	}
	return nil
}

func AuthHeader(apiURL string, params ParamsSort, httpMethod string, contentType string, environment string, appId string, privateKey *rsa.PrivateKey, clientSecret string) (string, error) {
	var authHeader string
	var err error

	if environment == common.SINPASS_SANDBOX_ENVIRONMENT {
		// No Headers
	} else if (environment == common.SINPASS_TEST_ENVIRONMENT) || (environment == common.SINPASS_PRODUCTION_ENVIRONMENT) {
		authHeader, err = GenerateAuthorizationHeader(
			apiURL,
			params,
			common.HTTP_METHOD_POST,
			common.CONTENT_TYPE,
			environment,
			appId,
			privateKey,
			clientSecret,
		)
		if err != nil {
			return authHeader, err
		}
	} else {
		return authHeader, errors.New(common.ERROR_UNKNOWN_AUTH_LEVEL)
	}
	return authHeader, nil
}
