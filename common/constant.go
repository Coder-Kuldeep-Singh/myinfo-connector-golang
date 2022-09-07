package common

import "net/http"

const (
	ERROR                                                       string = "error"
	OK                                                          string = "OK"
	INVALID_TOKEN                                               string = "invalid token"
	UINFIN_NOT_FOUND                                            string = "uinfin not found"
	PERSON_DATA_NOT_FOUND                                       string = "person data not found"
	INVALID_DATA_OR_SIGNATURE                                   string = "invalid data or signature for person data"
	ERROR_CONFIGURATION_PUBLIC_CERT_NOT_FOUND                   string = "public cert not found"
	ERROR_CONFIGURATION_CLIENT_ID_NOT_FOUND                     string = "client id not found"
	ERROR_CONFIGURATION_CLIENT_SECRET_NOT_FOUND                 string = "client secret not found"
	ERROR_CONFIGURATION_REDIRECT_URL_NOT_FOUND                  string = "redirect URL not found"
	ERROR_CONFIGURATION_CLIENT_SECURE_CERT_NOT_FOUND            string = "client secure cert not found"
	ERROR_CONFIGURATION_CLIENT_SECURE_CERT_PASSPHRASE_NOT_FOUND string = "client passphrase not found"
	ERROR_CONFIGURATION_ENVIRONMENT_NOT_FOUND                   string = "environment not found"
	ERROR_CONFIGURATION_TOKEN_URL_NOT_FOUND                     string = "token URL not found"
	ERROR_CONFIGURATION_PERSON_URL_NOT_FOUND                    string = "person URL not found"
	ERROR_CONFIGURATION_ATTRIBUTES_NOT_FOUND                    string = "attributes not found"
	ERROR_CONFIGURATION_PROXY_TOKEN_URL_NOT_FOUND               string = "proxy Token URL not found"
	ERROR_CONFIGURATION_PROXY_PERSON_URL_NOT_FOUND              string = "proxy Person URL not found"
	ERROR_UNKNOWN_AUTH_LEVEL                                    string = "unknown Auth Level"
	ERROR_UNKNOWN_NOT_INIT                                      string = "configurations not initialized"
	HTTP_METHOD_GET                                             string = http.MethodGet
	HTTP_METHOD_POST                                            string = http.MethodPost
	CONTENT_TYPE                                                string = "application/x-www-form-urlencoded"
	FAILED_TO_PARSE_RSA_PRIVATE_KEY                             string = "unable to parse rsa private key"
	SINPASS_TEST_ENVIRONMENT                                    string = "TEST"
	SINPASS_SANDBOX_ENVIRONMENT                                 string = "SANDBOX"
	SINPASS_PRODUCTION_ENVIRONMENT                              string = "PRODUCTION"
)
