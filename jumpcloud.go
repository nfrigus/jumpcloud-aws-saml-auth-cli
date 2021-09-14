package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/PuerkitoBio/goquery"
)

type JumpCloudXSRFResponse struct {
	XSRF string
}

type JumpCloudSession struct {
	cookies []*http.Cookie
	topt    string
	xsrf    string
}

func (session JumpCloudSession) getSamlRequest() string {
	res, err := session.Request("GET", "https://sso.jumpcloud.com/saml2/aws", nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	saml := getInputValue(*res, "SAMLResponse")
	if saml == "" {
		log.Fatal("Fail to get SAML-request")
	}

	return saml
}

func getInputValue(res http.Response, input_name string) string {
	defer res.Body.Close()

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	query := fmt.Sprintf("[name=\"%s\"]", input_name)
	result, _ := doc.Find(query).Attr("value")

	return result
}

func (session JumpCloudSession) Request(
	method string,
	url string,
	data []byte,
	headers http.Header,
) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer(data))
	if err != nil {
		log.Fatal(err)
	}

	for _, cookie := range session.cookies {
		req.AddCookie(cookie)
	}

	for name, values := range headers {
		req.Header.Add(name, values[0])
	}

	client := &http.Client{}

	res, err := client.Do(req)

	return res, err
}

func (session JumpCloudSession) Login(email string, password string, otp string) JumpCloudSession {
	url := "https://console.jumpcloud.com/userconsole/auth"
	data, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})

	headers := http.Header{}
	headers.Add("Accept", "application/json")
	headers.Add("Content-Type", "application/json")
	headers.Add("X-Xsrftoken", session.xsrf)

	resp, err := session.Request("POST", url, data, headers)
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode == 401 && otp != "" {
		session.AuthenticateOTP(otp)
	} else if resp.StatusCode != 200 {
		log.Fatal("Fail to login JumpCloud")
	}

	return session
}

func (session JumpCloudSession) AuthenticateOTP(otp string) JumpCloudSession {
	url := "https://console.jumpcloud.com/userconsole/auth/mfa"
	data, _ := json.Marshal(map[string]string{
		"otp": otp,
	})

	headers := http.Header{}
	headers.Add("Accept", "application/json")
	headers.Add("Content-Type", "application/json")
	headers.Add("X-Xsrftoken", session.xsrf)

	resp, err := session.Request("POST", url, data, headers)
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode != 200 {
		log.Fatal("Fail to login JumpCloud MFA")
	}

	return session
}

func NewJumpCloudSession() JumpCloudSession {
	resp, err := http.Get("https://console.jumpcloud.com/userconsole/xsrf")
	if err != nil {
		log.Fatal(err)
	}

	var xsrf JumpCloudXSRFResponse
	json.Unmarshal(readResponseBody(*resp), &xsrf)

	if xsrf.XSRF == "" {
		log.Fatal("Fail to create JumpCloud session: unexpected xsrf response")
	}

	return JumpCloudSession{
		cookies: resp.Cookies(),
		xsrf:    xsrf.XSRF,
	}
}

func readResponseBody(res http.Response) []byte {
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	return body
}
