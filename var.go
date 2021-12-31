package m-api

import (
	"crypto/tls"
)

type MCbearers struct {
	Bearers     []string
	AccountType []string
}

var (
	redirect     string
	bearerReturn string
)

type Payload struct {
	Payload     []string
	Conns       []*tls.Conn
	UNIX        int64 `json:"UNIX,omitempty"`
	AccountType []string
}

type bearerMs struct {
	Bearer string `json:"access_token"`
}

type ServerInfo struct {
	Webhook string
	SkinUrl string
}

type securityRes struct {
	Answer answerRes `json:"answer"`
}

type answerRes struct {
	ID int `json:"id"`
}

type loginResponse struct {
	Token string `json:"accessToken"`
}

type accessTokenReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type accessTokenResp struct {
	AccessToken *string `json:"accessToken"`
}
