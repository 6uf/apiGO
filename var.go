package mcapi2

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
