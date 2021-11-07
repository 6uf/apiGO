package mcap

import (
	"crypto/tls"
	"time"
)

type MCbearers struct {
	Bearers     []string
	AccountType []string
}

var (
	redirect     string
	bearerReturn string
	sendTime     []time.Time
	statusCode   []string
	recv         []time.Time
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

type serverInfo struct {
	Webhook string
	SkinUrl string
}
