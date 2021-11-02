package mcgc

import (
	"crypto/tls"
	"time"
)

type MCbearers struct {
	Bearers []string
}

var (
	redirect     string
	bearerReturn string
	sendTime     []time.Time
	statusCode   []string
	recv         []time.Time
)

type Payload struct {
	Payload []string
	Conns   []*tls.Conn
	UNIX    int64 `json:"UNIX,omitempty"`
}

type bearerMs struct {
	Bearer string `json:"access_token"`
}
