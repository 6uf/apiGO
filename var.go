package apiGO

import (
	"crypto/tls"
	"net/http"
	"time"
)

func init() {
	acc.LoadState()
}

type Resp struct {
	SentAt     time.Time
	RecvAt     time.Time
	StatusCode string
}

type Payload struct {
	Payload []string
	Conns   []*tls.Conn

	UNIX     int64  `json:"unix"`
	Searches string `json:"searches"`

	errors      error
	searchBytes []byte
	resp        *http.Response
}

type ServerInfo struct {
	Webhook string
	SkinUrl string
}

type mojangData struct {
	Bearer     string `json:"accessToken"`
	Bearer_MS  string `json:"access_token"`
	NameChange bool   `json:"nameChangeAllowed"`
	Email      string
	Password   string
	Error      error
	Account    string
	JunkData   []byte
	LoginConn  *http.Response
}

type MCbearers struct {
	Details []Info
}

type Info struct {
	Bearer      string
	AccountType string
	Email       string
	Password    string
	Requests    int
	Error       string
}

type Config struct {
	ChangeSkinLink    string `json:"ChangeSkinLink"`
	ChangeskinOnSnipe bool   `json:"ChangeskinOnSnipe"`
	GcReq             int    `json:"GcReq"`
	MFAReq            int    `json:"MFAReq"`
	ManualBearer      bool   `json:"ManualBearer"`
	SpreadPerReq      int    `json:"SpreadPerReq"`

	Bearers []Bearers `json:"Bearers"`
	Logs    []Logs    `json:"logs"`
}

type Logs struct {
	Email   string    `json:"email"`
	Send    time.Time `json:"send"`
	Recv    time.Time `json:"recv"`
	Success bool      `json:"success"`
}

type Bearers struct {
	Bearer       string `json:"Bearer"`
	Email        string `json:"Email"`
	Password     string `json:"Password"`
	AuthInterval int64  `json:"AuthInterval"`
	AuthedAt     int64  `json:"AuthedAt"`
	Type         string `json:"Type"`
	NameChange   bool   `json:"NameChange"`
}

var (
	redirect string
	acc      Config
)
