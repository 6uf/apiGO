package apiGO

import (
	"crypto/tls"
	"net/http"
	"time"
)

type Name struct {
	Names string  `json:"name"`
	Drop  float64 `json:"droptime"`
}

type Proxys struct {
	Proxys   *[]string
	Used     map[string]bool
	Accounts []Info
	Conn     *tls.Conn
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
	Info        UserINFO `json:"Info"`
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
	Email    string    `json:"email"`
	Password string    `json:"password"`
	Send     time.Time `json:"send"`
	Recv     time.Time `json:"recv"`
	Success  bool      `json:"success"`
	Name     string    `json:"name"`
}

type UserINFO struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Bearers struct {
	Bearer       string   `json:"Bearer"`
	Email        string   `json:"Email"`
	Password     string   `json:"Password"`
	AuthInterval int64    `json:"AuthInterval"`
	AuthedAt     int64    `json:"AuthedAt"`
	Type         string   `json:"Type"`
	NameChange   bool     `json:"NameChange"`
	Info         UserINFO `json:"Info"`
}

type Bux2 struct {
	Action string     `json:"action"`
	Desc   string     `json:"desc"`
	Code   string     `json:"code"`
	ID     string     `json:"id"`
	Error  string     `json:"error"`
	Data   []Droptime `json:"data"`
}

type Bux struct {
	Action string   `json:"action"`
	Desc   string   `json:"desc"`
	Code   string   `json:"code"`
	ID     string   `json:"id"`
	Error  string   `json:"error"`
	Data   Droptime `json:"data"`
}

type Droptime struct {
	Name     string    `json:"name"`
	Droptime int       `json:"droptime"`
	Date     time.Time `json:"date"`
	Searches string    `json:"searches"`
}

type ReqConfig struct {
	Name     string
	Delay    float64
	Droptime int64
	Proxys   Proxys
	Bearers  MCbearers

	Proxy bool
}

type SentRequests struct {
	Requests []Details
}

type Details struct {
	ResponseDetails struct {
		SentAt     time.Time
		RecvAt     time.Time
		StatusCode string
	}
	Bearer   string
	Email    string
	Password string
	Type     string
	Info     UserINFO
}

var (
	redirect string
)
