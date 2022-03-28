package apiGO

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func (accountBearer MCbearers) CreatePayloads(name string) (Data Payload) {
	for _, bearer := range accountBearer.Details {
		if bearer.AccountType == "Giftcard" {
			Data.Payload = append(Data.Payload, fmt.Sprintf("POST /minecraft/profile HTTP/1.1\r\nHost: api.minecraftservices.com\r\nConnection: open\r\nContent-Length:%s\r\nContent-Type: application/json\r\nAccept: application/json\r\nAuthorization: Bearer %s\r\n\r\n"+string([]byte(`{"profileName":"`+name+`"}`))+"\r\n", strconv.Itoa(len(string([]byte(`{"profileName":"`+name+`"}`)))), bearer.Bearer))
		} else {
			Data.Payload = append(Data.Payload, "PUT /minecraft/profile/name/"+name+" HTTP/1.1\r\nHost: api.minecraftservices.com\r\nUser-Agent: MCSN/1.0\r\nAuthorization: bearer "+bearer.Bearer+"\r\n\r\n")
		}
	}

	return
}

func Sleep(dropTime int64, delay float64) {
	time.Sleep(time.Until(time.Unix(dropTime, 0).Add(time.Millisecond * time.Duration(0-delay)).Add(time.Duration(-float64(time.Since(time.Now()).Nanoseconds())/1000000.0) * time.Millisecond)))
}

func DropTime(name string) int64 {
	resp, _ := http.NewRequest("GET",
		"http://api.star.shopping/droptime/"+name,
		nil)
	resp.Header.Set("user-agent", "Sniper")

	data, _ := http.DefaultClient.Do(resp)
	dropTimeBytes, _ := ioutil.ReadAll(data.Body)
	var f Payload
	json.Unmarshal(dropTimeBytes, &f)
	return f.UNIX
}

func GetConfig(owo []byte) (Config map[string]interface{}) {
	json.Unmarshal(owo, &Config)
	return
}

func Sum(array []float64) (sum float64) {
	for _, ammount := range array {
		sum = sum + ammount
	}

	return
}

func CheckChange(bearer string) bool {
	conn, _ := tls.Dial("tcp", "api.minecraftservices.com:443", nil)
	fmt.Fprintln(conn, "GET /minecraft/profile/namechange HTTP/1.1\r\nHost: api.minecraftservices.com\r\nUser-Agent: MCSN/1.0\r\nAuthorization: Bearer "+bearer+"\r\n\r\n")

	e := make([]byte, 100)
	conn.Read(e)

	authbytes := make([]byte, 4096)
	auth := make(map[string]interface{})

	conn.Read(authbytes)
	conn.Close()

	authbytes = []byte(strings.Split(strings.Split(string(authbytes), "\x00")[0], "\r\n\r\n")[1])
	json.Unmarshal(authbytes, &auth)

	if auth["nameChangeAllowed"] != nil {
		switch auth["nameChangeAllowed"].(bool) {
		case false:
			return false
		}
	}

	return true
}

func SocketSending(conn *tls.Conn, payload string) (sendTime time.Time, recvTime time.Time, status string) {
	fmt.Fprintln(conn, payload)
	sendTime = time.Now()
	
	recvd := make([]byte, 4069)
	conn.Read(recvd)
	recvTime = time.Now()
	status = string(recvd[9:12])

	return
}

func (server ServerInfo) SendWebhook(body []byte) (Req *http.Response, err error) {
	Req, err = http.Post(server.Webhook, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	return
}

func (server ServerInfo) ChangeSkin(body []byte, bearer string) (Req *http.Response, err error) {
	resp, err := http.NewRequest("POST", "https://api.minecraftservices.com/minecraft/profile/skins", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	resp.Header.Set("Authorization", "bearer "+bearer)

	Req, err = http.DefaultClient.Do(resp)
	if err != nil {
		return nil, err
	}

	return
}

//refresh_token := strings.Split(splitValues[4], "=")[1]
//access_token := strings.Split(strings.Split(strings.Split(redirect, "#")[1], "&")[0], "=")[1]
//expires_in := strings.Split(splitValues[2], "=")[1]

func Auth(accounts []string) (returnDetails MCbearers) {
	var i int

	for _, infos := range accounts {
		email := strings.Split(infos, ":")[0]
		password := strings.Split(infos, ":")[1]
		if i == 3 {
			time.Sleep(60 * time.Second)
			i = 0
		}

		time.Sleep(time.Second)
		if jar, err := cookiejar.New(nil); err != nil {
			returnDetails.Details = append(returnDetails.Details, Info{
				Email:    email,
				Password: password,
				Error:    err.Error(),
			})
		} else {
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					redirect = req.URL.String()
					return nil
				},
				Jar: jar,
			}

			if response, err := client.Get("https://login.live.com/oauth20_authorize.srf?client_id=000000004C12AE6F&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en"); err != nil {
				returnDetails.Details = append(returnDetails.Details, Info{
					Email:    email,
					Password: password,
					Error:    err.Error(),
				})
			} else {
				jar.Cookies(response.Request.URL)

				if bodyByte, err := ioutil.ReadAll(response.Body); err != nil {
					returnDetails.Details = append(returnDetails.Details, Info{
						Email:    email,
						Password: password,
						Error:    err.Error(),
					})
				} else if _, err := client.Post(regexp.MustCompile(`urlPost:'(.+?)'`).FindAllStringSubmatch(string(bodyByte), -1)[0][1], "application/x-www-form-urlencoded", bytes.NewReader([]byte(fmt.Sprintf("login=%v&loginfmt=%v&passwd=%v&PPFT=%v", url.QueryEscape(email), url.QueryEscape(email), url.QueryEscape(password), regexp.MustCompile(`value="(.*?)"`).FindAllStringSubmatch(string(bodyByte[:]), -1)[0][1])))); err != nil {
					returnDetails.Details = append(returnDetails.Details, Info{
						Email:    email,
						Password: password,
						Error:    err.Error(),
					})
				} else if respBytes, err := ioutil.ReadAll(response.Body); err != nil {
					returnDetails.Details = append(returnDetails.Details, Info{
						Email:    email,
						Password: password,
						Error:    err.Error(),
					})
				} else {
					if strings.Contains(string(respBytes), "Sign in to") {
						returnDetails.Details = append(returnDetails.Details, Info{
							Email:    email,
							Password: password,
							Error:    "Incorrect Password",
						})
					} else if strings.Contains(string(respBytes), "Help us protect your account") {
						returnDetails.Details = append(returnDetails.Details, Info{
							Email:    email,
							Password: password,
							Error:    "Account has security questions",
						})
					} else if !strings.Contains(redirect, "access_token") || redirect == regexp.MustCompile(`urlPost:'(.+?)'`).FindAllStringSubmatch(string(bodyByte), -1)[0][1] {
						returnDetails.Details = append(returnDetails.Details, Info{
							Email:    email,
							Password: password,
							Error:    "Incorrect Password",
						})
					} else {
						client := &http.Client{
							Transport: &http.Transport{
								TLSClientConfig: &tls.Config{
									Renegotiation: tls.RenegotiateFreelyAsClient,
								},
							},
						}

						if bodyRP, err := client.Post("https://user.auth.xboxlive.com/user/authenticate", "application/json", bytes.NewBuffer([]byte(`{"Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": "`+strings.Split(strings.Split(strings.Split(redirect, "#")[1], "&")[0], "=")[1]+`"}, "RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT"}`))); err != nil {
							returnDetails.Details = append(returnDetails.Details, Info{
								Email:    email,
								Password: password,
								Error:    "Incorrect Password",
							})
						} else if rpBody, err := ioutil.ReadAll(bodyRP.Body); err != nil {
							returnDetails.Details = append(returnDetails.Details, Info{
								Email:    email,
								Password: password,
								Error:    "Incorrect Password",
							})
						} else if bodyXS, err := client.Post("https://xsts.auth.xboxlive.com/xsts/authorize", "application/json", bytes.NewBuffer([]byte(`{"Properties": {"SandboxId": "RETAIL", "UserTokens": ["`+FindData(string(rpBody), "Token")+`"]}, "RelyingParty": "rp://api.minecraftservices.com/", "TokenType": "JWT"}`))); err != nil {
							returnDetails.Details = append(returnDetails.Details, Info{
								Email:    email,
								Password: password,
								Error:    "Incorrect Password",
							})
						} else if xsBody, err := ioutil.ReadAll(bodyXS.Body); err != nil {
							returnDetails.Details = append(returnDetails.Details, Info{
								Email:    email,
								Password: password,
								Error:    "Incorrect Password",
							})
						} else {
							switch bodyXS.StatusCode {
							case 401:
								switch strings.Contains(string(xsBody), "XErr") {
								case strings.Contains(string(xsBody), "2148916238"):
									returnDetails.Details = append(returnDetails.Details, Info{
										Email:    email,
										Password: password,
										Error:    "Account belongs to someone under 18 and needs to be added to a family",
									})
									continue
								case strings.Contains(string(xsBody), "2148916233"):
									returnDetails.Details = append(returnDetails.Details, Info{
										Email:    email,
										Password: password,
										Error:    "Account has no Xbox account, you must sign up for one first",
									})
									continue
								}
							}
							if bodyBearer, err := client.Post("https://api.minecraftservices.com/authentication/login_with_xbox", "application/json", bytes.NewBuffer([]byte(`{"identityToken" : "XBL3.0 x=`+FindData(string(rpBody), "uhs")+`;`+FindData(string(xsBody), "Token")+`", "ensureLegacyEnabled" : true}`))); err != nil {
								returnDetails.Details = append(returnDetails.Details, Info{
									Email:    email,
									Password: password,
									Error:    "Account has no Xbox account, you must sign up for one first",
								})
							} else if bearerValue, err := ioutil.ReadAll(bodyBearer.Body); err != nil {
								returnDetails.Details = append(returnDetails.Details, Info{
									Email:    email,
									Password: password,
									Error:    "Account has no Xbox account, you must sign up for one first",
								})
							} else {
								var bearerMS mojangData
								json.Unmarshal(bearerValue, &bearerMS)
								returnDetails.Details = append(returnDetails.Details, Info{
									Bearer:      bearerMS.Bearer_MS,
									Email:       email,
									Password:    password,
									AccountType: accountInfo(bearerMS.Bearer_MS),
								})

								i++
								continue
							}
						}
					}
				}
			}
		}
	}

	return returnDetails
}

func Remove(l []string, item string) (f []string) {
	for _, other := range l {
		if other != item {
			f = append(f, other)
		}
	}
	return
}

func FindData(body string, key string) string {
	return strings.ReplaceAll(strings.Split(regexp.MustCompile("\""+key+"\":[^,;\\]}]*").FindString(body), ":")[1], "\"", "")
}

func accountInfo(bearer string) string {
	var accountT string
	conn, _ := tls.Dial("tcp", "api.minecraftservices.com"+":443", nil)

	fmt.Fprintln(conn, "GET /minecraft/profile/namechange HTTP/1.1\r\nHost: api.minecraftservices.com\r\nUser-Agent: Dismal/1.0\r\nAuthorization: Bearer "+bearer+"\r\n\r\n")

	e := make([]byte, 12)
	conn.Read(e)

	switch string(e[9:12]) {
	case `404`:
		accountT = "Giftcard"
	default:
		accountT = "Microsoft"
	}
	return accountT
}

func (s *Config) ToJson() (Data []byte, err error) {
	return json.MarshalIndent(s, "", "  ")
}

func (config *Config) SaveConfig() {
	if Json, err := config.ToJson(); err == nil {
		WriteFile("config.json", string(Json))
	}
}

func (s *Config) LoadState() {
	data, err := ReadFile("config.json")
	if err != nil {
		s.LoadFromFile()
		s.GcReq = 2
		s.MFAReq = 2
		s.SpreadPerReq = 40
		s.ChangeskinOnSnipe = true
		s.ChangeSkinLink = "https://textures.minecraft.net/texture/516accb84322ca168a8cd06b4d8cc28e08b31cb0555eee01b64f9175cefe7b75"
		s.SaveConfig()
		return
	}

	json.Unmarshal([]byte(data), s)
	s.LoadFromFile()
}

func (c *Config) LoadFromFile() {
	// Load a config file

	jsonFile, err := os.Open("config.json")
	// if we os.Open returns an error then handle it
	if err != nil {
		jsonFile, _ = os.Create("config.json")
	}
	byteValue, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal(byteValue, &c)
}

func WriteFile(path string, content string) {
	ioutil.WriteFile(path, []byte(content), 0644)
}

func ReadFile(path string) ([]byte, error) {
	return ioutil.ReadFile(path)
}

func Search(username string) (Data Payload) {
	Data.resp, Data.errors = http.Get(fmt.Sprintf("https://droptime.herokuapp.com/searches/%v", username))
	if Data.errors != nil {
		return
	}

	defer Data.resp.Body.Close()

	Data.searchBytes, Data.errors = ioutil.ReadAll(Data.resp.Body)
	if Data.errors != nil {
		return
	}

	if Data.resp.StatusCode < 300 {
		Data.errors = json.Unmarshal(Data.searchBytes, &Data)
		if Data.errors != nil {
			return
		}
	}

	return
}
