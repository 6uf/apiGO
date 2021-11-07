package mcapi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	fmt.Print(`
   __  ___________   ___  ____
  /  |/  / ___/ _ | / _ \/  _/
 / /|_/ / /__/ __ |/ ___// /  
/_/  /_/\___/_/ |_/_/  /___/  
                               
`)
}

func (accountBearer MCbearers) CreatePayloads(name string) Payload {
	payload := make([]string, 0)
	var conns []*tls.Conn

	for i, bearer := range accountBearer.Bearers {
		if accountBearer.AccountType[i] == "Giftcard" {
			payload = append(payload, fmt.Sprintf("POST /minecraft/profile HTTP/1.1\r\nHost: api.minecraftservices.com\r\nConnection: open\r\nContent-Length:%s\r\nContent-Type: application/json\r\nAccept: application/json\r\nAuthorization: Bearer %s\r\n\r\n"+string([]byte(`{"profileName":"`+name+`"}`))+"\r\n", strconv.Itoa(len(string([]byte(`{"profileName":"`+name+`"}`)))), bearer))
		} else {
			payload = append(payload, "PUT /minecraft/profile/name/"+name+" HTTP/1.1\r\nHost: api.minecraftservices.com\r\nUser-Agent: Medusa/1.0\r\nAuthorization: bearer "+bearer+"\r\n\r\n")
		}
	}

	for range payload {
		conn, _ := tls.Dial("tcp", "api.minecraftservices.com"+":443", nil)
		conns = append(conns, conn)
	}

	return Payload{Payload: payload, Conns: conns, AccountType: accountBearer.AccountType}
}

func Sleep(dropTime int64, delay float64) {
	dropStamp := time.Unix(dropTime, 0)

	fmt.Println("\n\nPreparing to snipe..\n")

	time.Sleep(time.Until(dropStamp.Add(time.Millisecond * time.Duration(0-delay)).Add(time.Duration(-float64(time.Since(time.Now()).Nanoseconds())/1000000.0) * time.Millisecond)))
}

func PreSleep(dropTime int64) {
	dropStamp := time.Unix(dropTime, 0)

	delDroptime := dropStamp.Add(-time.Second * 5)

	for {
		fmt.Printf("Dropping in %v    \r", time.Until(delDroptime).Round(time.Second).Seconds())
		time.Sleep(time.Second * 1)
		if time.Until(dropStamp) <= 5*time.Second {
			break
		}
	}
}

func DropTime(name string) int64 {
	resp, _ := http.NewRequest("GET",
		"https://api.star.shopping/droptime/"+name,
		nil)

	resp.Header.Set("user-agent", "Sniper")

	data, err := http.DefaultClient.Do(resp)
	if err != nil {
		fmt.Println(err)
	}

	defer data.Body.Close()

	dropTimeBytes, err := ioutil.ReadAll(data.Body)
	if err != nil {
		fmt.Print(err)
	}

	var f Payload
	json.Unmarshal(dropTimeBytes, &f)
	return f.UNIX
}

func GetConfig(owo []byte) map[string]interface{} {
	var config map[string]interface{}
	json.Unmarshal(owo, &config)
	return config
}

func (payloadInfo Payload) SocketSending(spread int64) ([]time.Time, []time.Time, []string) {

	recvd := make([]byte, 4069)

	fmt.Fprintln(payloadInfo.Conns[0], payloadInfo.Payload[0])
	sendTimes := time.Now()
	payloadInfo.Conns[0].Read(recvd)
	recvTime := time.Now()

	sendTime = append(sendTime, sendTimes)
	recv = append(recv, recvTime)
	statusCode = append(statusCode, string(recvd[9:12]))

	return sendTime, recv, statusCode
}

func (server ServerInfo) SendWebhook(body []byte) (*http.Response, error) {

	webhookReq, err := http.NewRequest("POST", server.Webhook, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	webhookReq.Header.Set("Content-Type", "application/json")

	conn, err := http.DefaultClient.Do(webhookReq)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (server ServerInfo) ChangeSkin(body []byte, bearer string) (*http.Response, error) {

	resp, err := http.NewRequest("POST", "https://api.minecraftservices.com/minecraft/profile/skins", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	resp.Header.Set("Authorization", "bearer "+bearer)

	skin, err := http.DefaultClient.Do(resp)
	if err != nil {
		return nil, err
	}

	return skin, nil
}

func Auth(accounts []string) (MCbearers, error) {
	var bearerReturn []string
	var i int
	var accountType []string
	for _, info := range accounts {
		if i == 3 {
			fmt.Println("[LOG] Sleeping to avoid rate limit. (1 Minute)")
			time.Sleep(time.Minute)
			i = 0
		}

		time.Sleep(time.Second)
		email := strings.Split(info, ":")[0]
		password := strings.Split(info, ":")[1]
		var bearer string
		jar, err := cookiejar.New(nil)
		if err != nil {
			return MCbearers{}, errors.New(fmt.Sprintf("Got error while creating cookie jar %s", err.Error()))
		}

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				redirect = req.URL.String()
				return nil
			},
			Jar: jar,
		}

		resp, err := http.NewRequest("GET", "https://login.live.com/oauth20_authorize.srf?client_id=000000004C12AE6F&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en", nil)
		if err != nil {
			return MCbearers{}, err
		}

		resp.Header.Set("User-Agent", "Mozilla/5.0 (XboxReplay; XboxLiveAuth/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36")

		response, err := client.Do(resp)
		if err != nil {
			return MCbearers{}, err
		}

		jar.Cookies(resp.URL)

		bodyByte, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return MCbearers{}, err
		}

		myString := string(bodyByte[:])

		search1 := regexp.MustCompile(`value="(.*?)"`)
		search3 := regexp.MustCompile(`urlPost:'(.+?)'`)

		value := search1.FindAllStringSubmatch(myString, -1)[0][1]
		urlPost := search3.FindAllStringSubmatch(myString, -1)[0][1]

		emailEncode := url.QueryEscape(email)
		passwordEncode := url.QueryEscape(password)

		body := []byte(fmt.Sprintf("login=%v&loginfmt=%v&passwd=%v&PPFT=%v", emailEncode, emailEncode, passwordEncode, value))

		req, err := http.NewRequest("POST", urlPost, bytes.NewReader(body))

		if err != nil {
			return MCbearers{}, err
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "Mozilla/5.0 (XboxReplay; XboxLiveAuth/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36")

		_, err = client.Do(req)
		if err != nil {
			panic(err)
		}

		respBytes, err := ioutil.ReadAll(response.Body)

		if err != nil {
			panic(err)
		}

		if strings.Contains(string(respBytes), "Sign in to") {
			bearer = "Invalid"
			return MCbearers{}, errors.New("Invalid Credentials")
		}

		if strings.Contains(string(respBytes), "Help us protect your account") {
			bearer = "Invalid"
			return MCbearers{}, errors.New("Account has security questions!")
		}

		if !strings.Contains(redirect, "access_token") || redirect == urlPost {
			bearer = "Invalid"
			return MCbearers{}, errors.New("Invalid Credentials")
		}

		if bearer != "Invalid" {
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						Renegotiation: tls.RenegotiateFreelyAsClient,
					},
				},
			}

			splitBear := strings.Split(redirect, "#")[1]

			splitValues := strings.Split(splitBear, "&")

			//refresh_token := strings.Split(splitValues[4], "=")[1]
			access_token := strings.Split(splitValues[0], "=")[1]
			//expires_in := strings.Split(splitValues[2], "=")[1]

			body := []byte(`{"Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": "` + access_token + `"}, "RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT"}`)
			post, err := http.NewRequest("POST", "https://user.auth.xboxlive.com/user/authenticate", bytes.NewBuffer(body))
			if err != nil {
				return MCbearers{}, err
			}

			post.Header.Set("Content-Type", "application/json")
			post.Header.Set("Accept", "application/json")

			bodyRP, err := client.Do(post)
			if err != nil {
				return MCbearers{}, err
			}

			rpBody, err := ioutil.ReadAll(bodyRP.Body)
			if err != nil {
				return MCbearers{}, err
			}

			Token := func(body string, key string) string {
				keystr := "\"" + key + "\":[^,;\\]}]*"
				r, _ := regexp.Compile(keystr)
				match := r.FindString(body)
				keyValMatch := strings.Split(match, ":")
				return strings.ReplaceAll(keyValMatch[1], "\"", "")
			}(string(rpBody), "Token")

			uhs := func(body string, key string) string {
				keystr := "\"" + key + "\":[^,;\\]}]*"
				r, _ := regexp.Compile(keystr)
				match := r.FindString(body)
				keyValMatch := strings.Split(match, ":")
				return strings.ReplaceAll(keyValMatch[1], "\"", "")
			}(string(rpBody), "uhs")

			payload := []byte(`{"Properties": {"SandboxId": "RETAIL", "UserTokens": ["` + Token + `"]}, "RelyingParty": "rp://api.minecraftservices.com/", "TokenType": "JWT"}`)
			xstsPost, err := http.NewRequest("POST", "https://xsts.auth.xboxlive.com/xsts/authorize", bytes.NewBuffer(payload))
			if err != nil {
				return MCbearers{}, err
			}

			xstsPost.Header.Set("Content-Type", "application/json")
			xstsPost.Header.Set("Accept", "application/json")

			bodyXS, err := client.Do(xstsPost)
			if err != nil {
				return MCbearers{}, err
			}

			xsBody, err := ioutil.ReadAll(bodyXS.Body)
			if err != nil {
				return MCbearers{}, err
			}

			switch bodyXS.StatusCode {
			case 401:
				switch !strings.Contains(string(xsBody), "XErr") {
				case !strings.Contains(string(xsBody), "2148916238"):

					return MCbearers{}, errors.New("account belongs to someone under 18 and needs to be added to a family")
				case !strings.Contains(string(xsBody), "2148916233"):

					return MCbearers{}, errors.New("account has no Xbox account, you must sign up for one first")
				}
			}

			xsToken := func(body string, key string) string {
				keystr := "\"" + key + "\":[^,;\\]}]*"
				r, _ := regexp.Compile(keystr)
				match := r.FindString(body)
				keyValMatch := strings.Split(match, ":")
				return strings.ReplaceAll(keyValMatch[1], "\"", "")
			}(string(xsBody), "Token")

			mcBearer := []byte(`{"identityToken" : "XBL3.0 x=` + uhs + `;` + xsToken + `", "ensureLegacyEnabled" : true}`)
			mcBPOST, err := http.NewRequest("POST", "https://api.minecraftservices.com/authentication/login_with_xbox", bytes.NewBuffer(mcBearer))
			if err != nil {
				return MCbearers{}, err
			}

			mcBPOST.Header.Set("Content-Type", "application/json")

			bodyBearer, err := client.Do(mcBPOST)
			if err != nil {
				return MCbearers{}, err
			}

			bearerValue, err := ioutil.ReadAll(bodyBearer.Body)
			if err != nil {
				return MCbearers{}, err
			}
			var bearerMS bearerMs
			json.Unmarshal(bearerValue, &bearerMS)

			accountType = func() []string {
				var accountType []string
				conn, err := tls.Dial("tcp", "api.minecraftservices.com"+":443", nil)
				if err != nil {
					fmt.Print(err)
				}

				fmt.Fprintln(conn, "GET /minecraft/profile/namechange HTTP/1.1\r\nHost: api.minecraftservices.com\r\nUser-Agent: Dismal/1.0\r\nAuthorization: Bearer "+bearerMS.Bearer+"\r\n\r\n")

				e := make([]byte, 12)
				_, err = conn.Read(e)
				if err != nil {
					fmt.Print(err)
				}

				// checks status codes..
				switch string(e[9:12]) {
				case `404`:
					accountType = append(accountType, "Giftcard")
				default:
					accountType = append(accountType, "Microsoft")
				}
				return accountType
			}()

			bearerReturn = append(bearerReturn, bearerMS.Bearer)
			i++
		} else {
			i++
		}
	}

	return MCbearers{Bearers: bearerReturn, AccountType: accountType}, nil
}
