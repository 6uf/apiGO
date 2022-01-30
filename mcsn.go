package apiGO

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/logrusorgru/aurora/v3"
)

func (accountBearer MCbearers) CreatePayloads(name string) Payload {
	payload := make([]string, 0)
	var conns []*tls.Conn

	for _, bearer := range accountBearer.Details {
		if bearer.AccountType == "Giftcard" {
			payload = append(payload, fmt.Sprintf("POST /minecraft/profile HTTP/1.1\r\nHost: api.minecraftservices.com\r\nConnection: open\r\nContent-Length:%s\r\nContent-Type: application/json\r\nAccept: application/json\r\nAuthorization: Bearer %s\r\n\r\n"+string([]byte(`{"profileName":"`+name+`"}`))+"\r\n", strconv.Itoa(len(string([]byte(`{"profileName":"`+name+`"}`)))), bearer.Bearer))
		} else {
			payload = append(payload, "PUT /minecraft/profile/name/"+name+" HTTP/1.1\r\nHost: api.minecraftservices.com\r\nUser-Agent: MCSN/1.0\r\nAuthorization: bearer "+bearer.Bearer+"\r\n\r\n")
		}
	}

	for range payload {
		conn, _ := tls.Dial("tcp", "api.minecraftservices.com"+":443", nil)
		conns = append(conns, conn)
	}

	return Payload{Payload: payload, Conns: conns}
}

func Sleep(dropTime int64, delay float64) {
	dropStamp := time.Unix(dropTime, 0)

	sendI("Preparing to snipe..")

	time.Sleep(time.Until(dropStamp.Add(time.Millisecond * time.Duration(0-delay)).Add(time.Duration(-float64(time.Since(time.Now()).Nanoseconds())/1000000.0) * time.Millisecond)))
}

func PreSleep(dropTime int64) {
	dropStamp := time.Unix(dropTime, 0)

	delDroptime := dropStamp.Add(-time.Second * 5)

	for {
		sendT(fmt.Sprintf("Dropping in %v    \r", time.Until(delDroptime).Round(time.Second).Seconds()))
		time.Sleep(time.Second * 1)
		if time.Until(dropStamp) <= 5*time.Second {
			break
		}
	}

	fmt.Println()
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

func GetConfig(owo []byte) map[string]interface{} {
	var config map[string]interface{}
	json.Unmarshal(owo, &config)
	return config
}

func Sum(array []float64) float64 {
	var sum1 float64
	for _, ammount := range array {
		sum1 = sum1 + ammount
	}

	return sum1
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

func (payloadInfo Payload) SocketSending(payloadInt int64) (time.Time, time.Time, string) {

	recvd := make([]byte, 4069)

	fmt.Fprintln(payloadInfo.Conns[payloadInt], payloadInfo.Payload[payloadInt])
	sendTimes := time.Now()
	payloadInfo.Conns[payloadInt].Read(recvd)
	recvTime := time.Now()

	return sendTimes, recvTime, string(recvd[9:12])
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

func writetoFile(str interface{}) {
	v, _ := json.MarshalIndent(str, "", "  ")

	ioutil.WriteFile("config.json", v, 0)
}

func sendE(content string) {
	fmt.Println(aurora.Sprintf(aurora.White("[%v] "+content), aurora.Bold(aurora.Red("ERROR"))))
}

func sendI(content string) {
	fmt.Println(aurora.Sprintf(aurora.White("[%v] "+content), aurora.Yellow("INFO")))
}

func sendS(content string) {
	fmt.Println(aurora.Sprintf(aurora.White("[%v] "+content), aurora.Green("SUCCESS")))
}

func sendW(content string) string {
	var value string
	fmt.Print(aurora.Sprintf(aurora.White("[%v] "+content), aurora.Yellow("WAIT")))
	fmt.Scan(&value)
	return value
}

func sendT(content string) {
	fmt.Print(aurora.Sprintf(aurora.White("[%v] "+content), aurora.Green("TIMER")))
}

func Auth(accounts []string) MCbearers {
	var returnDetails MCbearers
	var i int
	var g int

	for _, infos := range accounts {

		email := strings.Split(infos, ":")[0]
		password := strings.Split(infos, ":")[1]

		if i == 3 {
			dropStamp := time.Unix(time.Now().Add(time.Minute).Unix(), 0)
			for {
				sendT(fmt.Sprintf("Continuing in: %v    \r", time.Until(dropStamp).Round(time.Second).Seconds()))
				time.Sleep(time.Second * 1)

				if time.Until(dropStamp) <= 0*time.Second {
					break
				}
			}
			fmt.Println()
			i = 0
		}

		time.Sleep(time.Second)
		jar, _ := cookiejar.New(nil)

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				redirect = req.URL.String()
				return nil
			},
			Jar: jar,
		}

		resp, _ := http.NewRequest("GET", "https://login.live.com/oauth20_authorize.srf?client_id=000000004C12AE6F&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en", nil)

		resp.Header.Set("User-Agent", "Mozilla/5.0 (XboxReplay; XboxLiveAuth/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36")

		response, _ := client.Do(resp)

		jar.Cookies(resp.URL)
		bodyByte, _ := ioutil.ReadAll(response.Body)
		myString := string(bodyByte[:])

		search1 := regexp.MustCompile(`value="(.*?)"`)
		search3 := regexp.MustCompile(`urlPost:'(.+?)'`)

		value := search1.FindAllStringSubmatch(myString, -1)[0][1]
		urlPost := search3.FindAllStringSubmatch(myString, -1)[0][1]

		emailEncode := url.QueryEscape(email)
		passwordEncode := url.QueryEscape(password)

		body := []byte(fmt.Sprintf("login=%v&loginfmt=%v&passwd=%v&PPFT=%v", emailEncode, emailEncode, passwordEncode, value))

		req, _ := http.NewRequest("POST", urlPost, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "Mozilla/5.0 (XboxReplay; XboxLiveAuth/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36")
		client.Do(req)

		respBytes, _ := ioutil.ReadAll(response.Body)

		if strings.Contains(string(respBytes), "Sign in to") {
			sendI(fmt.Sprintf("Couldnt Auth | %v [MICROSOFT]", email))
		} else if strings.Contains(string(respBytes), "Help us protect your account") {
			sendI(fmt.Sprintf("Account has security questions | %v", email))
		} else if !strings.Contains(redirect, "access_token") || redirect == urlPost {
			sendI(fmt.Sprintf("Couldnt Auth | %v [MICROSOFT]", email))
		} else {
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
			post, _ := http.NewRequest("POST", "https://user.auth.xboxlive.com/user/authenticate", bytes.NewBuffer(body))

			post.Header.Set("Content-Type", "application/json")
			post.Header.Set("Accept", "application/json")

			bodyRP, _ := client.Do(post)

			rpBody, _ := ioutil.ReadAll(bodyRP.Body)

			Token := grabTokens(string(rpBody), "Token")
			uhs := grabTokens(string(rpBody), "uhs")

			payload := []byte(`{"Properties": {"SandboxId": "RETAIL", "UserTokens": ["` + Token + `"]}, "RelyingParty": "rp://api.minecraftservices.com/", "TokenType": "JWT"}`)
			xstsPost, _ := http.NewRequest("POST", "https://xsts.auth.xboxlive.com/xsts/authorize", bytes.NewBuffer(payload))
			xstsPost.Header.Set("Content-Type", "application/json")
			xstsPost.Header.Set("Accept", "application/json")

			bodyXS, _ := client.Do(xstsPost)
			xsBody, _ := ioutil.ReadAll(bodyXS.Body)

			switch bodyXS.StatusCode {
			case 401:
				switch !strings.Contains(string(xsBody), "XErr") {
				case !strings.Contains(string(xsBody), "2148916238"):
					sendI(fmt.Sprintf("Account belongs to someone under 18 and needs to be added to a family | %v", email))
					continue
				case !strings.Contains(string(xsBody), "2148916233"):
					sendI(fmt.Sprintf("Account has no Xbox account, you must sign up for one first | %v", email))
					continue
				}
			}

			xsToken := grabTokens(string(xsBody), "Token")
			mcBearer := []byte(`{"identityToken" : "XBL3.0 x=` + uhs + `;` + xsToken + `", "ensureLegacyEnabled" : true}`)
			mcBPOST, _ := http.NewRequest("POST", "https://api.minecraftservices.com/authentication/login_with_xbox", bytes.NewBuffer(mcBearer))
			mcBPOST.Header.Set("Content-Type", "application/json")

			bodyBearer, _ := client.Do(mcBPOST)
			bearerValue, _ := ioutil.ReadAll(bodyBearer.Body)

			var bearerMS bearerMs
			json.Unmarshal(bearerValue, &bearerMS)

			returnDetails.Details = append(returnDetails.Details, Info{
				Bearer:      bearerMS.Bearer,
				Email:       email,
				Password:    password,
				AccountType: accountInfo(bearerMS.Bearer),
			})

			sendS(fmt.Sprintf("Authenticated | %v [MICROSOFT]", email))
			i++
			continue
		}

		sendI(fmt.Sprintf("Attempting Mojang Login | %v [MICROSOFT]", email))

		bearer, account := Mojang(email, password, infos, g)
		if bearer != "" {
			returnDetails.Details = append(returnDetails.Details, Info{
				Bearer:      bearer,
				Email:       email,
				Password:    password,
				AccountType: account,
			})
		}

		g++
	}

	return returnDetails
}

func rewrite(accounts string) {

	os.Create("accounts.txt")

	file, _ := os.OpenFile("accounts.txt", os.O_RDWR, 0644)
	defer file.Close()

	file.WriteAt([]byte(accounts), 0)
}

func sendEmbed(embed *discordgo.MessageEmbed, id string) {
	go func() {
		s.AddHandler(func(s *discordgo.Session, r *discordgo.Ready) {})

		s.Open()

		channel, err := s.UserChannelCreate(id)
		if err != nil {
			log.Println("error creating channel:", err)
			return
		}

		_, err = s.ChannelMessageSendEmbed(channel.ID, embed)
		if err != nil {
			log.Println("error sending DM message:", err)
			return
		}
	}()
}

func Bot() {
	var err error

	q, _ := ioutil.ReadFile("config.json")

	config := GetConfig(q)

	if config[`DiscordBotToken`].(string) != "" {
		s, err = discordgo.New("Bot " + config[`DiscordBotToken`].(string))
		if err != nil {
			sendE("Invalid bot parameters: " + err.Error())
		}

		s.AddHandler(func(s *discordgo.Session, i *discordgo.InteractionCreate) {
			if h, ok := commandHandlers[i.ApplicationCommandData().Name]; ok {
				h(s, i)
			}
		})

		s.AddHandler(func(s *discordgo.Session, r *discordgo.Ready) {
			sendI("Bot is up!")
		})

		err = s.Open()
		if err != nil {
			sendE("Cannot open the session: " + err.Error())
		}

		for _, command := range commands {
			s.ApplicationCommandCreate(s.State.User.ID, "", command)
		}

		defer s.Close()
	} else {
		sendE("Unable to start the bot, please add a discord bot token to your config.")
	}

	sendW("\nPress CTRL+C to Continue : ")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	sendI("Gracefully shutdowning")
}

func remove(l []string, item string) []string {
	for i, other := range l {
		if other == item {
			l = append(l[:i], l[i+1:]...)
		}
	}
	return l
}

func grabTokens(body string, key string) string {
	keystr := "\"" + key + "\":[^,;\\]}]*"
	r, _ := regexp.Compile(keystr)
	match := r.FindString(body)
	keyValMatch := strings.Split(match, ":")
	return strings.ReplaceAll(keyValMatch[1], "\"", "")
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

func Mojang(email, password, security string, increment int) (string, string) {
	if increment == 10 {
		dropStamp := time.Unix(time.Now().Add(30*time.Second).Unix(), 0)
		for {
			sendT(fmt.Sprintf("Continuing in: %v    \r", time.Until(dropStamp).Round(time.Second).Seconds()))
			time.Sleep(time.Second * 1)

			if time.Until(dropStamp) <= 0*time.Second {
				break
			}
		}
		fmt.Println()
		increment = 0
	}

	var access accessTokenResp
	splitLogin := strings.Split(security, ":")

	data := accessTokenReq{
		Username: email,
		Password: password,
	}

	bytesToSend, _ := json.Marshal(data)

	reqs, _ := http.NewRequest("POST", "https://authserver.mojang.com/authenticate", bytes.NewBuffer(bytesToSend))
	reqs.Header.Set("Content-Type", "application/json")
	reqs.Header.Set("User-Agent", "MCSN/1.0")
	res, err := http.DefaultClient.Do(reqs)

	if err == nil {
		if res.Status == "200 OK" {
			respData, _ := ioutil.ReadAll(res.Body)
			json.Unmarshal(respData, &access)
			if len(strings.Split(security, ":")) == 5 {
				req, _ := http.NewRequest("GET", "https://api.mojang.com/user/security/challenges", nil)

				req.Header.Set("Authorization", "Bearer "+*access.AccessToken)
				res, _ = http.DefaultClient.Do(req)

				respData, _ = ioutil.ReadAll(res.Body)

				var security []securityRes
				json.Unmarshal(respData, &security)

				if len(security) == 3 {
					dataBytes := []byte(`[{"id": ` + strconv.Itoa(security[0].Answer.ID) + `, "answer": "` + splitLogin[2] + `"}, {"id": ` + strconv.Itoa(security[1].Answer.ID) + `, "answer": "` + splitLogin[3] + `"}, {"id": ` + strconv.Itoa(security[2].Answer.ID) + `, "answer": "` + splitLogin[4] + `"}]`)
					req, _ := http.NewRequest("POST", "https://api.mojang.com/user/security/location", bytes.NewReader(dataBytes))

					req.Header.Set("Authorization", "Bearer "+*access.AccessToken)
					resps, _ := http.DefaultClient.Do(req)
					if resps.StatusCode == 204 {
						sendS(fmt.Sprintf("Authenticated | %v [MOJANG]", email))
						increment++
					} else {
						sendI(fmt.Sprintf("Couldnt Auth | %v [MOJANG]", email))
					}
				}
			} else {
				sendS(fmt.Sprintf("Authenticated | %v [MOJANG]", email))
			}
		} else {
			sendI(fmt.Sprintf("Couldnt Auth | %v [MOJANG]", email))
		}
	}
	return *access.AccessToken, "Microsoft"
}
