package apiGO

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
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

	for i, bearer := range accountBearer.Bearers {
		if accountBearer.AccountType[i] == "Giftcard" {
			payload = append(payload, fmt.Sprintf("POST /minecraft/profile HTTP/1.1\r\nHost: api.minecraftservices.com\r\nConnection: open\r\nContent-Length:%s\r\nContent-Type: application/json\r\nAccept: application/json\r\nAuthorization: Bearer %s\r\n\r\n"+string([]byte(`{"profileName":"`+name+`"}`))+"\r\n", strconv.Itoa(len(string([]byte(`{"profileName":"`+name+`"}`)))), bearer))
		} else {
			payload = append(payload, "PUT /minecraft/profile/name/"+name+" HTTP/1.1\r\nHost: api.minecraftservices.com\r\nUser-Agent: MCSN/1.0\r\nAuthorization: bearer "+bearer+"\r\n\r\n")
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

	fmt.Println(aurora.Bold(aurora.White("\n\nPreparing to snipe..")))

	time.Sleep(time.Until(dropStamp.Add(time.Millisecond * time.Duration(0-delay)).Add(time.Duration(-float64(time.Since(time.Now()).Nanoseconds())/1000000.0) * time.Millisecond)))
}

func PreSleep(dropTime int64) {
	dropStamp := time.Unix(dropTime, 0)

	delDroptime := dropStamp.Add(-time.Second * 5)

	for {

		fmt.Printf(aurora.Sprintf(aurora.Bold(aurora.White(("Dropping in %v    \r"))), aurora.Bold(aurora.Red(time.Until(delDroptime).Round(time.Second).Seconds()))))

		time.Sleep(time.Second * 1)
		if time.Until(dropStamp) <= 5*time.Second {
			break
		}
	}
}

func DropTime(name string) int64 {
	resp, _ := http.NewRequest("GET",
		"http://api.star.shopping/droptime/"+name,
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

func Auth() (MCbearers, error) {
	var empty bool
	var AccountsVer []string
	var BearersVer []string

	var finalB []string
	var finalA []string

	q, _ := ioutil.ReadFile("config.json")

	config := GetConfig(q)

	file, _ := os.Open("accounts.txt")

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		if scanner.Text() == "" {
			break
		} else {
			AccountsVer = append(AccountsVer, scanner.Text())
		}
	}

	if len(AccountsVer) == 0 {
		fmt.Println(aurora.Bold(aurora.White("unable to continue, you have no accounts added.")))
		os.Exit(0)
	}

	if config["ManualBearer"].(bool) {
		for _, bearer := range AccountsVer {
			if CheckChange(bearer) {
				finalB = append(finalB, bearer)
				finalA = append(finalA, isGC(bearer))
			} else {
				fmt.Println(aurora.Sprintf(aurora.Bold(aurora.White(("[DISMAL] Cannot Namechange | %v"))), aurora.Bold(aurora.Red(bearer[0:10]))))
			}

			time.Sleep(time.Second)
		}
	} else {
		if config[`Bearers`] == nil {
			empty = true
		} else {
			BearersVer, _ = grabArray(config[`Bearers`].([]interface{}))
		}

		if empty {
			bearerz, err := authAcc(AccountsVer)
			if err != nil {
				fmt.Println(err)
			}

			if len(bearerz.Bearers) == 0 {
				fmt.Println(aurora.Bold(aurora.White("Unable to authenticate your account(s), please Reverify your login details.")))
			} else {
				for i := range bearerz.Bearers {
					BearersVer = append(BearersVer, bearerz.Bearers[i]+"`"+time.Now().Add(time.Duration(time.Second*86400)).Format(time.RFC850)+"`"+bearerz.AccountType[i]+"`"+AccountsVer[i])
				}
			}
		} else {
			if len(BearersVer) < len(AccountsVer) {
				func() {
					BearersVer = []string{}
					bearerz, err := authAcc(AccountsVer)
					if err != nil {
						fmt.Println(err)
					}

					if len(bearerz.Bearers) == 0 {
					} else {
						for i := range bearerz.Bearers {
							BearersVer = append(BearersVer, bearerz.Bearers[i]+"`"+time.Now().Add(time.Duration(time.Second*86400)).Format(time.RFC850)+"`"+bearerz.AccountType[i]+"`"+AccountsVer[i])
						}
					}
				}()
			} else if len(AccountsVer) < len(BearersVer) {
				var confirmedBearers []string
				for _, acc := range AccountsVer {
					for _, num := range BearersVer {
						if acc == strings.Split(num, "`")[3] {
							confirmedBearers = append(confirmedBearers, strings.Split(num, "`")[0]+"`"+time.Now().Add(time.Duration(time.Second*86400)).Format(time.RFC850)+"`"+strings.Split(num, "`")[2]+"`"+acc)
						}
					}
				}

				BearersVer = confirmedBearers
			}
		}
	}

	var reAuth []string
	var Confirmed []string

	for _, accs := range BearersVer {
		m := strings.Split(accs, "`")
		f, _ := http.NewRequest("GET", "https://api.minecraftservices.com/minecraft/profile/name/boom/available", nil)
		f.Header.Set("Authorization", "Bearer "+m[0])
		j, _ := http.DefaultClient.Do(f)

		if j.StatusCode == 401 {
			reAuth = append(reAuth, m[3])
		} else {
			wdad, _ := time.Parse(time.RFC850, m[1])

			if time.Now().After(wdad) {
				reAuth = append(reAuth, m[3])
			} else {
				if CheckChange(m[0]) {
					Confirmed = append(Confirmed, m[0]+"`"+m[1]+"`"+m[2]+"`"+m[3])
				} else {
					fmt.Println(aurora.Sprintf(aurora.Bold(aurora.White(("[DISMAL] Cannot Namechange | %v"))), aurora.Bold(aurora.Red(strings.Split(m[3], ":")[0]))))
				}
			}
		}
	}

	if len(reAuth) != 0 {
		fmt.Print(aurora.Sprintf(aurora.Bold(aurora.White("Reauthing %v accounts..\n")), aurora.Bold(aurora.Red(len(reAuth)))))
		bearerz, _ := authAcc(reAuth)

		for i, acc := range bearerz.Bearers {
			if CheckChange(acc) {
				Confirmed = append(Confirmed, acc+"`"+time.Now().Add(time.Duration(time.Second*86400)).Format(time.RFC850)+"`"+bearerz.AccountType[i]+"`"+AccountsVer[i])
				time.Sleep(time.Second)
			} else {
				fmt.Println(aurora.Sprintf(aurora.Bold(aurora.White(("[DISMAL] Cannot Namechange | %v"))), aurora.Bold(aurora.Red(strings.Split(AccountsVer[i], ":")[0]))))
			}
		}
	}

	if !config["ManualBearer"].(bool) {
		if BearersVer == nil {
			fmt.Println(aurora.Bold(aurora.White("\nNo bearers have been found, please check your details.")))
			os.Exit(0)
		} else {

			var reAuth []string
			var Confirmed []string

			for _, accs := range BearersVer {
				m := strings.Split(accs, "`")
				f, _ := http.NewRequest("GET", "https://api.minecraftservices.com/minecraft/profile/name/boom/available", nil)
				f.Header.Set("Authorization", "Bearer "+m[0])
				j, _ := http.DefaultClient.Do(f)

				if j.StatusCode == 401 {
					reAuth = append(reAuth, m[3])
				} else {
					wdad, _ := time.Parse(time.RFC850, m[1])

					if time.Now().After(wdad) {
						reAuth = append(reAuth, m[3])
					} else {
						if CheckChange(m[0]) {
							Confirmed = append(Confirmed, m[0]+"`"+m[1]+"`"+m[2]+"`"+m[3])
							time.Sleep(time.Second)
						} else {
							fmt.Println(aurora.Sprintf(aurora.Bold(aurora.White(("[DISMAL] Cannot Namechange | %v"))), aurora.Bold(aurora.Red(strings.Split(m[3], ":")[0]))))
						}
					}
				}
			}

			config["Bearers"] = Confirmed

			writetoFile(config)

			for _, acc := range Confirmed {
				finalB = append(finalB, strings.Split(acc, "`")[0])
				finalA = append(finalA, strings.Split(acc, "`")[2])
			}
		}
	}

	return MCbearers{Bearers: finalB, AccountType: finalA}, nil
}

func grabArray(array []interface{}) ([]string, error) {
	var list []string

	if array != nil {
		for _, names := range array {
			list = append(list, names.(string))
		}
		if len(list) == 0 {
			return nil, errors.New("empty")
		}
	} else {
		return nil, errors.New("empty")
	}

	return list, nil
}

func writetoFile(str interface{}) {
	v, _ := json.MarshalIndent(str, "", "  ")

	ioutil.WriteFile("config.json", v, 0)
}

func isGC(bearer string) string {
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

func authAcc(accounts []string) (MCbearers, error) {
	var bearerReturn []string
	var i int
	var g int
	var accountType []string
	for _, info := range accounts {
		if i == 3 {
			fmt.Println(aurora.Bold(aurora.White(("[LOG] Sleeping to avoid rate limit. (1 Minute)"))))
			time.Sleep(time.Minute)
			i = 0
		}

		time.Sleep(time.Second)

		email := strings.Split(info, ":")[0]
		password := strings.Split(info, ":")[1]
		var bearer string
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
			bearer = "Invalid"
			fmt.Println(aurora.Sprintf(aurora.Bold(aurora.White(("[DISMAL] Couldnt Auth | %v"))), aurora.Bold(aurora.Red(email))))
		}

		if strings.Contains(string(respBytes), "Help us protect your account") {
			bearer = "Invalid"
			fmt.Println(aurora.Sprintf(aurora.Bold(aurora.White(("Account has security questions! | %v"))), aurora.Bold(aurora.Red(email))))
		}

		if !strings.Contains(redirect, "access_token") || redirect == urlPost {
			bearer = "Invalid"
			fmt.Println(aurora.Sprintf(aurora.Bold(aurora.White(("[DISMAL] Couldnt Auth | %v"))), aurora.Bold(aurora.Red(email))))
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
			post, _ := http.NewRequest("POST", "https://user.auth.xboxlive.com/user/authenticate", bytes.NewBuffer(body))

			post.Header.Set("Content-Type", "application/json")
			post.Header.Set("Accept", "application/json")

			bodyRP, _ := client.Do(post)

			rpBody, _ := ioutil.ReadAll(bodyRP.Body)

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
			xstsPost, _ := http.NewRequest("POST", "https://xsts.auth.xboxlive.com/xsts/authorize", bytes.NewBuffer(payload))
			xstsPost.Header.Set("Content-Type", "application/json")
			xstsPost.Header.Set("Accept", "application/json")

			bodyXS, _ := client.Do(xstsPost)

			xsBody, _ := ioutil.ReadAll(bodyXS.Body)

			switch bodyXS.StatusCode {
			case 401:
				switch !strings.Contains(string(xsBody), "XErr") {
				case !strings.Contains(string(xsBody), "2148916238"):
					fmt.Println(aurora.Sprintf(aurora.Bold(aurora.White(("account belongs to someone under 18 and needs to be added to a family | %v"))), aurora.Bold(aurora.Red(email))))
					continue
				case !strings.Contains(string(xsBody), "2148916233"):
					fmt.Println(aurora.Sprintf(aurora.Bold(aurora.White(("account has no Xbox account, you must sign up for one first | %v"))), aurora.Bold(aurora.Red(email))))
					continue
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
			mcBPOST, _ := http.NewRequest("POST", "https://api.minecraftservices.com/authentication/login_with_xbox", bytes.NewBuffer(mcBearer))

			mcBPOST.Header.Set("Content-Type", "application/json")

			bodyBearer, _ := client.Do(mcBPOST)

			bearerValue, _ := ioutil.ReadAll(bodyBearer.Body)

			var bearerMS bearerMs
			json.Unmarshal(bearerValue, &bearerMS)

			accountType = append(accountType, func() string {
				var accountT string
				conn, _ := tls.Dial("tcp", "api.minecraftservices.com"+":443", nil)

				fmt.Fprintln(conn, "GET /minecraft/profile/namechange HTTP/1.1\r\nHost: api.minecraftservices.com\r\nUser-Agent: Dismal/1.0\r\nAuthorization: Bearer "+bearerMS.Bearer+"\r\n\r\n")

				e := make([]byte, 12)
				conn.Read(e)

				switch string(e[9:12]) {
				case `404`:
					accountT = "Giftcard"
				default:
					accountT = "Microsoft"
				}
				return accountT
			}())

			bearerReturn = append(bearerReturn, bearerMS.Bearer)
			fmt.Println(aurora.Sprintf(aurora.Bold(aurora.White(("[DISMAL] Authenticated | %v"))), aurora.Bold(aurora.Red(email))))
			i++
		} else {
			if g == 10 {
				fmt.Println(aurora.Sprintf(aurora.Bold(aurora.White(("Sleeping for %v seconds to avoid Mojang rate limit."))), aurora.Bold(aurora.Red("30"))))
				time.Sleep(30 * time.Second)
				g = 0
			}

			var access accessTokenResp
			splitLogin := strings.Split(info, ":")
			email := strings.Split(info, ":")[0]
			password := strings.Split(info, ":")[1]

			data := accessTokenReq{
				Username: email,
				Password: password,
			}

			bytesToSend, _ := json.Marshal(data)

			req, _ := http.NewRequest("POST", "https://authserver.mojang.com/authenticate", bytes.NewBuffer(bytesToSend))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "MCSN/1.0")

			res, err := http.DefaultClient.Do(req)
			if err != nil {
				continue
			}
			if res.Status != "200 OK" {
				continue
			}
			respData, _ := ioutil.ReadAll(res.Body)

			json.Unmarshal(respData, &access)

			if len(strings.Split(info, ":")) != 5 {
				bearerReturn = append(bearerReturn, *access.AccessToken)
				accountType = append(accountType, "Microsoft")
			}
			req, _ = http.NewRequest("GET", "https://api.mojang.com/user/security/challenges", nil)

			req.Header.Set("Authorization", "Bearer "+*access.AccessToken)
			res, _ = http.DefaultClient.Do(req)

			respData, _ = ioutil.ReadAll(res.Body)

			var security []securityRes
			json.Unmarshal(respData, &security)

			if len(security) != 3 {
				continue
			}
			dataBytes := []byte(`[{"id": ` + strconv.Itoa(security[0].Answer.ID) + `, "answer": "` + splitLogin[2] + `"}, {"id": ` + strconv.Itoa(security[1].Answer.ID) + `, "answer": "` + splitLogin[3] + `"}, {"id": ` + strconv.Itoa(security[2].Answer.ID) + `, "answer": "` + splitLogin[4] + `"}]`)
			req, _ = http.NewRequest("POST", "https://api.mojang.com/user/security/location", bytes.NewReader(dataBytes))

			req.Header.Set("Authorization", "Bearer "+*access.AccessToken)
			resp, _ := http.DefaultClient.Do(req)
			if resp.StatusCode == 204 {
				fmt.Println(aurora.Sprintf(aurora.Bold(aurora.White(("[DISMAL] Authenticated | %v"))), aurora.Bold(aurora.Red(email))))
				bearerReturn = append(bearerReturn, *access.AccessToken)
				accountType = append(accountType, "Microsoft")
			} else {
				fmt.Println(aurora.Sprintf(aurora.Bold(aurora.White(("[DISMAL] Couldnt Auth | %v"))), aurora.Bold(aurora.Red(email))))
			}

			g++
		}
	}

	return MCbearers{Bearers: bearerReturn, AccountType: accountType}, nil
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

	s, err = discordgo.New("Bot " + config[`DiscordBotToken`].(string))
	if err != nil {
		log.Fatalf("Invalid bot parameters: %v", err)
	}

	s.AddHandler(func(s *discordgo.Session, i *discordgo.InteractionCreate) {
		if h, ok := commandHandlers[i.ApplicationCommandData().Name]; ok {
			h(s, i)
		}
	})

	s.AddHandler(func(s *discordgo.Session, r *discordgo.Ready) {
		log.Println("Bot is up!")
	})

	err = s.Open()
	if err != nil {
		log.Fatalf("Cannot open the session: %v", err)
	}

	for _, command := range commands {
		s.ApplicationCommandCreate(s.State.User.ID, "", command)
	}

	defer s.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	log.Println("Gracefully shutdowning")
}

func remove(l []string, item string) []string {
	for i, other := range l {
		if other == item {
			l = append(l[:i], l[i+1:]...)
		}
	}
	return l
}
