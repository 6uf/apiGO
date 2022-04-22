package apiGO

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

func (Data *ReqConfig) SnipeReq() (data SentRequests) {
	var wg sync.WaitGroup

	for time.Now().Before(time.Unix(Data.Droptime, 0).Add(-time.Second * 10)) {
		time.Sleep(time.Second * 1)
	}

	if Data.Proxy {
		Clients := Data.Bearers.GenSocketConns(Data.Proxys, Data.Name)
		time.Sleep(time.Until(time.Unix(Data.Droptime, 0).Add(time.Millisecond * time.Duration(0-Data.Delay)).Add(time.Duration(-float64(time.Since(time.Now()).Nanoseconds())/1000000.0) * time.Millisecond)))
		for _, config := range Clients {
			wg.Add(1)
			go func(config Proxys) {
				var wgs sync.WaitGroup
				for _, Acc := range config.Accounts {
					if Acc.AccountType == "Giftcard" {
						for i := 0; i < Acc.Requests; i++ {
							wgs.Add(1)
							go func(Account Info, payloads string) {
								data.Requests = append(data.Requests, Details{
									ResponseDetails: SocketSending(config.Conn, payloads),
									Bearer:          Account.Bearer,
									Email:           Account.Email,
									Type:            Account.AccountType,
								})
								wgs.Done()
							}(Acc, fmt.Sprintf("POST /minecraft/profile HTTP/1.1\r\nHost: api.minecraftservices.com\r\nConnection: open\r\nContent-Length:%v\r\nContent-Type: application/json\r\nAccept: application/json\r\nAuthorization: Bearer %v\r\n\r\n{\"profileName\":\"%v\"}\r\n", len(`{"profileName":"`+Data.Name+`"}`), Acc.Bearer, Data.Name))
						}
					} else {
						for i := 0; i < Acc.Requests; i++ {
							wgs.Add(1)
							go func(Account Info, payloads string) {
								data.Requests = append(data.Requests, Details{
									ResponseDetails: SocketSending(config.Conn, payloads),
									Bearer:          Account.Bearer,
									Email:           Account.Email,
									Type:            Account.AccountType,
								})
								wgs.Done()
							}(Acc, "PUT /minecraft/profile/name/"+Data.Name+" HTTP/1.1\r\nHost: api.minecraftservices.com\r\nConnection: open\r\nUser-Agent: MCSN/1.0\r\nAuthorization: bearer "+Acc.Bearer+"\r\n\r\n")
						}
					}
				}
				wgs.Wait()
				wg.Done()
			}(config)
		}
	} else {
		payload := Data.Bearers.CreatePayloads(Data.Name)
		conn, _ := tls.Dial("tcp", "api.minecraftservices.com:443", nil)
		time.Sleep(time.Until(time.Unix(Data.Droptime, 0).Add(time.Millisecond * time.Duration(0-Data.Delay)).Add(time.Duration(-float64(time.Since(time.Now()).Nanoseconds())/1000000.0) * time.Millisecond)))
		for e, Account := range Data.Bearers.Details {
			for i := 0; i < Account.Requests; i++ {
				wg.Add(1)
				go func(e int, Account Info) {
					data.Requests = append(data.Requests, Details{
						ResponseDetails: SocketSending(conn, payload.Payload[e]),
						Bearer:          Account.Bearer,
						Email:           Account.Email,
						Type:            Account.AccountType,
					})
					wg.Done()
				}(e, Account)
				time.Sleep(time.Duration(Acc.SpreadPerReq) * time.Microsecond)
			}
		}
	}

	wg.Wait()
	fmt.Println()

	sort.Slice(data.Requests, func(i, j int) bool {
		return data.Requests[i].ResponseDetails.SentAt.Before(data.Requests[j].ResponseDetails.SentAt)
	})

	/*

		for _, request := range data.Requests {
			switch request.ResponseDetails.StatusCode {
			case "200":
				content += fmt.Sprintf("+ Sent @ %v | [%v] @ %v ~ %v\n", formatTime(request.ResponseDetails.SentAt), request.ResponseDetails.StatusCode, formatTime(request.ResponseDetails.RecvAt), request.Email)
				fmt.Print(aurora.Sprintf(aurora.Faint(aurora.White("%v >> [%v] @ %v O %v\n\n")), aurora.Green(formatTime(request.ResponseDetails.SentAt)), aurora.Green(request.ResponseDetails.StatusCode), aurora.Green(formatTime(request.ResponseDetails.RecvAt)), aurora.Green(request.Email)))
				switch Acc.ChangeskinOnSnipe {
				case true:
					SendInfo := ServerInfo{
						SkinUrl: Acc.ChangeSkinLink,
					}
					resp, err := SendInfo.ChangeSkin(JsonValue(skinUrls{Url: SendInfo.SkinUrl, Varient: "slim"}), request.Bearer)
					if err == nil {
						if resp.StatusCode == 200 {
							fmt.Print(aurora.Sprintf(aurora.Faint(aurora.White("[%v] Succesfully Changed your Skin!\n")), aurora.Green(resp.StatusCode)))
						} else {
							fmt.Print(aurora.Sprintf(aurora.Faint(aurora.White("[%v] Couldnt Change your Skin..\n")), aurora.Red("ERROR")))
						}
					}
				}
				removeDetails(request)
			default:
				content += fmt.Sprintf("- Sent @ %v >> [%v] @ %v ~ %v\n", formatTime(request.ResponseDetails.SentAt), request.ResponseDetails.StatusCode, formatTime(request.ResponseDetails.RecvAt), request.Email)
				fmt.Print(aurora.Sprintf(aurora.Faint(aurora.White("%v >> [%v] @ %v X %v\n")), aurora.Red(formatTime(request.ResponseDetails.SentAt)), aurora.Red(request.ResponseDetails.StatusCode), aurora.Red(formatTime(request.ResponseDetails.RecvAt)), aurora.Red(request.Email)))
			}
		}

	*/

	return
}

func JsonValue(f interface{}) []byte {
	g, _ := json.Marshal(f)
	return g
}
