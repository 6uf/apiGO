package apiGO

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type Authed struct {
	Error   string
	Bearers MCbearers
}

func (Acc *Config) AuthAccs() (Bearers Authed) {
	var AccountsVer []string
	file, _ := os.Open("accounts.txt")
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		AccountsVer = append(AccountsVer, scanner.Text())
	}

	if len(AccountsVer) == 0 {
		//PrintGrad("Unable to continue, you have no Accounts added.\n")
		os.Exit(0)
	}

	CheckDupes(AccountsVer)
	for _, data := range Acc.GrabDetails(AccountsVer, Bearers.Bearers) {
		if data.Error != "" {
			Bearers.Bearers.Details = append(Bearers.Bearers.Details, Info{
				Error: data.Error,
			})
		} else {
			Bearers.Bearers.Details = append(Bearers.Bearers.Details, Info{
				Bearer:      data.Bearers.Bearer,
				AccountType: data.Bearers.Type,
				Email:       data.Bearers.Email,
				Requests:    Acc.GcReq,
			})
		}
	}

	if !Acc.ManualBearer {
		Acc.CheckifValid(AccountsVer)
		rewrite("accounts.txt", strings.Join(AccountsVer, "\n"))
		if len(AccountsVer) != 0 {
			for _, Accs := range Acc.Bearers {
				if Accs.NameChange {
					if Accs.Type == "Giftcard" {
						Bearers.Bearers.Details = append(Bearers.Bearers.Details, Info{
							Bearer:      Accs.Bearer,
							AccountType: Accs.Type,
							Email:       Accs.Email,
							Requests:    Acc.GcReq,
						})
					} else {
						Bearers.Bearers.Details = append(Bearers.Bearers.Details, Info{
							Bearer:      Accs.Bearer,
							AccountType: Accs.Type,
							Email:       Accs.Email,
							Requests:    Acc.MFAReq,
						})
					}
				}
			}
		}
	}

	return
}

type LogDetails struct {
	Error   string
	Content string
	Bearers Bearers
}

func (Acc *Config) GrabDetails(AccountsVer []string, Bearer MCbearers) (Logs []LogDetails) {
	if Acc.ManualBearer {
		for _, bearer := range AccountsVer {
			if CheckChange(bearer) {
				Bearer.Details = append(Bearer.Details, Info{
					Bearer:      bearer,
					AccountType: IsGC(bearer),
				})
			}

			time.Sleep(time.Second)
		}
	} else if Acc.Bearers == nil {
		for _, Accs := range Auth(AccountsVer).Details {
			if Accs.Error != "" {
				AccountsVer = remove(AccountsVer, Accs.Email+":"+Accs.Password)
				Logs = append(Logs, LogDetails{
					Error: fmt.Sprintf("Account %v came up Invalid: %v\n", Accs.Email, Accs.Error),
				})
			} else {
				if Accs.Bearer != "" {
					if CheckChange(Accs.Bearer) {
						Logs = append(Logs,
							LogDetails{
								Content: fmt.Sprintf("Succesfully authed %v\n", Accs.Email),
								Bearers: Bearers{
									Bearer:       Accs.Bearer,
									AuthInterval: 86400,
									AuthedAt:     time.Now().Unix(),
									Type:         Accs.AccountType,
									Email:        Accs.Email,
									Password:     Accs.Password,
									NameChange:   true,
								},
							})
					} else {
						AccountsVer = remove(AccountsVer, Accs.Email+":"+Accs.Password)
						Logs = append(Logs, LogDetails{
							Error: fmt.Sprintf("Account %v Cannot Name Change.\n", Accs.Email),
						})
					}
				} else {
					Logs = append(Logs, LogDetails{
						Error: fmt.Sprintf("Account %v bearer is nil.\n", Accs.Email),
					})
				}
			}
		}
	} else if len(Acc.Bearers) < len(AccountsVer) {
		var auth []string
		check := make(map[string]bool)

		for _, Acc := range Acc.Bearers {
			check[Acc.Email+":"+Acc.Password] = true
		}

		for _, Accs := range AccountsVer {
			if !check[Accs] {
				auth = append(auth, Accs)
			}
		}

		//PrintGrad(fmt.Sprintf("Attempting to authenticate %v account(s)\n\n", len(AccountsVer)))
		for _, Accs := range Auth(auth).Details {
			if Accs.Error != "" {
				AccountsVer = remove(AccountsVer, Accs.Email+":"+Accs.Password)
				Logs = append(Logs, LogDetails{
					Error: fmt.Sprintf("Account %v came up Invalid: %v\n", Accs.Email, Accs.Error),
				})
			} else {
				if Accs.Bearer != "" {
					if CheckChange(Accs.Bearer) {
						Logs = append(Logs,
							LogDetails{
								Content: fmt.Sprintf("Succesfully authed %v\n", Accs.Email),
								Bearers: Bearers{
									Bearer:       Accs.Bearer,
									AuthInterval: 86400,
									AuthedAt:     time.Now().Unix(),
									Type:         Accs.AccountType,
									Email:        Accs.Email,
									Password:     Accs.Password,
									NameChange:   true,
								},
							})
					} else {
						AccountsVer = remove(AccountsVer, Accs.Email+":"+Accs.Password)
						Logs = append(Logs, LogDetails{
							Error: fmt.Sprintf("Account %v Cannot Name Change.\n", Accs.Email),
						})
					}
				} else {
					Logs = append(Logs, LogDetails{
						Error: fmt.Sprintf("Account %v bearer is nil.\n", Accs.Email),
					})
				}
			}
		}
	} else if len(AccountsVer) < len(Acc.Bearers) {
		for _, Accs := range AccountsVer {
			for _, num := range Acc.Bearers {
				if Accs == num.Email+":"+num.Password {
					Logs = append(Logs,
						LogDetails{
							Content: fmt.Sprintf("Succesfully reloaded %v\n", num.Email),
							Bearers: num,
						})
				}
			}
		}
	}

	return
}

func (Acc *Config) CheckifValid(AccountsVer []string) []string {
	var reAuth []string
	for _, Accs := range Acc.Bearers {
		f, _ := http.NewRequest("GET", "https://api.minecraftservices.com/minecraft/profile/name/boom/available", nil)
		f.Header.Set("Authorization", "Bearer "+Accs.Bearer)
		j, _ := http.DefaultClient.Do(f)

		if j.StatusCode == 401 {
			//PrintGrad(fmt.Sprintf("Account %v turned up invalid. Attempting to Reauth\n", Accs.Email))
			reAuth = append(reAuth, Accs.Email+":"+Accs.Password)
		}
	}

	if len(reAuth) != 0 {
		//PrintGrad(fmt.Sprintf("\nReauthing %v Accounts..\n\n", len(reAuth)))
		bearerz := Auth(reAuth)

		for point, data := range Acc.Bearers {
			for _, Accs := range bearerz.Details {
				if Accs.Error != "" {
					AccountsVer = remove(AccountsVer, Accs.Email+":"+Accs.Password)
					//PrintGrad(fmt.Sprintf("Account %v came up Invalid: %v\n", Accs.Email, Accs.Error))
				} else if Accs.Bearer != "" {
					if data.Email == Accs.Email {
						if Accs.Bearer != "" {
							if CheckChange(Accs.Bearer) {
								//PrintGrad(fmt.Sprintf("Succesfully Reauthed %v\n", Accs.Email))
								data.Bearer = Accs.Bearer
								data.NameChange = true
								data.Type = Accs.AccountType
								data.Password = Accs.Password
								data.Email = Accs.Email
								data.AuthedAt = time.Now().Unix()
								Acc.Bearers[point] = data
							} else {
								AccountsVer = remove(AccountsVer, Accs.Email+":"+Accs.Password)
								//PrintGrad(fmt.Sprintf("Account %v Cannot Name Change.\n", Accs.Email))
							}
						} else {
							//PrintGrad(fmt.Sprintf("Account %v bearer is nil.\n", Accs.Email))
						}
					}
				}
			}
		}
	}

	Acc.SaveConfig()
	Acc.LoadState()

	return AccountsVer
}

func remove(l []string, item string) []string {
	for i, other := range l {
		if other == item {
			l = append(l[:i], l[i+1:]...)
		}
	}
	return l
}

func rewrite(path, accounts string) {
	os.Create(path)

	file, _ := os.OpenFile(path, os.O_RDWR, 0644)
	defer file.Close()

	file.WriteAt([]byte(accounts), 0)
}

// _diamondburned_#4507 thanks to them for the epic example below.

func CheckDupes(strs []string) []string {
	dedup := strs[:0] // re-use the backing array
	track := make(map[string]bool, len(strs))

	for _, str := range strs {
		if track[str] {
			continue
		}
		dedup = append(dedup, str)
		track[str] = true
	}

	return dedup
}
