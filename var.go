package apiGO

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/digitalocean/godo"
)

func init() {
	acc.LoadState()
}

type Payload struct {
	Payload []string
	Conns   []*tls.Conn
	UNIX    int64 `json:"unix"`
}

type bearerMs struct {
	Bearer string `json:"access_token"`
}

type ServerInfo struct {
	Webhook string
	SkinUrl string
}

type securityRes struct {
	Answer answerRes `json:"answer"`
}

type answerRes struct {
	ID int `json:"id"`
}

type accessTokenReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type accessTokenResp struct {
	AccessToken string `json:"accessToken"`
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
	DiscordBotToken   string `json:"DiscordBotToken"`
	DiscordID         string `json:"DiscordID"`
	GcReq             int    `json:"GcReq"`
	MFAReq            int    `json:"MFAReq"`
	ManualBearer      bool   `json:"ManualBearer"`
	SpreadPerReq      int    `json:"SpreadPerReq"`
	Digital           string `json:"DigitalOceanKey"`

	Bearers []Bearers `json:"Bearers"`
	Task    []Task    `json:"Tasks"`
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

type Vps struct {
	IP       string `json:"ip"`
	Port     string `json:"port"`
	Password string `json:"password"`
	User     string `json:"user"`
}

type Task struct {
	Name  string `json:"name"`
	Unix  int64  `json:"unix"`
	Type  string `json:"type"`
	Delay int64  `json:"delay"`
}

type Searches struct {
	Searches string `json:"searches"`
}

type Output struct {
	Group    string      `json:"group"`
	Accounts [][]Bearers `json:"accounts"`
}

var (
	redirect        string
	GuildID         = flag.String("guild", "", "Test guild ID. If not passed - bot registers commands globally")
	RemoveCommands  = flag.Bool("rmcmd", true, "Remove all commands after shutdowning or not")
	s               *discordgo.Session
	acc             Config
	client          *godo.Client
	Key             *godo.Key
	privateKeyBytes []byte
	content         []byte
	accNum          int = 0
	increase        int = 0

	commands = []*discordgo.ApplicationCommand{
		{
			Name:        "create-task",
			Description: "Enter a name and delay to begin your snipe!",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionInteger,
					Name:        "delay",
					Description: "Delay to use.",
					Required:    true,
				},
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "queue",
					Description: "`3nl`, `3c`, `list`, `3l` OR type a name and it'll only queue that",
					Required:    true,
				},
			},
		},
		{
			Name:        "add-accounts",
			Description: "add your accounts. `email:password,email:password`",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "account-info",
					Description: "email:password,email:password",
					Required:    true,
				},
			},
		},
		{
			Name:        "remove-accounts",
			Description: "add your accounts. `email:password,email:password`",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "account-info",
					Description: "email:password,email:password",
					Required:    true,
				},
			},
		},
		{
			Name:        "add-names",
			Description: "This is for adding names to your list queues",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "name",
					Description: "Format `name,name,name` or `name` alone",
					Required:    true,
				},
			},
		},
		{
			Name:        "delete-names",
			Description: "Remove a list of names",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "name",
					Description: "Format `name,name,name` or `name` alone",
					Required:    true,
				},
			},
		},
	}

	commandHandlers = map[string]func(s *discordgo.Session, i *discordgo.InteractionCreate){
		"add-accounts": func(s *discordgo.Session, i *discordgo.InteractionCreate) {
			go func() {
				var id string
				var AccountsVer []string

				if i.Member == nil {
					id = i.User.ID
				} else {
					id = i.Member.User.ID
				}

				if id != acc.DiscordID {
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Embeds: []*discordgo.MessageEmbed{
								{
									Author:      &discordgo.MessageEmbedAuthor{},
									Color:       000000, // Green
									Description: "```You are not authorized to use this Bot.```",
									Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
									Title:       "MCSN Errors",
								},
							},
						},
					})
					return
				}

				files, _ := ioutil.ReadFile("accounts.txt")

				AccountsVer = append(AccountsVer, string(files))
				AccountsVer = append(AccountsVer, strings.Split(i.ApplicationCommandData().Options[0].StringValue(), ",")...)

				rewrite("accounts.txt", strings.Join(AccountsVer, "\n"))

				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Embeds: []*discordgo.MessageEmbed{
							{
								Author:      &discordgo.MessageEmbedAuthor{},
								Color:       000000, // Green
								Description: "```Succesfully added your Account(s)```",
								Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
								Title:       "MCSN Logs",
							},
						},
					},
				})
			}()
		},
		"remove-accounts": func(s *discordgo.Session, i *discordgo.InteractionCreate) {
			go func() {
				var id string

				if i.Member == nil {
					id = i.User.ID
				} else {
					id = i.Member.User.ID
				}

				if id != acc.DiscordID {
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Embeds: []*discordgo.MessageEmbed{
								{
									Author:      &discordgo.MessageEmbedAuthor{},
									Color:       000000, // Green
									Description: "```You are not authorized to use this Bot.```",
									Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
									Title:       "MCSN Errors",
								},
							},
						},
					})
					return
				}

				exists := make(map[string]bool)
				var accz []string

				file, _ := os.Open("accounts.txt")

				scanner := bufio.NewScanner(file)

				for scanner.Scan() {
					exists[scanner.Text()] = true
					accz = append(accz, scanner.Text())
				}

				accs := strings.Split(i.ApplicationCommandData().Options[0].StringValue(), ",")

				for _, data := range accs {
					if exists[data] {
						accz = remove(accz, data)
					}
				}

				file.Close()

				rewrite("accounts.txt", strings.Join(accz, "\n"))

				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Embeds: []*discordgo.MessageEmbed{
							{
								Author:      &discordgo.MessageEmbedAuthor{},
								Color:       000000, // Green
								Description: "```Succesfully removed your Account(s)```",
								Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
								Title:       "MCSN Logs",
							},
						},
					},
				})
			}()
		},
		"create-task": func(s *discordgo.Session, i *discordgo.InteractionCreate) {
			go func() {
				var id string

				if i.Member == nil {
					id = i.User.ID
				} else {
					id = i.Member.User.ID
				}

				if id != acc.DiscordID {
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Embeds: []*discordgo.MessageEmbed{
								{
									Author:      &discordgo.MessageEmbedAuthor{},
									Color:       000000, // Green
									Description: "```You are not authorized to use this Bot.```",
									Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
									Title:       "MCSN Errors",
								},
							},
						},
					})
					return
				}

				dropTime := DropTime(i.ApplicationCommandData().Options[1].StringValue())

				if dropTime != 0 {
					if !strings.Contains(i.ApplicationCommandData().Options[1].StringValue(), "3n") && !strings.Contains(i.ApplicationCommandData().Options[1].StringValue(), "3c") && !strings.Contains(i.ApplicationCommandData().Options[1].StringValue(), "3l") && !strings.Contains(i.ApplicationCommandData().Options[1].StringValue(), "list") {
						acc.Task = append(acc.Task, Task{
							Name:  i.ApplicationCommandData().Options[1].StringValue(),
							Type:  "singlename",
							Unix:  dropTime,
							Delay: i.ApplicationCommandData().Options[0].IntValue(),
						})

						s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
							Type: discordgo.InteractionResponseChannelMessageWithSource,
							Data: &discordgo.InteractionResponseData{
								Embeds: []*discordgo.MessageEmbed{
									{
										Author:      &discordgo.MessageEmbedAuthor{},
										Color:       000000, // Green
										Description: fmt.Sprintf("```Succesfully created your task: %v ~ %v```", i.ApplicationCommandData().Options[1].StringValue(), time.Unix(dropTime, 0).Local().Format("2006-01-02 15:04:05")),
										Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
										Title:       "MCSN Logs",
									},
								},
							},
						})
					} else {
						acc.Task = append(acc.Task, Task{
							Type: i.ApplicationCommandData().Options[1].StringValue(),
						})

						s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
							Type: discordgo.InteractionResponseChannelMessageWithSource,
							Data: &discordgo.InteractionResponseData{
								Embeds: []*discordgo.MessageEmbed{
									{
										Author:      &discordgo.MessageEmbedAuthor{},
										Color:       000000, // Green
										Description: fmt.Sprintf("```Succesfully created your task: %v```", i.ApplicationCommandData().Options[1].StringValue()),
										Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
										Title:       "MCSN Logs",
									},
								},
							},
						})
					}
					acc.SaveConfig()
					acc.LoadState()
				} else {
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Embeds: []*discordgo.MessageEmbed{
								{
									Author:      &discordgo.MessageEmbedAuthor{},
									Color:       000000, // Green
									Description: fmt.Sprintf("```Unable to find droptime for task: %v```", i.ApplicationCommandData().Options[1].StringValue()),
									Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
									Title:       "MCSN Errors",
								},
							},
						},
					})
				}
			}()
		},
		"add-names": func(s *discordgo.Session, i *discordgo.InteractionCreate) {
			var id string
			var Names []string
			if i.Member == nil {
				id = i.User.ID
			} else {
				id = i.Member.User.ID
			}

			if id != acc.DiscordID {
				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Embeds: []*discordgo.MessageEmbed{
							{
								Author:      &discordgo.MessageEmbedAuthor{},
								Color:       000000, // Green
								Description: "```You are not authorized to use this Bot.```",
								Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
								Title:       "MCSN Errors",
							},
						},
					},
				})
				return
			}

			files, _ := ioutil.ReadFile("names.txt")

			Names = append(Names, string(files))
			Names = append(Names, strings.Split(i.ApplicationCommandData().Options[0].StringValue(), ",")...)

			rewrite("names.txt", strings.Join(Names, "\n"))
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Embeds: []*discordgo.MessageEmbed{
						{
							Author:      &discordgo.MessageEmbedAuthor{},
							Color:       000000, // Green
							Description: fmt.Sprintf("```Succesfully Added %v Name(s)```", len(Names)),
							Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
							Title:       "MCSN Logs",
						},
					},
				},
			})
		},
		"delete-names": func(s *discordgo.Session, i *discordgo.InteractionCreate) {
			var id string

			if i.Member == nil {
				id = i.User.ID
			} else {
				id = i.Member.User.ID
			}

			if id != acc.DiscordID {
				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Embeds: []*discordgo.MessageEmbed{
							{
								Author:      &discordgo.MessageEmbedAuthor{},
								Color:       000000, // Green
								Description: "```You are not authorized to use this Bot.```",
								Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
								Title:       "MCSN Errors",
							},
						},
					},
				})
				return
			}

			exists := make(map[string]bool)
			var accz []string

			file, _ := os.Open("names.txt")
			scanner := bufio.NewScanner(file)

			for scanner.Scan() {
				exists[scanner.Text()] = true
				accz = append(accz, scanner.Text())
			}

			accs := strings.Split(i.ApplicationCommandData().Options[0].StringValue(), ",")

			for _, data := range accs {
				if exists[data] {
					accz = remove(accz, data)
				}
			}

			file.Close()

			rewrite("names.txt", strings.Join(accz, "\n"))

			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Embeds: []*discordgo.MessageEmbed{
						{
							Author:      &discordgo.MessageEmbedAuthor{},
							Color:       000000, // Green
							Description: fmt.Sprintf("```Succesfully Removed %v Name(s)```", len(accz)),
							Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
							Title:       "MCSN Logs",
						},
					},
				},
			})
		},
	}
)

/*
func TaskThread() {
	for {
		time.Sleep(time.Second * 10)
		for _, task := range acc.Task {
			// if less than 3 minutes is left
			if task.Unix-time.Now().Unix() < 300 {
				sendEmbed(&discordgo.MessageEmbed{
					Author:      &discordgo.MessageEmbedAuthor{},
					Color:       000000, // Green
					Description: fmt.Sprintf("```Starting task %v```", task.Name),
					Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
					Title:       "MCSN Info",
				}, acc.DiscordID)

				var conns []*godo.Droplet
				if acc.Digital != "" {
					for i := 0; i < len(acc.Task); {
						newDroplet, res, err := client.Droplets.Create(context.TODO(), &godo.DropletCreateRequest{
							Name:   "super-cool-droplet",
							Region: "nyc3",
							Size:   "s-1vcpu-1gb",
							Image: godo.DropletCreateImage{
								Slug: "ubuntu-20-04-x64",
							},
							SSHKeys: []godo.DropletCreateSSHKey{
								{
									ID:          Key.ID,
									Fingerprint: Key.Fingerprint,
								},
							},
						})

						if res.StatusCode == 429 {
							sendEmbed(&discordgo.MessageEmbed{
								Author:      &discordgo.MessageEmbedAuthor{},
								Color:       000000, // Green
								Description: "```Rate limited sleeping for a minute.```",
								Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
								Title:       "MCSN Timers",
							}, acc.DiscordID)

							time.Sleep(time.Minute)
						} else {
							if err != nil {
								sendEmbed(&discordgo.MessageEmbed{
									Author:      &discordgo.MessageEmbedAuthor{},
									Color:       000000, // Green
									Description: "```Failed to build a VPS, continuing.```",
									Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
									Title:       "MCSN Errors",
								}, acc.DiscordID)
							} else {
								conns = append(conns, newDroplet)
							}
						}
						i++
					}
				}

				if len(conns) == 0 {
					sendEmbed(&discordgo.MessageEmbed{
						Author:      &discordgo.MessageEmbedAuthor{},
						Color:       000000, // Green
						Description: "```Cannot start the task(s) you werent able to generate Conns```",
						Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
						Title:       "MCSN Errors",
					}, acc.DiscordID)
				} else {
					for {
						if task.Unix-time.Now().Unix() < 60 {
							break
						}
						time.Sleep(1 * time.Second)
					}

					var meow []*godo.Droplet
					for _, conn := range conns {
						drop, _, _ := client.Droplets.Get(context.TODO(), conn.ID)
						meow = append(meow, drop)
					}

					conns = meow

					var Listofstring [][]Bearers
					for i := 0; i < 5; i++ {
						Listofstring = append(Listofstring, []Bearers{})
					}

					for _, nums := range acc.Bearers {
						Listofstring[accNum] = append(Listofstring[accNum], nums)
						accNum++
						if accNum == len(Listofstring) {
							increase++
							accNum = 0
						}
					}

					for i, conn := range conns {
						if i >= len(conns) {
							break
						} else {
							ip, _ := conn.PublicIPv4()

							if AddVps(ip, "22", "root", Listofstring[i], task) {
								sendEmbed(&discordgo.MessageEmbed{
									Author:      &discordgo.MessageEmbedAuthor{},
									Color:       000000, // Green
									Description: fmt.Sprintf("```Started task %v on IP: %v```", task.Name, ip),
									Timestamp:   time.Now().Format(time.RFC3339),
									Title:       "MCSN Logs",
								}, acc.DiscordID)
							}

							time.Sleep(1 * time.Second)
						}
					}
				}

				var ts = []Task{}
				for _, i := range acc.Task {
					if i.Name != task.Name {
						ts = append(ts, i)
					}
				}

				acc.Task = ts
				acc.SaveConfig()
				acc.LoadState()

				go func() {
					time.Sleep(time.Until(time.Unix(task.Unix, 0).Add(10 * time.Second)))

					var leg int = len(conns)
					for _, conn := range conns {
						client.Droplets.Delete(context.TODO(), conn.ID)
					}

					conns = []*godo.Droplet{}

					sendEmbed(&discordgo.MessageEmbed{
						Author:      &discordgo.MessageEmbedAuthor{},
						Color:       000000, // Green
						Description: fmt.Sprintf("```Deleted %v vpses succesfully : New length of conns %v```", leg, len(conns)),
						Timestamp:   time.Now().Format(time.RFC3339),
						Title:       "MCSN Logs",
					}, acc.DiscordID)
				}()
			}
		}
	}
}

func StartDigital() {
	client = godo.NewFromToken(acc.Digital)

	_, err := os.Stat("ssh")
	if os.IsNotExist(err) {
		os.Mkdir("ssh", 0755)

		privateKey, err := generatePrivateKey(4096)
		if err != nil {
			log.Fatal(err.Error())
		}

		publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
		if err != nil {
			log.Fatal(err.Error())
		}

		privateKeyBytess := encodePrivateKeyToPEM(privateKey)

		err = writeKeyToFile(privateKeyBytess, "./ssh/privatekey")
		if err != nil {
			log.Fatal(err.Error())
		}

		err = writeKeyToFile([]byte(publicKeyBytes), "./ssh/publickey.pub")
		if err != nil {
			log.Fatal(err.Error())
		}

		content, _ = ioutil.ReadFile("/ssh/publickey.pub")
		privateKeyBytes, _ = ioutil.ReadFile("./ssh/privatekey")
		Keys, _, err := client.Keys.List(context.TODO(), &godo.ListOptions{
			Page:    1,
			PerPage: 1,
		})
		if err != nil {
			fmt.println()
			sendE("Error: " + err.Error())
		} else {
			if len(Keys) == 0 {
				Key, _, err = client.Keys.Create(context.TODO(), &godo.KeyCreateRequest{
					Name:      "key",
					PublicKey: string(content),
				})
				if err != nil {
					sendE("Error: " + err.Error())
				}
			} else {
				Key = &Keys[0]
			}
		}
	} else {
		content, _ = ioutil.ReadFile("./ssh/publickey.pub")
		privateKeyBytes, _ = ioutil.ReadFile("./ssh/privatekey")
		Keys, _, err := client.Keys.List(context.TODO(), &godo.ListOptions{
			Page:    1,
			PerPage: 1,
		})
		if err != nil {
			sendE("Error: " + err.Error())
		} else {
			if len(Keys) == 0 {
				Key, _, err = client.Keys.Create(context.TODO(), &godo.KeyCreateRequest{
					Name:      "key",
					PublicKey: string(content),
				})
				if err != nil {
					sendE("Error: " + err.Error())
				}
			} else {
				Key = &Keys[0]
			}
		}
	}
}

func AddVps(ip, port, user string, Output []Bearers, task Task) bool {
	signer, err := signerFromPem(privateKeyBytes, content)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
	}
	conn, err := ssh.Dial("tcp", ip+":"+port, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		User:            user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
	})

	if err != nil {
		sendEmbed(&discordgo.MessageEmbed{
			Author:      &discordgo.MessageEmbedAuthor{},
			Color:       000000, // Green
			Description: fmt.Sprintf("```Error on %v: %v```", ip, err.Error()),
			Timestamp:   time.Now().Format(time.RFC3339),
			Title:       "MCSN Errors",
		}, acc.DiscordID)
	} else {
		session, _ := sftp.NewClient(conn)
		defer session.Close()

		file, err := os.Open("./botsniper/sniper")
		if err != nil {
			sendEmbed(&discordgo.MessageEmbed{
				Author:      &discordgo.MessageEmbedAuthor{},
				Color:       000000, // Green
				Description: fmt.Sprintf("```Error on %v: %v```", ip, err.Error()),
				Timestamp:   time.Now().Format(time.RFC3339),
				Title:       "MCSN Errors",
			}, acc.DiscordID)
		} else {
			dstFile, err := session.Create("/root/snipe")
			if err != nil {
				sendEmbed(&discordgo.MessageEmbed{
					Author:      &discordgo.MessageEmbedAuthor{},
					Color:       000000, // Green
					Description: fmt.Sprintf("```Error on %v: %v```", ip, err.Error()),
					Timestamp:   time.Now().Format(time.RFC3339),
					Title:       "MCSN Errors",
				}, acc.DiscordID)
			} else {
				if _, err := dstFile.ReadFrom(file); err == nil {
					sesh, _ := conn.NewSession()
					defer sesh.Close()

					var stdoutBuf bytes.Buffer
					sesh.Stdout = &stdoutBuf

					Listofstr, _ := json.Marshal(Output)

					err := sesh.Run(fmt.Sprintf("git clone https://github.com/Liza-Developer/mcsn\ncd mcsn\ncd botsniper\nchmod +x ./sniper\ntmux ./sniper snipe -j %v -d %v -k %v -n %v -delay %v", string(Listofstr), acc.DiscordID, acc.DiscordBotToken, task.Name, task.Delay))
					if err != nil {
						sendEmbed(&discordgo.MessageEmbed{
							Author:      &discordgo.MessageEmbedAuthor{},
							Color:       000000, // Green
							Description: fmt.Sprintf("```Error on %v: %v```", ip, err.Error()),
							Timestamp:   time.Now().Format(time.RFC3339),
							Title:       "MCSN Errors",
						}, acc.DiscordID)
					}
				}
			}
			defer dstFile.Close()
		}
		return true
	}
	return false
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(privateKey),
	})
}

// generatePublicKey take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}

	return ssh.MarshalAuthorizedKey(publicRsaKey), nil
}

func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}

	log.Printf("Key saved to: %s", saveFileTo)
	return nil
}

func signerFromPem(pemBytes []byte, password []byte) (ssh.Signer, error) {
	// read pem block
	err := errors.New("Pem decode failed, no key found")
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, err
	}

	// handle encrypted key
	if x509.IsEncryptedPEMBlock(pemBlock) {
		// decrypt PEM
		pemBlock.Bytes, err = x509.DecryptPEMBlock(pemBlock, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("Decrypting PEM block failed %v", err)
		}

		// get RSA, EC or DSA key
		key, err := parsePemBlock(pemBlock)
		if err != nil {
			return nil, err
		}

		// generate signer instance from key
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			return nil, fmt.Errorf("Creating signer from encrypted key failed %v", err)
		}

		return signer, nil
	} else {
		// generate signer instance from plain key
		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("Parsing plain private key failed %v", err)
		}

		return signer, nil
	}
}

func parsePemBlock(block *pem.Block) (interface{}, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Parsing PKCS private key failed %v", err)
		} else {
			return key, nil
		}
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Parsing EC private key failed %v", err)
		} else {
			return key, nil
		}
	case "DSA PRIVATE KEY":
		key, err := ssh.ParseDSAPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Parsing DSA private key failed %v", err)
		} else {
			return key, nil
		}
	default:
		return nil, fmt.Errorf("Parsing private key failed, unsupported key type %q", block.Type)
	}
}

*/
