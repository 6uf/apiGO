package apiGO

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/pkg/sftp"
	"github.com/vultr/govultr/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

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
	AccessToken *string `json:"accessToken"`
}

type MCbearers struct {
	Details []Info
}

type Info struct {
	Bearer      string
	AccountType string
	Email       string
	Password    string
}

type Config struct {
	Bearers           []Bearers `json:"Bearers"`
	ChangeSkinLink    string    `json:"ChangeSkinLink"`
	ChangeskinOnSnipe bool      `json:"ChangeskinOnSnipe"`
	DiscordBotToken   string    `json:"DiscordBotToken"`
	DiscordID         string    `json:"DiscordID"`
	GcReq             int       `json:"GcReq"`
	MFAReq            int       `json:"MFAReq"`
	ManualBearer      bool      `json:"ManualBearer"`
	SpreadPerReq      int       `json:"SpreadPerReq"`
	Vultr             string    `json:"VultrKey"`
	Vps               []Vps     `json:"Vps"`
	Task              []Task    `json:"Tasks"`
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
	Name     string `json:"name"`
	Unix     int64  `json:"unix"`
	Searches string `json:"searches"`
	Type     string `json:"type"`
}

type Searches struct {
	Searches string `json:"searches"`
}

type Output struct {
	Group    string      `json:"group"`
	Accounts [][]Bearers `json:"accounts"`
}

var (
	redirect       string
	GuildID        = flag.String("guild", "", "Test guild ID. If not passed - bot registers commands globally")
	RemoveCommands = flag.Bool("rmcmd", true, "Remove all commands after shutdowning or not")
	s              *discordgo.Session
	acc            Config

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
			Name:        "vpses-loaded",
			Description: "Check the vpses you have loaded atm!",
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
		"vpses-loaded": func(s *discordgo.Session, i *discordgo.InteractionCreate) {
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

				if acc.Vps == nil || len(acc.Vps) == 0 {
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Embeds: []*discordgo.MessageEmbed{
								{
									Author:      &discordgo.MessageEmbedAuthor{},
									Color:       000000, // Green
									Description: "```You have no vpses loaded, please add some.```",
									Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
									Title:       "MCSN Errors",
								},
							},
						},
					})
					return
				}

				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Embeds: []*discordgo.MessageEmbed{
							{
								Author:      &discordgo.MessageEmbedAuthor{},
								Color:       000000, // Green
								Description: fmt.Sprintf("```Vpses: %v```", acc.Vps),
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

				if acc.Vps == nil || len(acc.Vps) == 0 {
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Embeds: []*discordgo.MessageEmbed{
								{
									Author:      &discordgo.MessageEmbedAuthor{},
									Color:       000000, // Green
									Description: "```You have no vpses loaded, please add some.```",
									Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
									Title:       "MCSN Errors",
								},
							},
						},
					})
					return

				} else {
					if !strings.ContainsAny(i.ApplicationCommandData().Options[1].StringValue(), "3n 3c list 3l") {
						acc.Task = append(acc.Task, Task{
							Name: i.ApplicationCommandData().Options[1].StringValue(),
							Type: "singlename",
							Unix: DropTime(i.ApplicationCommandData().Options[1].StringValue()),
						})
					} else {
						acc.Task = append(acc.Task, Task{
							Type: i.ApplicationCommandData().Options[1].StringValue(),
						})
					}

					acc.SaveConfig()
					acc.LoadState()

					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Embeds: []*discordgo.MessageEmbed{
								{
									Author:      &discordgo.MessageEmbedAuthor{},
									Color:       000000, // Green
									Description: "```Succesfully created your task.```",
									Timestamp:   time.Now().Format(time.RFC3339), // Discord wants ISO8601; RFC3339 is an extension of ISO8601 and should be completely compatible.
									Title:       "MCSN Logs",
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

				var conns []*govultr.Instance
				var vultrClient *govultr.Client
				if acc.Vultr != "" {
					config := &oauth2.Config{}
					ts := config.TokenSource(context.Background(), &oauth2.Token{AccessToken: acc.Vultr})
					vultrClient = govultr.NewClient(oauth2.NewClient(context.Background(), ts))
					for i := 0; i < len(acc.Task); {
						res, _ := vultrClient.Instance.Create(context.Background(), &govultr.InstanceCreateReq{
							Label:      "sniper-vpses",
							Hostname:   "sniper-vpses",
							Backups:    "disabled",
							EnableIPv6: &[]bool{false}[0],
							OsID:       362,
							Plan:       "vc2-1c-2gb",
							Region:     "nyc1",
						})

						if AddVps(res.MainIP, "22", res.DefaultPassword, "root") {
							conns = append(conns, res)
						}
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
					}

					var outputlist = make(map[string][][]Bearers)
					var meow int = 0
					var amount int

					for _, inp := range acc.Bearers {
						if inp.Type == "Giftcard" {
							amount = 5
						} else {
							amount = 1
						}

						if len(outputlist[inp.Type]) == 0 {
							outputlist[inp.Type] = append(outputlist[inp.Type], []Bearers{inp})
						} else {
							if len(outputlist[inp.Type][meow]) < amount {
								outputlist[inp.Type][meow] = append(outputlist[inp.Type][meow], inp)
							} else {
								meow++
								outputlist[inp.Type] = append(outputlist[inp.Type], []Bearers{inp})
							}
						}
					}

					var outputs []Output
					for i, outp := range outputlist {
						outputs = append(outputs, Output{Group: i, Accounts: outp})
					}

					for _, info := range outputs {
						fmt.Println(info.Accounts)
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

				for _, conn := range conns {
					err := vultrClient.BareMetalServer.Delete(context.Background(), conn.ID)
					if err != nil {
						sendE(err.Error())
					}
				}
			}
		}
	}
}

func AddVps(ip, port, password, user string) bool {
	conn, err := ssh.Dial("tcp", ip+":"+port, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		User:            user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
	})
	if err != nil {
		sendE("Error: " + err.Error())
	} else {
		session, _ := sftp.NewClient(conn)
		defer session.Close()

		file, _ := os.Open("sniper")

		dstFile, err := session.Create("/root/snipe")
		if err != nil {
			sendE("Error: " + err.Error())
		} else {
			if _, err := dstFile.ReadFrom(file); err == nil {
				acc.Vps = append(acc.Vps, Vps{
					IP:       ip,
					Port:     port,
					Password: password,
					User:     user,
				})
			}

			acc.SaveConfig()
			acc.LoadState()

			sesh, _ := conn.NewSession()
			defer sesh.Close()

			var stdoutBuf bytes.Buffer
			sesh.Stdout = &stdoutBuf
			sesh.Run("chmod +x ./snipe\n")
		}

		dstFile.Close()

		return true
	}

	return false
}
