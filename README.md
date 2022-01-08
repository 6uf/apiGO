# apiGO
A library for Minecraft's name change api, this utilizes sockets and supports MSAUTH.


# Usage Tutorial

First you will need 2 files, a accounts.txt and a config.json

inside of the config.json will be;

```json
{
    "Bearers": [],
    "ChangeSkinLink": "https://textures.minecraft.net/texture/393e1dc4b234665792c7775d2466f109421d0145ed7d3d63d89d5d4e0dbf5228",
    "DiscordBotToken": "",
    "DiscordID": "",
    "ManualBearer": false,
    "Vps": []
}
```

This is so the library can detect the values needed and also store the bearers it auths into the Bearers: [], the other info is used for sniper settings and the discord bot if you ever use it will store added vpses into the Vps: [] list.

# Features

Some of this librarys features are;

- Invalid bearer detection
- Bearer caching for reusability
- Built in multi account sniping support
- Helper functions like Sum() `gets the sum of a int array` SendWebhook() `sends a discord webhook` Droptime() `Gets a names droptime value` and ChangeSkin `changes the accounts skin.`
- A self hostable DISCORD BOT that manages your accounts, vpses and snipes. It has security so ONLY the DiscordID in your config.json can use it.
- THERES ALOT MORE! and more to be included!

# Examples

This is a 60~ line multi account sniper i made using the Library, it supports GCs, Mojang and Microsoft accounts.

```go
package main

import (
	"fmt"
	"sync"

	"github.com/Liza-Developer/apiGO"
	"github.com/logrusorgru/aurora/v3"
)

var (
	name  string
	delay float64
)

func main() {

	fmt.Print(" Name: \n>>")
	fmt.Scan(&name)
	fmt.Print("Delay: \n>>")
	fmt.Scan(&delay)

	fmt.Println()

	bearers, _ := apiGO.Auth()
	dropTime := apiGO.DropTime(name)

	apiGO.PreSleep(dropTime)

	paload := bearers.CreatePayloads(name)

	apiGO.Sleep(dropTime, delay)

	var wg sync.WaitGroup

	fmt.Println()

	for e, acc := range paload.AccountType {
		if acc == "Giftcard" {
			for i := 0; i < 6; i++ {
				wg.Add(1)
				go func() {
					send, recv, status := paload.SocketSending(int64(e))
					if status == "200" {
						fmt.Printf("Sent @ %v ~ [%v] @ %v \n", send.Format("05.00000"), aurora.Green("SUCCESS"), recv.Format("05.00000"))
					} else {
						fmt.Printf("Sent @ %v ~ [%v] @ %v \n", send.Format("05.00000"), aurora.Red(status), recv.Format("05.00000"))
					}
					wg.Done()
				}()
			}
		} else {
			for i := 0; i < 2; i++ {
				wg.Add(1)
				go func() {
					send, recv, status := paload.SocketSending(int64(e))
					if status == "200" {
						fmt.Printf("Sent @ %v ~ [%v] @ %v \n", send.Format("05.00000"), aurora.Green("SUCCESS"), recv.Format("05.00000"))
					} else {
						fmt.Printf("Sent @ %v ~ [%v] @ %v \n", send.Format("05.00000"), aurora.Red(status), recv.Format("05.00000"))
					}
					wg.Done()
				}()
			}
		}
	}

	wg.Wait()
}
```

