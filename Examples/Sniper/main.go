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
	var AccountsVer []string
	fmt.Print(" Name: \n>>")
	fmt.Scan(&name)
	fmt.Print("Delay: \n>>")
	fmt.Scan(&delay)

	fmt.Println()
	
	file, err := os.Open("accounts.txt")
	if err != nil {
		fmt.Println(err.Error())
	}
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		AccountsVer = append(AccountsVer, scanner.Text())
	}

	bearers, _ := apiGO.Auth(AccountsVer)
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
