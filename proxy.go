package apiGO

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

func (Proxy *Proxys) GetProxys() {
	Proxy.Proxys = &[]string{}
	file, err := os.Open("proxys.txt")
	defer file.Close()
	if err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			*Proxy.Proxys = append(*Proxy.Proxys, scanner.Text())
		}
	}
}

func (Proxy *Proxys) Setup() {
	Proxy.Used = make(map[string]bool)
	for _, proxy := range *Proxy.Proxys {
		Proxy.Used[proxy] = false
	}
}

func (Proxy *Proxys) RandProxy() string {
	for {
		rand.Seed(time.Now().UnixNano())
		fmt.Println(Proxy.Proxys)
		proxy := (*Proxy.Proxys)[rand.Intn(len(*Proxy.Proxys))]
		if !Proxy.Used[proxy] {
			Proxy.Used[proxy] = true
			return proxy
		}
	}
}

func (Bearers *MCbearers) GenSocketConns(Proxy ReqConfig, name string) (pro []Proxys) {
	var Accs [][]Info
	var incr int
	var use int
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(`
	-- GlobalSign Root R2, valid until Dec 15, 2021
	-----BEGIN CERTIFICATE-----
	MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4G
	A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNp
	Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1
	MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEG
	A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
	hvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPL
	v4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8
	eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklq
	tTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzd
	C9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pa
	zq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCB
	mTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IH
	V2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5n
	bG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG
	3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4Gs
	J0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO
	291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavS
	ot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxd
	AfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7
	TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==
	-----END CERTIFICATE-----`))

	for _, Acc := range Bearers.Details {
		if len(Accs) == 0 {
			Accs = append(Accs, []Info{
				Acc,
			})
		} else {
			if incr == 3 {
				incr = 0
				use++
				Accs = append(Accs, []Info{})
			}
			Accs[use] = append(Accs[use], Acc)
		}
		incr++
	}

	var wg sync.WaitGroup
	for _, Accs := range Accs {
		wg.Add(1)
		go func(Accs []Info) {
			var user, pass, ip, port string
			auth := strings.Split(Proxy.Proxys.RandProxy(), ":")
			ip, port = auth[0], auth[1]
			if len(auth) > 2 {
				user, pass = auth[2], auth[3]
			}
			req, err := proxy.SOCKS5("tcp", fmt.Sprintf("%v:%v", ip, port), &proxy.Auth{
				User:     user,
				Password: pass,
			}, proxy.Direct)
			if err == nil {
				conn, err := req.Dial("tcp", "api.minecraftservices.com:443")
				if err == nil {
					pro = append(pro, Proxys{
						Accounts: Accs,
						Conn:     tls.Client(conn, &tls.Config{RootCAs: roots, InsecureSkipVerify: true, ServerName: "api.minecraftservices.com"}),
					})
				}
			}
			wg.Done()
		}(Accs)
	}

	wg.Wait()
	return
}
