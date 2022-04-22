package apiGO

import (
	"crypto/tls"
	"time"
)

// https://github.com/overestimate/awm-src/blob/master/httping.go (used from emmas awm sniper check it out)

func PingMC() float64 {
	conn, _ := tls.Dial("tcp", "api.minecraftservices.com:443", nil)
	tmpVar := make([]byte, 4096)
	t1 := time.Now()
	conn.Write([]byte("HEAD /minecraft/profile HTTP/1.1\r\nUser-Agent: httping.go/0.1\r\n\r\n"))
	conn.Read(tmpVar)
	return float64(time.Now().Sub(t1).Milliseconds())
}
