package apiGO

import (
	"errors"
	"strings"
	"time"

	"github.com/Tnze/go-mc/bot"
	"github.com/Tnze/go-mc/bot/basic"
	"github.com/Tnze/go-mc/chat"
	pk "github.com/Tnze/go-mc/net/packet"
	"github.com/google/uuid"
)

func NameMC(Bearer string) string {
	C := bot.NewClient()
	B := GetProfileInformation(Bearer)
	C.Auth = bot.Auth{
		AsTk: Bearer,
		UUID: B.ID,
		Name: B.Name,
	}
	basic.EventsListener{
		GameStart: func() error {
			go func() {
				time.Sleep(time.Millisecond * 500)
				C.Conn.WritePacket(pk.Marshal(
					0x03,
					pk.String("/namemc"),
				))
			}()
			return nil
		},
		ChatMsg: func(c chat.Message, pos byte, uuid uuid.UUID) error {
			if KEY := c.ClearString(); strings.Contains(KEY, "https://namemc.com/claim?key=") {
				return errors.New("got-key:" + KEY)
			}
			return nil
		},
	}.Attach(C)
	C.JoinServer("blockmania.com")
	if err := C.HandleGame(); err != nil && strings.Contains(err.Error(), "got-key") {
		return strings.Split(err.Error(), ":")[0]
	}
	return "Error: Unable to find a valid url."
}
