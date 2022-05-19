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

func (Data Details) ClaimNameMC() (URL string) {
	if Data.Info.ID == "" {
		Data.Info = GetProfileInformation(Data.Bearer)
	}
	C := bot.NewClient()

	C.Auth = bot.Auth{
		AsTk: Data.Bearer,
		Name: Data.Info.Name,
		UUID: Data.Info.ID,
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
			cStr := c.ClearString()
			if strings.Contains(cStr, "https://namemc.com/claim?key=") {
				URL = cStr
				return errors.New("got-key:200")
			}
			return nil
		},
	}.Attach(C)
	C.JoinServer("blockmania.com")

	if err := C.HandleGame(); err != nil && strings.Contains(err.Error(), "got-key:200") {
		return
	}

	return "Unable to find URL"
}
