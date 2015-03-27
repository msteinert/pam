// This is a fake login implementation. It uses whatever default
// PAM service configuration is available on the system, and tries
// to authenticate any user. This should cause PAM to ask its
// conversation handler for a username and password, in sequence.
//
// This application will handle those requests by displaying the
// PAM-provided prompt and sending back the first line of stdin input
// it can read for each.
//
// Keep in mind that unless run as root (or setuid root), the only
// user's authentication that can succeed is that of the process owner.
//
// It's not a real login for several reasons:
//
// It doesn't switch users.
// It's not a real login.
//
// It does however demonstrate a simple but powerful use of PAM.

package main

import (
	"bufio"
	"code.google.com/p/gopass"
	"errors"
	"fmt"
	"github.com/msteinert/pam"
	"log"
	"os"
)

func main() {
	t, err := pam.StartFunc("", "", func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return gopass.GetPass(msg)
		case pam.PromptEchoOn:
			fmt.Print(msg)
			bio := bufio.NewReader(os.Stdin)
			input, err := bio.ReadString('\n')
			if err != nil {
				return "", err
			}
			return input[:len(input)-1], nil
		case pam.ErrorMsg:
			log.Print(msg)
			return "", nil
		case pam.TextInfo:
			fmt.Println(msg)
			return "", nil
		}
		return "", errors.New("Unrecognized message style")
	})
	if err != nil {
		log.Fatalf("Start: %s", err.Error())
	}
	err = t.Authenticate(0)
	if err != nil {
		log.Fatalf("Authenticate: %s", err.Error())
	}
	log.Print("Authentication succeeded!")
}
