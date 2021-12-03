package pam_test

import (
	"bufio"
	"errors"
	"fmt"
	"os"

	"github.com/msteinert/pam"
	"golang.org/x/term"
)

// This example uses the default PAM service to authenticate any users. This
// should cause PAM to ask its conversation handler for a username and password
// in sequence.
func Example() {
	t, err := pam.StartFunc("", "", func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			fmt.Print(msg)
			pw, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return "", err
			}
			fmt.Println()
			return string(pw), nil
		case pam.PromptEchoOn:
			fmt.Print(msg)
			s := bufio.NewScanner(os.Stdin)
			s.Scan()
			return s.Text(), nil
		case pam.ErrorMsg:
			fmt.Fprintf(os.Stderr, "%s\n", msg)
			return "", nil
		case pam.TextInfo:
			fmt.Println(msg)
			return "", nil
		default:
			return "", errors.New("unrecognized message style")
		}
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "start: %s\n", err.Error())
		os.Exit(1)
	}
	err = t.Authenticate(0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "authenticate: %s\n", err.Error())
		os.Exit(1)
	}
	fmt.Println("authentication succeeded!")
}
