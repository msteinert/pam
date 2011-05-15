// This is a fake login implementation!  It uses whatever default
// PAM service configuration is available on the system, and tries
// to authenticate any user.  This should cause PAM to ask its
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
// (!WARNING!) It echos your password to the terminal (!WARNING!)
// It doesn't switch users.
// It's not a real login.
//
// It does however demonstrate a simple but powerful use of Go PAM.

package main

import(
    "fmt"
    "github.com/krockot/gopam/pam"
    "os"
    "bufio"
)

func GetLine(prompt string) (string,bool) {
    fmt.Print(prompt)
    in := bufio.NewReader(os.Stdin)
    input,err := in.ReadString('\n')
    if err != nil {
        return "",false
    }
    return input[:len(input)-1],true
}

// Echo on/off is ignored; echo will always happen.
func DumbPrompter(style int, msg string) (string,bool) {
    switch style {
        case pam.PROMPT_ECHO_OFF:
            return GetLine(msg)
        case pam.PROMPT_ECHO_ON:
            return GetLine(msg)
        case pam.ERROR_MSG:
            fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
            return "",true
        case pam.TEXT_INFO:
            fmt.Println(msg)
            return "",true
    }
    return "",false
}

func main() {
    t,status := pam.Start("", "", pam.ResponseFunc(DumbPrompter))
    if status != pam.SUCCESS {
        fmt.Fprintf(os.Stderr, "Start() failed: %s\n", t.Error(status))
        return
    }
    defer func(){ t.End(status) }()

    status = t.Authenticate(0)
    if status != pam.SUCCESS {
        fmt.Fprintf(os.Stderr, "Auth failed: %s\n", t.Error(status))
        return
    }

    fmt.Printf("Authentication succeeded!\n")
    fmt.Printf("Goodbye, friend.\n")
}

