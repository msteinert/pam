[![GoDoc](https://godoc.org/github.com/msteinert/pam?status.svg)](http://godoc.org/github.com/msteinert/pam)
[![Go Report Card](https://goreportcard.com/badge/github.com/msteinert/pam)](https://goreportcard.com/report/github.com/msteinert/pam)

# Go PAM

This is a Go wrapper for the PAM application API.

## Testing

To run the full suite, the tests must be run as the root user. To setup your
system for testing, create a user named "test" with the password "secret". For
example:

```
$ sudo useradd test \
    -d /tmp/test \
    -p '$1$Qd8H95T5$RYSZQeoFbEB.gS19zS99A0' \
    -s /bin/false
```

Then execute the tests:

```
$ sudo GOPATH=$GOPATH $(which go) test -v
```

[1]: http://godoc.org/github.com/msteinert/pam
[2]: http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_ADG.html
