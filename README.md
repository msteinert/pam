[![Build Status](https://travis-ci.org/msteinert/pam.svg?branch=master)](https://travis-ci.org/msteinert/pam)
[![GoDoc](https://godoc.org/github.com/msteinert/pam?status.svg)](http://godoc.org/github.com/msteinert/pam)

# Go PAM

This is a Go wrapper for the PAM application API. There's not much
else to be said. PAM is a simple API and now it's available for use in Go
applications.

There's an example of a "fake login" program in the examples directory.
Look at the pam module's [godocs][1] for details about the Go API, or refer
to the official [PAM documentation][2].

The test suite must be run as the root user. To setup your system for testing,
create a user named "test" with the password "secret". For example:

```
$ sudo useradd test \
    -d /tmp/test \
    -p '$1$Qd8H95T5$RYSZQeoFbEB.gS19zS99A0' \
    -s /bin/false
```

[1]: http://godoc.org/github.com/msteinert/pam
[2]: http://www.kernel.org/pub/linux/libs/pam/Linux-PAM-html/adg-interface-by-app-expected.html
