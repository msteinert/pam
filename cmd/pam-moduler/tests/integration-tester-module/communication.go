// Package main is the package for the integration tester module PAM shared library.
package main

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
)

// Request is a serializable integration module tester structure request.
type Request struct {
	Action     string
	ActionArgs []interface{}
}

// Result is a serializable integration module tester structure result.
type Result = Request

// NewRequest returns a new Request.
func NewRequest(action string, actionArgs ...interface{}) Request {
	return Request{action, actionArgs}
}

// GOB serializes the request in binary format.
func (r *Request) GOB() ([]byte, error) {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	if err := e.Encode(r); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// NewRequestFromGOB gets a Request from a serialized binary.
func NewRequestFromGOB(data []byte) (*Request, error) {
	b := bytes.Buffer{}
	b.Write(data)
	d := gob.NewDecoder(&b)

	var req Request
	if err := d.Decode(&req); err != nil {
		return nil, err
	}
	return &req, nil
}

const bufSize = 1024

type connectionHandler struct {
	inOutData  chan []byte
	outErr     chan error
	SocketPath string
}

// Listener is a socket listener.
type Listener struct {
	connectionHandler
	listener net.Listener
}

// NewListener creates a new Listener.
func NewListener(socketPath string) *Listener {
	if len(socketPath) > 90 {
		// See https://manpages.ubuntu.com/manpages/jammy/man7/sys_un.h.7posix.html#application%20usage
		panic(fmt.Sprintf("Socket path %s too long", socketPath))
	}
	return &Listener{connectionHandler{SocketPath: socketPath}, nil}
}

// WaitForData waits for result data (or an error) on connection to be returned.
func (c *connectionHandler) WaitForData() (*Result, error) {
	data, err := <-c.inOutData, <-c.outErr
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, err
	}

	req, err := NewRequestFromGOB(data)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// SendRequest sends a request to the connection.
func (c *connectionHandler) SendRequest(req *Request) error {
	bytes, err := req.GOB()
	if err != nil {
		return err
	}

	c.inOutData <- bytes
	return nil
}

// SendResult sends the Result to the connection.
func (c *connectionHandler) SendResult(res *Result) error {
	return c.SendRequest(res)
}

// DoRequest performs a Request on the connection, waiting for data.
func (c *connectionHandler) DoRequest(req *Request) (*Result, error) {
	if err := c.SendRequest(req); err != nil {
		return nil, err
	}

	return c.WaitForData()
}

// Send performs a request.
func (r *Request) Send(c *connectionHandler) error {
	return c.SendRequest(r)
}

// ErrAlreadyListening is the error if a listener is already set.
var ErrAlreadyListening = errors.New("listener already set")

// StartListening initiates the unix listener.
func (l *Listener) StartListening() error {
	if l.listener != nil {
		return ErrAlreadyListening
	}

	listener, err := net.Listen("unix", l.SocketPath)
	if err != nil {
		return err
	}

	l.listener = listener
	l.inOutData, l.outErr = make(chan []byte), make(chan error)

	go func() {
		bytes, err := func() ([]byte, error) {
			for {
				c, err := l.listener.Accept()
				if err != nil {
					return nil, err
				}

				for {
					buf := make([]byte, bufSize)
					nr, err := c.Read(buf)
					if err != nil {
						return buf, err
					}

					data := buf[0:nr]
					l.inOutData <- data
					l.outErr <- nil

					_, err = c.Write(<-l.inOutData)
					if err != nil {
						return nil, err
					}
				}
			}
		}()

		l.inOutData <- bytes
		l.outErr <- err
	}()

	return nil
}

// Connector is a connection type.
type Connector struct {
	connectionHandler
	connection net.Conn
}

// NewConnector creates a new connection.
func NewConnector(socketPath string) *Connector {
	return &Connector{connectionHandler{SocketPath: socketPath}, nil}
}

// ErrAlreadyConnected is the error if a connection is already set.
var ErrAlreadyConnected = errors.New("connection already set")

// Connect connects to a listening unix socket.
func (c *Connector) Connect() error {
	if c.connection != nil {
		return ErrAlreadyConnected
	}

	connection, err := net.Dial("unix", c.SocketPath)
	if err != nil {
		return err
	}

	runtime.SetFinalizer(c, func(c *Connector) {
		c.connection.Close()
	})

	c.connection = connection
	c.inOutData, c.outErr = make(chan []byte), make(chan error)

	go func() {
		buf := make([]byte, bufSize)
		writeAndRead := func() ([]byte, error) {
			data := <-c.inOutData
			_, err := c.connection.Write(data)
			if err != nil {
				return nil, err
			}

			n, err := c.connection.Read(buf[:])
			if err != nil {
				return nil, err
			}

			return buf[0:n], nil
		}

		for {
			bytes, err := writeAndRead()
			c.inOutData <- bytes
			c.outErr <- err
		}
	}()

	return nil
}
