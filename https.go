package main

// Some code Copyright (c) 2020 Andrew Ayer, under X11, MIT-advertising license

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

func tcpSniTlsProxy() {

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 443})
	if err != nil {
		log.Fatalln(err)
	}
	defer ln.Close()

	for {
		dbg.Println("443/waiting for accept")

		netconn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			time.Sleep(time.Second * 10)
		}

		dbg.Println("443/socket accepted")

		//	tcpconn := netconn.(*net.TCPConn)

		go func() {
			defer netconn.Close()
			proxySingleConnection(netconn)
		}()
	}
	// unreachable code
	//return
}

// read only conn
type ROConn struct {
	reader io.Reader
}

func (x ROConn) Read(p []byte) (int, error)         { return x.reader.Read(p) }
func (x ROConn) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (x ROConn) Close() error                       { return nil }
func (x ROConn) LocalAddr() net.Addr                { return nil }
func (x ROConn) RemoteAddr() net.Addr               { return nil }
func (x ROConn) SetDeadline(t time.Time) error      { return nil }
func (x ROConn) SetReadDeadline(t time.Time) error  { return nil }
func (x ROConn) SetWriteDeadline(t time.Time) error { return nil }

func proxySingleConnection(in net.Conn) {

	var err error

	servername := ""

	conf := &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			servername = argHello.ServerName
			return nil, nil
		},
	}

	err = in.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		log.Println("SetReadDeadline", err)
		return
	}

	tlsbuf := new(bytes.Buffer)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	_ = cancel

	newconn := ROConn{reader: io.TeeReader(in, tlsbuf)}
	/////XXXXXX Go 1.17!!1
	_ = ctx
	//_ = tls.Server(newconn, conf).HandshakeContext(ctx)
	_ = tls.Server(newconn, conf).Handshake()

	log.Println("https connection for:", servername)

	err = in.SetReadDeadline(time.Time{})
	if err != nil {
		log.Println("SetReadDeadline", err)
		return
	}

	conn2, err := net.DialTimeout("tcp", "localhost:8443", 5*time.Second)
	if err != nil {
		log.Print(err)
		return
	}
	defer conn2.Close()

	preloadReader := io.MultiReader(tlsbuf, in)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		_, _ = io.Copy(in, conn2)
		_ = in.(*net.TCPConn).CloseWrite()
		wg.Done()
	}()
	go func() {
		_, _ = io.Copy(conn2, preloadReader)
		_ = conn2.(*net.TCPConn).CloseWrite()
		wg.Done()
	}()

	wg.Wait()

}
