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

	redigo "github.com/gomodule/redigo/redis"
)

func tcpSniTlsProxy() {

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 443})
	if err != nil {
		log.Fatalln(err)
	}
	defer ln.Close()

	log.Println("sni/waiting for accept", ln.Addr())

	for {

		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			time.Sleep(time.Second * 10)
		}

		dbg.Println("sni/sockacceptee/local/remote", conn.LocalAddr(), conn.RemoteAddr())

		go func() {
			defer conn.Close()

			proxySingleConnection(conn)

			dbg.Println("sni/finished/local/remote", conn.LocalAddr(), conn.RemoteAddr())

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

/*
there are hard questions, about (and more)
1. what operations should timeout
2. the browser wants to hold this open forever, should we let it?
3. do we use SetReadDeadline(), ctx timeouts or both
---
the plan for now:
- let the browser hold stuff open forever
- dont use SetReadDeadline()
- use a ctx.withtimeout to put a timelimit on the setup, but not the proxying
*/
func proxySingleConnection(in net.Conn) {

	// time limit to get started
	// will not interrupt the copying of sockets
	max := time.Second * 10
	ctx, cancel := context.WithTimeout(context.Background(), max)
	defer cancel()

	var err error

	domain := ""

	conf := &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			domain = argHello.ServerName
			return nil, nil
		},
	}

	err = in.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		log.Println("SetReadDeadline", err)
		return
	}

	tlsbuf := new(bytes.Buffer)

	newconn := ROConn{reader: io.TeeReader(in, tlsbuf)}

	// we dont use the connection, we merely scarf the hostname
	_ = tls.Server(newconn, conf).HandshakeContext(ctx) // go 1.17

	//servername is now available

	log.Println("https connection for:", domain)

	rconn, err := redisPool.GetContext(ctx)
	if err != nil {
		log.Println("GetContext", err)
		return
	}
	defer rconn.Close()

	//we dont bother looking for the lock
	//keyx := "domain:" + domain + ":lock"

	key := "domain:" + domain + ":addrport"
	addrport, err := redigo.String(rconn.Do("get", key))
	if err != nil {
		log.Println("redigo.String(rconn.Do", err)
		return
	}

	err = in.SetReadDeadline(time.Time{})
	if err != nil {
		log.Println("SetReadDeadline", err)
		return
	}

	var d net.Dialer

	// this is the last time we pass ctx on,
	// so when it times-out, it won't affect later operations
	conn2, err := d.DialContext(ctx, "tcp", addrport)
	if err != nil {
		log.Printf("Failed to dial: %v", err)
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
