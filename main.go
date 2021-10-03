package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/url"

	"os"
	"path/filepath"
	"runtime"

	"errors"

	"log"
	"net"

	"time"

	redigo "github.com/gomodule/redigo/redis"

	"github.com/spf13/pflag"
	"github.com/x186k/ftlserver"
	"golang.org/x/sys/unix"
)

type FtlBackend struct {
	udpout   *net.UDPConn
	nrefused int
}

var redisPool *redigo.Pool

const logflag = log.LUTC | log.LstdFlags | log.Lshortfile

var dbg = log.New(os.Stdout, "D", logflag)

func checkFatal(err error) {
	if err != nil {
		_, fileName, fileLine, _ := runtime.Caller(1)
		log.Fatalf("FATAL %s:%d %v", filepath.Base(fileName), fileLine, err)
	}
}
func newRedisPool() {

	rurl := os.Getenv("REDIS_URL")
	if rurl == "" {
		checkFatal(fmt.Errorf("REDIS_URL must be set for cluster mode"))
	}

	var do = make([]redigo.DialOption, 0)

	uu, err := url.Parse(rurl)
	checkFatal(err)
	_=uu

	redisTls := true
	if redisTls {
		cert, err := tls.LoadX509KeyPair("tests/tls/redis.crt", "tests/tls/redis.key")
		checkFatal(err)

		caCert, err := ioutil.ReadFile("tests/tls/ca.crt")
		checkFatal(err)

		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caCert)

		//println(99,uu.Hostname())

		tlsconf := &tls.Config{
			ServerName:   uu.Hostname(),
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			InsecureSkipVerify: false,
		}

		//do = append(do, redigo.DialUseTLS(true)) //overwritten by DialUrlContext!
		//do = append(do, redigo.DialTLSSkipVerify(true)) // ignored when providing tlsconf
		do = append(do, redigo.DialTLSConfig(tlsconf))
	
		
	}

	redisPool = &redigo.Pool{
		MaxIdle:     3,
		IdleTimeout: 5 * time.Second,
		// Dial or DialContext must be set. When both are set, DialContext takes precedence over Dial.
		DialContext: func(ctx context.Context) (redigo.Conn, error) {
			//return redigo.DialContext(ctx, "tcp", uu.Hostname()+":6379", do...)
			return redigo.DialURLContext(ctx, rurl, do...)
		},
	}

	// threadsafe
	//redisLocker = redislock.New(redislockx.NewRedisLockClient(redisPool))
}

func (x *FtlBackend) TakePacket(inf *log.Logger, dbg *log.Logger, pkt []byte) bool {
	var err error
	_, err = x.udpout.Write(pkt)
	if err != nil {
		if errors.Is(err, unix.ECONNREFUSED) { // or windows.WSAECONNRESET
			x.nrefused++
			if x.nrefused > 10 {
				inf.Println("ending session: too many ECONNREFUSED")
				return false
			}
		} else {
			inf.Println("error forwarding packet, closing, err:", err)
			return false
		}
	}
	return true //okay
}

func main() {

	dbg.Println("dbg")
	log.SetFlags(logflag)

	newRedisPool()

	checkRedis()

	pflag.Parse()

	go ftlProxy()

	go httpsProxy()

	select {}

}

func checkRedis() {
	rconn := redisPool.Get()
	defer rconn.Close()

	pong, err := redigo.String(rconn.Do("ping"))
	if err != nil {
		log.Fatalln("ping fail", err)
	}

	if pong != "PONG" {
		log.Fatalln("redis fail, expect: PONG, got:", pong)
	}

	dbg.Println("redis ping is good!")
}

func ftlProxy() {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 8084})
	if err != nil {
		log.Fatalln(err)
	}
	defer ln.Close()

	for {
		log.Println("waiting for accept")

		netconn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			time.Sleep(time.Second * 10)
		}

		log.Println("socket accepted")

		tcpconn := netconn.(*net.TCPConn)

		go func() {
			defer netconn.Close()
			l := log.Default()
			ftlserver.NewTcpSession(l, l, tcpconn, findserver)
		}()
	}
	// unreachable code
	//return
}

func findserver(inf *log.Logger, dbg *log.Logger, chanidstr string) (ftlserver.FtlServer, string) {

	rconn := redisPool.Get()
	defer rconn.Close()

	key1 := "ftl:" + chanidstr + ":lock"
	key2 := "ftl:" + chanidstr + ":addrport"
	key3 := "ftl:" + chanidstr + ":hmackey"

	_, err := rconn.Do("get", key1)
	if err != nil {
		inf.Println(err)
		return nil, ""
	}

	addrport, err := redigo.String(rconn.Do("get", key2))
	if err != nil {
		inf.Println(err)
		return nil, ""
	}

	hmackey, err := redigo.String(rconn.Do("get", key3))
	if err != nil {
		inf.Println(err)
		return nil, ""
	}

	addr, err := net.ResolveUDPAddr("udp", addrport)
	if err != nil {
		inf.Println("net.ResolveUDPAddr", err)
		return nil, ""
	}

	//we make an individual connection to each SFU
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		inf.Println("net.Dialudp", err)
		return nil, ""
	}

	a := &FtlBackend{udpout: conn}

	return a, hmackey

}
