package main

import (
	"fmt"
	"os"

	"errors"

	"log"
	"net"

	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/spf13/pflag"
	"github.com/x186k/ftlserver"
	"golang.org/x/sys/unix"
)

type FtlBackend struct {
	udpout   *net.UDPConn
	nrefused int
}

func newRedisPool() *redis.Pool {
	return &redis.Pool{
		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,
		// Dial or DialContext must be set. When both are set, DialContext takes precedence over Dial.
		Dial: func() (redis.Conn, error) { return newRedisConn() },
	}
}

var pool *redis.Pool

func newRedisConn() (redis.Conn, error) {
	var err error
	url := os.Getenv("REDIS_URL")
	if url == "" {
		return nil, fmt.Errorf("REDIS_URL must be set for cluster mode")
	}
	conn, err := redis.DialURL(url)
	if err != nil {
		return nil, fmt.Errorf("redis.DialURL, %w", err)
	}
	return conn, nil
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

var enableFtlProxy = pflag.Bool("ftl", true, "enable ftl proxy")
var enableTlsProxy = pflag.Bool("tls", true, "enable tls proxy")

const logflag = log.LUTC | log.LstdFlags | log.Lshortfile

var dbg = log.New(os.Stdout, "D", logflag)

func main() {

	dbg.Println("dbg")
	log.SetFlags(logflag)

	pool = newRedisPool()

	pflag.Parse()

	if *enableFtlProxy {
		go func() {
			ftlProxy()
		}()
	}

	if *enableTlsProxy {
		go func() {
			tcpSniTlsProxy()
		}()
	}

	select {}

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

func findserver(inf *log.Logger, dbg *log.Logger, requestChanid string) (ftlserver.FtlServer, string) {

	rc := pool.Get()
	defer rc.Close()
	rkey := "user:" + requestChanid + ":ftl"
	mm, err := redis.StringMap(rc.Do("hgetall", rkey))
	if err != nil {
		inf.Println("redis.ScanSlice", err)
		return nil, ""
	}

	hmackey, ok := mm["hmackey"]
	if !ok || hmackey == "" {
		inf.Println("userid/chanid not registered", requestChanid)
		return nil, ""
	}

	udpaddrstr, ok := mm["addr.port"]
	if !ok || udpaddrstr == "" {
		inf.Println("missing ftl.addr.port for:", requestChanid)
		return nil, ""
	}

	addr, err := net.ResolveUDPAddr("udp", udpaddrstr)
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
