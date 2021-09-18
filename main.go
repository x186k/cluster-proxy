package main

import (
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

type SfuInfo struct {
	udpout   *net.UDPConn
	nrefused int
}

var redisconn redis.Conn

func connectRedis() {
	var err error
	url := os.Getenv("REDIS_URL")
	if url == "" {
		log.Fatalln("REDIS_URL must be set for cluster mode")
	}
	redisconn, err = redis.DialURL(url)
	if err != nil {
		log.Fatalln("redis.DialURL(url)", url, err)
	}
}

func (x *SfuInfo) TakePacket(inf *log.Logger, dbg *log.Logger, pkt []byte) bool {
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

	log.SetFlags(log.LUTC | log.LstdFlags | log.Lshortfile)

	connectRedis()

	pflag.Parse()

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
}

func findserver(inf *log.Logger, dbg *log.Logger, requestChanid string) (ftlserver.FtlServer, string) {

	rkey := "user:" + requestChanid
	mm, err := redis.StringMap(redisconn.Do("hgetall", rkey))
	if err != nil {
		inf.Println("redis.ScanSlice", err)
		return nil, ""
	}

	hmackey, ok := mm["ftl.hmackey"]
	if !ok || hmackey == "" {
		inf.Println("userid/chanid not registered", requestChanid)
		return nil, ""
	}

	udpaddrstr, ok := mm["ftl.addr.port"]
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

	a := &SfuInfo{udpout: conn}

	return a, hmackey

}
