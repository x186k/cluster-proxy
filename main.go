package main

import (
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

const logflag = log.LUTC | log.LstdFlags | log.Lshortfile

var dbg = log.New(os.Stdout, "D", logflag)

func checkFatal(err error) {
	if err != nil {
		_, fileName, fileLine, _ := runtime.Caller(1)
		log.Fatalf("FATAL %s:%d %v", filepath.Base(fileName), fileLine, err)
	}
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

	newRedisPoolFiles()

	checkRedis()

	pflag.Parse()

	go ftlProxy()

	go httpsProxy()

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
