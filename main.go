package main

import (
	"bufio"
	"context"
	"encoding/json"

	"errors"

	"log"
	"net"

	"sync"
	"time"

	"github.com/spf13/pflag"
	"github.com/x186k/ftlserver"
	"golang.org/x/sys/unix"
)

type SfuInfo struct {
	udptx    *net.UDPConn
	Hmackey  string
	nrefused int
}

func (x *SfuInfo) GetHmackey(inf *log.Logger, dbg *log.Logger) string {
	return x.Hmackey
}
func (x *SfuInfo) TakePacket(inf *log.Logger, dbg *log.Logger, pkt []byte) bool {
	var err error
	_, err = x.udptx.Write(pkt)
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

// must be same as in deadsfu
type FtlRegistrationInfo struct {
	Hmackey          string
	Channelid        string
	Port             int
	ObsProxyPassword string
}

var endpointMap = make(map[string]*SfuInfo)
var endpointMapMutex sync.Mutex

var obsProxyPassword = pflag.StringP("obs-proxy-password", "s", "", "password to register with ftl/obs proxy. required for proxy use")

func main() {

	log.SetFlags(log.LUTC | log.LstdFlags | log.Lshortfile)

	pflag.Parse()
	if *obsProxyPassword == "" {
		pflag.Usage()
		return
	}

	config := &net.ListenConfig{}
	ln, err := config.Listen(context.Background(), "tcp", ":8084")
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
			ftlserver.NewTcpSession(l, l, tcpconn, nothmacCmd, findserver)
		}()
	}
}

func findserver(inf *log.Logger, dbg *log.Logger, requestChanid string) (ftlserver.FtlServer, bool) {
	endpointMapMutex.Lock()
	sfuinfo, ok := endpointMap[requestChanid]
	endpointMapMutex.Unlock()
	return sfuinfo, ok
}

func nothmacCmd(inf *log.Logger, dbg *log.Logger, tokens []string, t *net.TCPConn, s2 *bufio.Scanner) (retbool bool) {

	if len(tokens) < 2 || tokens[0] != "REGISTER" {
		inf.Println("Invalid command presented on FTL socket:", tokens[0])
		return
	}

	reginfo := &FtlRegistrationInfo{}

	err := json.Unmarshal([]byte(tokens[1]), reginfo)
	if err != nil {
		log.Println("json.Unmarshal", err)
		return false
	}

	log.Println(reginfo)

	if reginfo.ObsProxyPassword != *obsProxyPassword {
		log.Println("invalid obsProxyPassword token", err)
		return false
	}

	endpointMapMutex.Lock()
	_, ok := endpointMap[reginfo.Channelid]
	endpointMapMutex.Unlock()
	if ok {
		log.Println("hangup: duplicate sfu registration for channelid", reginfo.Channelid)
		return
	}

	log.Println("sfu registered chanid/", reginfo.Channelid)

	sfuaddr := t.LocalAddr().(*net.TCPAddr)
	sfuaddr2 := &net.UDPAddr{
		IP:   sfuaddr.IP,
		Port: reginfo.Port,
		Zone: "",
	}

	a := &SfuInfo{
		udptx:   &net.UDPConn{},
		Hmackey: reginfo.Hmackey,
	}

	// rtp to sfu socket
	a.udptx, err = net.DialUDP("udp", nil, sfuaddr2)
	if err != nil {
		log.Println("DialUDP", err)
		return
	}
	defer a.udptx.Close()

	// no timeout
	err = t.SetReadDeadline(time.Time{})
	if err != nil {
		log.Println("SetReadDeadline: ", err)
		return
	}

	endpointMapMutex.Lock()
	endpointMap[reginfo.Channelid] = a
	endpointMapMutex.Unlock()

	b := make([]byte, 1)
	// should block until SFU disconnects
	// when this returns, it is our indication the SFU is done/gone/dead
	_, err = t.Read(b)
	log.Println("sfu dead/gone: read returned", err)

	endpointMapMutex.Lock()
	delete(endpointMap, reginfo.Channelid)
	endpointMapMutex.Unlock()

	return true //okay
}
