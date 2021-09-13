package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"

	"errors"
	"fmt"

	"log"
	"net"

	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
)

type SfuInfo struct {
	udptx     *net.UDPConn
	Channelid string
	Hmackey   []byte
}

var endpointMap = make(map[string]*SfuInfo)
var endpointMapMutex sync.Mutex

var secret = pflag.StringP("secret", "s", "", "required: secret password for sfu registration")

func main() {

	log.SetFlags(log.LUTC | log.LstdFlags | log.Lshortfile)

	pflag.Parse()
	if *secret == "" {
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
			tcpSession(tcpconn)
		}()
	}
}

func tcpSession(tcpconn *net.TCPConn) {
	var err error

	err = tcpconn.SetKeepAlive(true)
	if err != nil {
		log.Println("SetKeepAlive", err) //nil err okay
		return
	}

	err = tcpconn.SetKeepAlivePeriod(time.Second * 15)
	if err != nil {
		log.Println("SetKeepAlivePeriod", err) //nil err okay
		return
	}

	err = tcpconn.SetReadDeadline(time.Now().Add(10 * time.Second)) //ping period is 5sec
	if err != nil {
		log.Println("SetReadDeadline: ", err) //nil err okay
		return
	}

	log.Println("OBS/FTL GOT TCP SOCKET CONNECTION")

	scanner := bufio.NewScanner(tcpconn)

	if !scanner.Scan() {
		reportScannerError(scanner)
		return
	}
	line := scanner.Text()
	foo := strings.SplitN(line, " ", 2)

	switch foo[0] {
	case "HMAC":
		hmacHandler(tcpconn, scanner)
	case "REGISTER":
		registrationHandler(tcpconn, scanner, foo[1])
	default:
		log.Println("unknown 1st line:", line)
	}

}
func registrationHandler(tcpconn *net.TCPConn, scanner *bufio.Scanner, part2 string) {

	a := struct {
		SfuInfo
		Secret string
	}{}

	err := json.Unmarshal([]byte(part2), &a)
	if err != nil {
		log.Println("json.Unmarshal", err)
		return
	}

	if a.Secret != *secret {
		log.Println("invalid secret token", err)
		return
	}

	endpointMapMutex.Lock()
	_, ok := endpointMap[a.Channelid]
	endpointMapMutex.Unlock()

	if ok {
		log.Println("hangup: duplicate sfu registration for channelid", a.Channelid)
		return
	}

	log.Println("sfu registered chanid/", a.Channelid)

	sfuaddr := tcpconn.LocalAddr().(*net.TCPAddr)
	sfuaddr2 := &net.UDPAddr{
		IP:   sfuaddr.IP,
		Port: 8084,
		Zone: "",
	}

	// rtp to sfu socket
	a.udptx, err = net.DialUDP("udp", nil, sfuaddr2)
	if err != nil {
		log.Println("DialUDP", err)
		return
	}
	defer a.udptx.Close()

	endpointMapMutex.Lock()
	endpointMap[a.Channelid] = &a.SfuInfo
	endpointMapMutex.Unlock()

	b := make([]byte, 1)
	//should block until SFU disconnects
	// when this returns, it is our indication the SFU is done
	_, err = tcpconn.Read(b)
	log.Println("tcpconn", err)

	endpointMapMutex.Lock()
	delete(endpointMap, a.Channelid)
	endpointMapMutex.Unlock()
}

func hmacHandler(tcpconn net.Conn, scanner *bufio.Scanner) {
	var l string
	var err error

	log.Println("ftl: got hmac")

	if !scanner.Scan() {
		reportScannerError(scanner)
		return
	}
	if l = scanner.Text(); l != "" {
		log.Println("ftl/no blank after hmac:", l)
		return
	}
	log.Println("ftl: got hmac blank")

	numrand := 128
	message := make([]byte, numrand)
	_, err = crand.Read(message)
	if err != nil {
		log.Print(err)
		return
	}

	fmt.Fprintf(tcpconn, "200 %s\n", hex.EncodeToString(message))

	if !scanner.Scan() {
		reportScannerError(scanner)
		return
	}

	if l = scanner.Text(); !strings.HasPrefix(l, "CONNECT ") {
		log.Println("ftl/no connect:", l)
		return
	}
	log.Println("ftl: got connect")

	connectsplit := strings.Split(l, " ")
	if len(connectsplit) < 3 {
		log.Println("ftl: bad connect")
		return
	}

	userid := connectsplit[1]
	connectMsg := "CONNECT " + userid + " $"
	client_hash, err := hex.DecodeString(l[len(connectMsg):])
	if err != nil {
		log.Println(err)
		return
	}

	endpointMapMutex.Lock()
	sfuinfo, ok := endpointMap[userid]
	endpointMapMutex.Unlock()

	if !ok {
		log.Println("Non existent userid presented", userid)
		return
	}

	good := ValidMAC([]byte(sfuinfo.Hmackey), message, client_hash)

	log.Println("ftl: auth is okay:", good)

	if !good {
		log.Println("FTL authentication failed for", userid)
		return
	}

	fmt.Fprintf(tcpconn, "200\n")

	kvmap := make(map[string]string)

	err = tcpconn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		log.Println(err)
	}
	for scanner.Scan() {
		l = scanner.Text()
		if l == "." {
			break
		}
		if l != "" {
			split := strings.SplitN(l, ": ", 2)
			if len(split) == 2 {
				kvmap[split[0]] = split[1]
			} else {
				log.Println("ftl/bad format keyval section:", l)
				return
			}
		}
	}

	for k, v := range kvmap {
		log.Println("ftl: key/value", k, v)
	}

	keyvalsOK := true // todo
	//do a consistency check of the key vals
	if !keyvalsOK {
		log.Println("ftl/issue with k/v pairs")
		return
	}

	// net.DialUDP("udp",nil,), not yet, cause we don't know remote port
	x := net.UDPAddr{IP: nil, Port: 0, Zone: ""}
	udprx, err := net.ListenUDP("udp", &x)
	if err != nil {
		log.Println(err)
		return
	}
	defer udprx.Close()

	laddr := udprx.LocalAddr().(*net.UDPAddr)
	log.Println("bound inbound udp on", laddr)

	fmt.Fprintf(tcpconn, "200. Use UDP port %d\n", laddr.Port)

	// PING goroutine
	go func() {
		defer tcpconn.Close()
		defer udprx.Close()

		for {
			err = tcpconn.SetReadDeadline(time.Now().Add(7 * time.Second)) //ping period is 5sec
			if err != nil {
				log.Println("ping GR done: ", scanner.Err()) //nil err okay
				return
			}

			ok := scanner.Scan()
			if !ok {
				log.Println("ping GR done: ", scanner.Err()) //nil err okay
				return
			}

			l := scanner.Text()

			if strings.HasPrefix(l, "PING ") {
				// XXX PING is sometimes followed by streamkey-id
				// but we don't validate it.
				// it is checked for Connect message
				//log.Println("ftl: ping!")
				fmt.Fprintf(tcpconn, "201\n")
			} else if l == "" {
				//ignore blank
			} else if l == "DISCONNECT" {
				log.Println("disconnect, ping GR done")
				return
			} else {
				log.Println("ftl: unexpected msg:", l)
			}
		}
	}()

	buf := make([]byte, 2000)

	nrefused := 0

	for {
		err = udprx.SetReadDeadline(time.Now().Add(time.Second))
		if err != nil {
			log.Println(err)
			return
		}

		n, _, err := udprx.ReadFromUDP(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return
		} else if err != nil {
			log.Println(err)
			return
		}

		// not now: udprx, err = net.DialUDP("udp", laddr, readaddr)

		if n < 12 {
			continue
		}

		_, err = sfuinfo.udptx.Write(buf[:n])
		if err != nil {
			if errors.Is(err, unix.ECONNREFUSED) { // or windows.WSAECONNRESET
				nrefused++
				if nrefused > 10 {
					log.Println("ending session: too many ECONNREFUSED")
					return
				}
			}
		}
	}

}

func reportScannerError(scanner *bufio.Scanner) {
	err := scanner.Err()
	if err == nil {
		log.Println("EOF on OBS/FTL")
	} else {
		log.Println(err)
	}
}

func ValidMAC(key, message, messageMAC []byte) bool {
	mac := hmac.New(sha512.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
