package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/hex"

	"errors"
	"fmt"

	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
)

type SfuInfo struct {
	udptx   *net.UDPConn
	userid  string
	hmackey []byte
}

var endpointMap = make(map[string]*SfuInfo)
var endpointMapMutex sync.Mutex

func httpError(w http.ResponseWriter, err error) {
	_, fileName, fileLine, _ := runtime.Caller(1)
	tt := time.Now().Format(time.RFC3339)
	m := fmt.Sprintf("ftl-proxy: httperr %v %v %v", filepath.Base(fileName), fileLine, err)
	log.Print(tt)
	log.Print(m)
	http.Error(w, m+" "+tt, http.StatusInternalServerError)
}

var httphostport = pflag.String("http", "", "http addr:port, addr may be blank, ie: ':7777'")
var registerUrl = pflag.String("url", "/", "at what url to accept SFU registrations")

func main() {
	var err error

	log.SetFlags(log.LUTC | log.LstdFlags | log.Lshortfile)

	pflag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc(*registerUrl, registrationHandler)

	log.Print("starting http listenAndServe() on:", *httphostport, *registerUrl)

	go func() {
		err = http.ListenAndServe(*httphostport, mux)
		if err != nil {
			log.Fatalln(err)
		}
	}()

	go func() {
		ftlListener()
	}()

	select {}

}

func registrationHandler(rw http.ResponseWriter, r *http.Request) {
	var err error

	streamkey := r.PostFormValue("streamkey")
	split := strings.Split(streamkey, "-")
	if len(split) != 2 {
		httpError(rw, fmt.Errorf("Invalid stream key, valid example format: 123-abc"))
		return
	}

	a := SfuInfo{}

	a.userid = split[0]
	a.hmackey = []byte(split[1])

	port := r.PostFormValue("port")
	if port == "" {
		httpError(rw, fmt.Errorf("port not present/valid in form"))
		return
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		httpError(rw, err)
		return
	}

	endpointMapMutex.Lock()
	check, ok := endpointMap[a.userid]
	endpointMapMutex.Unlock()

	if ok {
		if bytes.Equal(check.hmackey, a.hmackey) && check.userid == a.userid {
			//log.Println("duplicate sfu registration")
			_, _ = rw.Write([]byte("OK"))
			return
		}
	}

	hostport := host + ":" + port
	log.Printf("sfu registered for user/%v at %v", a.userid, hostport)

	sfuaddr, err := net.ResolveUDPAddr("udp", hostport)
	if err != nil {
		httpError(rw, err)
		return
	}

	a.udptx, err = net.DialUDP("udp", nil, sfuaddr)
	if err != nil {
		httpError(rw, err)
		return
	}

	endpointMapMutex.Lock()
	endpointMap[a.userid] = &a
	endpointMapMutex.Unlock()

	_, _ = rw.Write([]byte("OK"))
}

func ftlListener() {
	config := &net.ListenConfig{}
	ln, err := config.Listen(context.Background(), "tcp4", ":8084")
	if err != nil {
		log.Fatalln(err)
	}
	defer ln.Close()

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Println(err)
			time.Sleep(time.Second * 10)
		}

		log.Println("socket accepted")

		go func() {
			defer c.Close()
			ftlSession(c)
		}()
	}
}

func ftlSession(tcpconn net.Conn) {
	var err error

	err = tcpconn.SetReadDeadline(time.Now().Add(10 * time.Second)) //ping period is 5sec
	if err != nil {
		log.Println("ping GR done: ", err) //nil err okay
		return
	}

	log.Println("OBS/FTL GOT TCP SOCKET CONNECTION")

	scanner := bufio.NewScanner(tcpconn)

	var l string

	if !scanner.Scan() {
		reportScannerError(scanner)
		return
	}
	if l = scanner.Text(); l != "HMAC" {
		log.Println("ftl/no hmac:", l)
		return
	}
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

	good := ValidMAC([]byte(sfuinfo.hmackey), message, client_hash)

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
