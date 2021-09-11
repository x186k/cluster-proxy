package main

import (
	"bufio"
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
	tosfu   *net.UDPConn
	userid  string
	hmackey []byte
}

var endpointMap = make(map[string]*SfuInfo)
var endpointMapMutex sync.Mutex

func httpError(w http.ResponseWriter, err error) {
	_, fileName, fileLine, _ := runtime.Caller(1)
	tt := time.Now().Format(time.RFC3339)
	m := fmt.Sprintf("httperr %v %v %v", filepath.Base(fileName), fileLine, err)
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
	mux.HandleFunc(*registerUrl, func(rw http.ResponseWriter, r *http.Request) {
		var err error

		if r.PostFormValue("ping") != "" {
			_, _ = rw.Write([]byte("OK"))
			return
		}

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

		hostport := host + ":" + port
		log.Printf("sfu registered for user/%v at %v", a.userid, hostport)

		sfuaddr, err := net.ResolveUDPAddr("udp", hostport)
		if err != nil {
			httpError(rw, err)
			return
		}

		a.tosfu, err = net.DialUDP("udp", nil, sfuaddr)
		if err != nil {
			httpError(rw, err)
			return
		}

		endpointMapMutex.Lock()
		endpointMap[a.userid] = &a
		endpointMapMutex.Unlock()

		_, _ = rw.Write([]byte("OK"))
	})

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

		go func() {
			defer c.Close()
			ftlSession(c)
		}()
	}
}

func ftlSession(tcpconn net.Conn) {
	var err error

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

	z := make(chan bool)

	go func() {
		select {
		case <-time.NewTimer(5 * time.Second).C:
			tcpconn.Close()
			log.Println("ftl: timeout waiting for handshake")
			return
		case <-z:
			log.Println("ftl: handshake complete before timeout")
		}
	}()

	kvmap := make(map[string]string)

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
		//fmt.Println(">", l)
	}

	close(z) //stop key read timeout
	log.Println("ftl: got k/v set")

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
	udpconn, err := net.ListenUDP("udp", &x)
	if err != nil {
		log.Println(err)
		return
	}
	defer udpconn.Close()

	laddr := udpconn.LocalAddr().(*net.UDPAddr)

	log.Println("bound inbound udp on", laddr)

	fmt.Fprintf(tcpconn, "200. Use UDP port %d\n", laddr.Port)

	pingchan := make(chan bool)
	disconnectCh := make(chan bool)

	// PING goroutine
	// this will silently go away when the socket gets closed
	go func() {
		log.Println("ftl: ping responder running")
		for scanner.Scan() {
			l := scanner.Text()

			// XXX PING is sometimes followed by streamkey-id
			// but we don't validate it.
			// it is checked for Connect message
			if strings.HasPrefix(l, "PING ") {
				log.Println("ftl: ping!")
				fmt.Fprintf(tcpconn, "201\n")

				pingchan <- true
			} else if l == "" {
				//ignore blank
			} else if l == "DISCONNECT" {
				disconnectCh <- true
			} else {
				// unexpected
				log.Println("ftl: unexpected msg:", l)
			}
		}
		//silently finish goroutine on scanner error or socket close
	}()

	lastping := time.Now()
	lastudp := time.Now()
	buf := make([]byte, 2000)

	connected := false
	for {

		select {
		case m, more := <-pingchan:
			if m && more {
				lastping = time.Now()
			}
		case <-disconnectCh:
			log.Println("OBS/FTL: SERVER DISCONNECTED")
			return
		default:
		}
		if time.Since(lastping) > time.Second*11 {
			log.Println("OBS/FTL: PINGING TIMEOUT, CLOSING")
			return
		}
		if time.Since(lastudp) > time.Second*3/2 { // 1.5 second
			log.Println("OBS/FTL: UDP/RX TIMEOUT, CLOSING")
			return
		}

		err = udpconn.SetReadDeadline(time.Now().Add(time.Second))
		if err != nil {
			log.Println(err)
			return
		}

		n, readaddr, err := udpconn.ReadFromUDP(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		} else if err != nil {
			log.Println(fmt.Errorf("OBS/FTL: UDP FAIL, CLOSING: %w", err))
			return
		}

		//this increases security,
		// and performance too, per this: https://stackoverflow.com/a/51296247/86375
		//
		if !connected {
			connected = true

			err := udpconn.Close()
			if err != nil {
				log.Println(err)
				return
			}
			//XXX there may be a 1 in 1e6 race here

			udpconn, err = net.DialUDP("udp", laddr, readaddr)
			if err != nil {
				log.Println(err)
				return
			}
		}

		lastudp = time.Now()

		if n < 12 {
			continue
		}

		// we could have a single udp forwarder or many
		// the way I see it is, that
		// having many makes tcp session management easier
		//udp timeouts become easy to propagate up the stack
		// invoking defers etc for cleanup
		// hopefully simpler, more robust design

		_, err = sfuinfo.tosfu.Write(buf[:n])
		if err != nil {
			if errors.Is(err, unix.ECONNREFUSED) { // or windows.WSAECONNRESET
				log.Printf("sfu %s %s %s not receiving, marking dead",
					sfuinfo.userid,
					sfuinfo.tosfu.LocalAddr().String(),
					sfuinfo.tosfu.RemoteAddr().String(),
				)
				continue
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
