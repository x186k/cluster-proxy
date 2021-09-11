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

func checkFatal(err error) {
	if err != nil {
		_, fileName, fileLine, _ := runtime.Caller(1)
		log.Fatalf("FATAL %s:%d %v", filepath.Base(fileName), fileLine, err)
	}
}
func checkNotFatal(err error) {
	if err != nil {
		_, fileName, fileLine, _ := runtime.Caller(1)
		log.Printf("NOTFATAL %s:%d %v", filepath.Base(fileName), fileLine, err)
	}
}
func httpError(w http.ResponseWriter, err error) {
	_, fileName, fileLine, _ := runtime.Caller(1)
	tt := time.Now().Format(time.RFC3339)
	m := fmt.Sprintf("httperr %s %s %d %v", tt, filepath.Base(fileName), fileLine, err)
	log.Print(err)
	http.Error(w, m, http.StatusInternalServerError)
}

var httphostport = pflag.String("http", "", "http addr:port, addr may be blank, ie: ':7777'")

func main() {
	var err error

	log.SetFlags(log.Lshortfile | log.LUTC | log.LstdFlags | log.Lmsgprefix)

	pflag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(rw http.ResponseWriter, r *http.Request) {
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

		sfuaddr, err := net.ResolveUDPAddr("udp", host+":"+port)
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

	log.Print("starting http listenAndServe() on:", *httphostport)

	go func() {
		err = http.ListenAndServe(*httphostport, mux)
		checkFatal(err)
	}()

	go func() {
		ftlListener()
	}()

	select {}

}

func ftlListener() {
	config := &net.ListenConfig{}
	ln, err := config.Listen(context.Background(), "tcp4", ":8084")
	checkFatal(err)
	defer ln.Close()

	for {
		c, err := ln.Accept()
		if err != nil {
			checkNotFatal(err)
			time.Sleep(time.Second * 10)
		}

		go func() {
			defer c.Close()

			err := ftlSession(c)
			log.Println(err.Error())
		}()
	}
}

func ftlSession(tcpconn net.Conn) error {
	var err error

	log.Println("OBS/FTL GOT TCP SOCKET CONNECTION")

	scanner := bufio.NewScanner(tcpconn)

	var l string

	if !scanner.Scan() {
		err = scanner.Err()
		if err == nil {
			return fmt.Errorf("EOF on OBS/FTL")
		}
		return err
	}
	if l = scanner.Text(); l != "HMAC" {
		return fmt.Errorf("ftl/no hmac:%s", l)
	}
	log.Println("ftl: got hmac")

	if !scanner.Scan() {
		err = scanner.Err()
		if err == nil {
			return fmt.Errorf("EOF on OBS/FTL")
		}
		return err
	}
	if l = scanner.Text(); l != "" {
		err = fmt.Errorf("ftl/no blank after hmac:%s", l)
		return err
	}
	log.Println("ftl: got hmac blank")

	numrand := 128
	message := make([]byte, numrand)
	_, err = crand.Read(message)
	if err != nil {
		log.Print(err)
		return nil
	}

	fmt.Fprintf(tcpconn, "200 %s\n", hex.EncodeToString(message))

	if !scanner.Scan() {
		err = scanner.Err()
		if err == nil {
			return fmt.Errorf("EOF on OBS/FTL")
		}
		return err
	}

	if l = scanner.Text(); !strings.HasPrefix(l, "CONNECT ") {
		err = fmt.Errorf("ftl/no connect:%s", l)
		return err
	}
	log.Println("ftl: got connect")

	connectsplit := strings.Split(l, " ")
	if len(connectsplit) < 3 {
		err = fmt.Errorf("ftl: bad connect")
		return err
	}

	userid := connectsplit[1]
	connectMsg := "CONNECT " + userid + " $"
	client_hash, err := hex.DecodeString(l[len(connectMsg):])
	checkFatal(err)

	endpointMapMutex.Lock()
	sfuinfo, ok := endpointMap[userid]
	endpointMapMutex.Unlock()

	if !ok {
		return fmt.Errorf("Non existent userid presented %s", userid)
	}

	good := ValidMAC([]byte(sfuinfo.hmackey), message, client_hash)

	log.Println("ftl: auth is okay:", good)

	if !good {
		return fmt.Errorf("FTL authentication failed for %s", userid)
	}

	fmt.Fprintf(tcpconn, "200\n")

	z := make(chan bool)

	go func() {
		select {
		case <-time.NewTimer(5 * time.Second).C:
			tcpconn.Close()
			err = fmt.Errorf("ftl: timeout waiting for handshake")
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
				err = fmt.Errorf("ftl/bad format keyval section: %s", l)
				return err
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
		err = fmt.Errorf("ftl/issue with k/v pairs")
		return err
	}

	// net.DialUDP("udp",nil,), not yet, cause we don't know remote port
	x := net.UDPAddr{IP: nil, Port: 0, Zone: ""}
	udpconn, err := net.ListenUDP("udp", &x)
	if err != nil {
		return err
	}
	defer udpconn.Close()

	_, rxport, err := net.SplitHostPort(udpconn.LocalAddr().String())
	if err != nil {
		return err
	}

	fmt.Fprintf(tcpconn, "200. Use UDP port %s\n", rxport)

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
			return nil
		default:
		}
		if time.Since(lastping) > time.Second*11 {
			log.Println("OBS/FTL: PINGING TIMEOUT, CLOSING")
			return nil
		}
		if time.Since(lastudp) > time.Second*3/2 { // 1.5 second
			log.Println("OBS/FTL: UDP/RX TIMEOUT, CLOSING")
			return nil
		}

		err = udpconn.SetReadDeadline(time.Now().Add(time.Second))
		checkFatal(err)
		n, readaddr, err := udpconn.ReadFromUDP(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		} else if err != nil {
			log.Println(fmt.Errorf("OBS/FTL: UDP FAIL, CLOSING: %w", err))
			return nil
		}

		//this increases security,
		// and performance too, per this: https://stackoverflow.com/a/51296247/86375
		//
		if !connected {
			connected = true

			udpconn.Close()
			addr, err := net.ResolveUDPAddr("udp4", ":"+rxport)
			if err != nil {
				return err
			}

			udpconn, err = net.DialUDP("udp", addr, readaddr)
			if err != nil {
				return err
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

func ValidMAC(key, message, messageMAC []byte) bool {
	mac := hmac.New(sha512.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
