package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/spf13/pflag"
)

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
	m := fmt.Sprintf("httperr %s:%d %v", filepath.Base(fileName), fileLine, err)
	//m := time.Now().Format(time.RFC3339) + " :: " + err.Error()
	log.Println(m)
	http.Error(w, m, http.StatusInternalServerError)
}

func checkFreeze(err error) {
	if err != nil {
		log.SetFlags(log.Flags() | log.Lshortfile)
		log.Printf("FATAL %v", err) // log.Fatalf calls os.Exit(1)
		select {}                   //freeze
	}
}

var udpconnout net.PacketConn

var domain = pflag.String("domain", "", "https domain name")

func main() {
	var err error

	udpconnout, err = net.ListenPacket("udp", ":0")
	checkFatal(err)

	pflag.Parse()
	if *domain == "" {
		checkFatal(fmt.Errorf("--domain not set, fatal"))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/register-sfu", func(rw http.ResponseWriter, r *http.Request) {
		buf, err := ioutil.ReadAll(r.Body)
		if err != nil {
			httpError(rw, err)
			return
		}
		ep := new(Endpoint)
		err = json.Unmarshal(buf, &ep)
		if err != nil {
			httpError(rw, err)
			return
		}

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			httpError(rw, err)
			return
		}

		xip := net.ParseIP(host)
		if xip == nil {
			httpError(rw, fmt.Errorf("bad ip %s", host))
			return
		}

		ep.ip = xip
		endpointMapMutex.Lock()
		endpointMap[ep.key] = ep
		endpointMapMutex.Unlock()
	})

	log.Print("starting certmagic listenAndServe() on:", *domain)

	go func() {
		err = certmagic.HTTPS([]string{*domain}, mux)
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

type Endpoint struct {
	ip  net.IP
	key string
}

var endpointMap = make(map[string]*Endpoint)
var endpointMapMutex sync.Mutex

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
	_, err = rand.Read(message)
	// fatal, system has issues
	checkFreeze(err)

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

	var ep *Endpoint
	endpointMapMutex.Lock()
	ep, ok := endpointMap[userid]
	endpointMapMutex.Unlock()
	if !ok {
		return fmt.Errorf("Non existent userid presented %s", userid)
	}

	good := ValidMAC([]byte(ep.key), message, client_hash)

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

	fmt.Fprintf(tcpconn, "200. Use UDP port 8084\n")

	addr, err := net.ResolveUDPAddr("udp4", ":8084")
	if err != nil {
		return err
	}

	// we cannot this
	// net.DialUDP("udp",nil,)
	// cause we don't know the remote port,
	// we can do it in the read loop on the first packet.

	udpconn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}
	defer udpconn.Close()

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

	//XXX consider use of rtp.Packet pool
	//println(999,buf[1],p.Header.PayloadType)
	// default:
	// 	checkFatal(fmt.Errorf("bad RTP payload from FTL: %d", p.Header.PayloadType))

	lastping := time.Now()
	lastudp := time.Now()
	buf := make([]byte, 2000)

	dst := &net.UDPAddr{
		IP:   ep.ip,
		Port: 8084,
		Zone: "",
	}

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

		//this increases security
		if !connected {
			connected = true

			udpconn.Close()
			addr, err := net.ResolveUDPAddr("udp4", ":8084")
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

		_, err = udpconnout.WriteTo(buf[:n], dst)
		if err != nil {
			return err
		}
	}

}

func ValidMAC(key, message, messageMAC []byte) bool {
	mac := hmac.New(sha512.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
