package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
)

type Endpoint struct {
	hmackey    string
	sfuFtlAddr *net.UDPAddr
}

var endpointMap = make(map[string]*Endpoint)
var endpointMapMutex sync.Mutex

func checkFatal(err error) {
	if err != nil {
		_, fileName, fileLine, _ := runtime.Caller(1)
		log.Fatalf("FATAL %s:%d %v", filepath.Base(fileName), fileLine, err)
	}
}

func httpError(w http.ResponseWriter, err error) {
	_, fileName, fileLine, _ := runtime.Caller(1)
	m := fmt.Sprintf("httperr %s:%d %v", filepath.Base(fileName), fileLine, err)
	//m := time.Now().Format(time.RFC3339) + " :: " + err.Error()
	log.Println(m)
	http.Error(w, m, http.StatusInternalServerError)
}

var httpAddrPort = pflag.String("http", ":9999", "http addr:port")

var xlog = log.New(os.Stderr, "XX", log.Lshortfile|log.LUTC|log.LstdFlags|log.Lmsgprefix)

func main() {

	pflag.Parse()
	if *httpAddrPort == "" {
		checkFatal(fmt.Errorf("--domain not set, fatal"))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(rw http.ResponseWriter, r *http.Request) {
		var err error

		streamkey := r.PostFormValue("streamkey")
		split := strings.Split(streamkey, "-")
		if len(split) != 2 {
			httpError(rw, fmt.Errorf("Invalid stream key, valid example format: 123-abc"))
			return
		}
		chanid := split[0]
		hmackey := split[1]

		port := r.PostFormValue("port")
		if port == "" {
			httpError(rw, fmt.Errorf("port not present in form"))
			return
		}

		portint, err := strconv.Atoi(port)
		if err != nil {
			httpError(rw, err)
			return
		}

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			httpError(rw, err)
			return
		}

		sfuip := net.ParseIP(host)
		if sfuip == nil {
			httpError(rw, fmt.Errorf("bad ip %s", host))
			return
		}

		ep := &Endpoint{}

		ep.hmackey = hmackey
		ep.sfuFtlAddr.IP = sfuip
		ep.sfuFtlAddr.Port = portint

		endpointMapMutex.Lock()
		_, found := endpointMap[chanid]
		endpointMap[chanid] = ep
		endpointMapMutex.Unlock()

		log.Printf("chanid:%s keylen:%d, from sfu at %s, overwrite:%v", chanid, len(ep.hmackey), r.RemoteAddr, found)

		_, _ = rw.Write([]byte("OK"))
	})

	log.Print("starting listenAndServe() on ", *httpAddrPort)

	go func() {

		err := http.ListenAndServe(*httpAddrPort, mux)

		checkFatal(err)
	}()

	go func() {
		ftlListener()
	}()

	select {}

}

func ftlListener() {
	config := &net.ListenConfig{}
	ln, err := config.Listen(context.Background(), "tcp", ":8084")
	checkFatal(err)
	defer ln.Close()

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Print(fmt.Errorf("ln.accept fail: %w", err))
			time.Sleep(time.Second * 10)
		}

		go func() {
			defer c.Close()

			err := ftlSession(c)
			if err != nil {
				log.Println(err.Error())
			}
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
	_, err = rand.Read(message)
	if err != nil {
		return fmt.Errorf("rand.Read failed %w", err)
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
	hexval := l[len(connectMsg):]
	client_hash, err := hex.DecodeString(hexval)
	if err != nil {
		return fmt.Errorf("bad data in connect user:%s data:%s", userid, hexval)
	}

	var ep *Endpoint
	endpointMapMutex.Lock()
	ep, ok := endpointMap[userid]
	endpointMapMutex.Unlock()
	if !ok {
		return fmt.Errorf("Non existent userid presented %s", userid)
	}

	good := ValidMAC([]byte(ep.hmackey), message, client_hash)

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

	// we cannot do this
	// net.DialUDP("udp",nil,)
	// cause we don't know the remote port,
	// we can do it in the read loop on the first packet.

	// open firewall hole
	// we don't know the source host:port, so we CANNOT send
	// (well, we don't know the port)
	// a packet to open a firewall hole.
	// this means port 8084 must be forwarded/open to udp traffic on
	// the firewall
	//udpconn.WriteToUDP()

	pingchan := make(chan bool)
	disconnectCh := make(chan bool)

	// PING goroutine
	// this will silently go away when the socket gets closed

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

	return scanner.Err()

}

func ValidMAC(key, message, messageMAC []byte) bool {
	mac := hmac.New(sha512.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

type SfuInfo struct {
	sfuaddr *net.UDPAddr
	//badrtp  int
	lastrx  time.Time
	dead    bool
}

func udphandler() {

	mm := make(map[string]*SfuInfo)

	pc, err := net.ListenPacket("udp", ":8084")
	checkFatal(err)

	udp8084 := pc.(*net.UDPConn)

	//XXX consider use of rtp.Packet pool
	//println(999,buf[1],p.Header.PayloadType)
	// default:
	// 	checkFatal(fmt.Errorf("bad RTP payload from FTL: %d", p.Header.PayloadType))

	buf := make([]byte, 2000)

	for {

		n, srcaddr, err := udp8084.ReadFromUDP(buf)
		if err != nil {
			// sad but fatal, crash everyone
			checkFatal(fmt.Errorf(".ReadFromUDP err %w", err))
		}

		key := srcaddr.Network()

		sfuinfo, found := mm[key]

		if !found {
			//look to see if we can find addr:port=0
			addrport0 := net.UDPAddr{IP: srcaddr.IP, Port: 0, Zone: srcaddr.Zone}
			sfuinfo, found = mm[addrport0.Network()]

			if !found {
				log.Printf("Unexpected pkt from:%s, routing to /dev/null", srcaddr.String())
				mm[key] = &SfuInfo{} // no dest addr
			} else {
				log.Printf("First pkt from:%s, saving routing to %s", srcaddr.String(), key)
				delete(mm, addrport0.Network())
				mm[key] = sfuinfo
			}

		} else if found {
			//sfuinfo.lastrx = time.Now()
			//sfuinfo.nujrx++

			if n < 12 {
				//sfuinfo.badrtp++
				continue
			}

			if sfuinfo.dead {
				continue
			}

			_, err = udp8084.WriteTo(buf[:n], sfuinfo.sfuaddr)
			if err != nil {
				if errors.Is(err, unix.ECONNREFUSED) { // or windows.WSAECONNRESET
					log.Printf("sfu %s not receiving, marking dead", srcaddr.String())
					sfuinfo.dead = true
					continue
				}
			}
		}
	}
}
