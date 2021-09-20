package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/caddyserver/certmagic"
)

func tcpSniTlsProxy() {

	certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(name string) (err error) {

			if name != "kego.com" {
				err = fmt.Errorf("domain not available")
			}
			log.Printf("domain %s decision: ",err)
			return err
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Hello, HTTPS visitor!")
	})

	err := certmagic.HTTPS([]string{}, nil)
	if err != nil {
		log.Fatal(err)
	}

}
