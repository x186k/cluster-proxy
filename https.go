package main

// Some code Copyright (c) 2020 Andrew Ayer, under X11, MIT-advertising license

import (
	"log"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

func httpsProxy() {

	token := os.Getenv("CLOUDFLARE_TOKEN")
	if token == "" {
		log.Fatalln("env var CLOUDFLARE_TOKEN is not set")
	}

	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSProvider: &cloudflare.Provider{
			APIToken: token,
		},
	}

	url, err := url.Parse("http://localhost:999")
	if err != nil {
		log.Fatalln("url.parse", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(url)

	err = certmagic.HTTPS([]string{"*.deadsfu.com"}, proxy)
	log.Fatalln("certmagic.https", err)

}
