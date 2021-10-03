# Cluster design



## Exploration

We want to be able to offer instant-up, SFUs for experimentation and streaming.
That support both WebRTC-HTTPS signalling and FTL ingest.

### Explore / Specific problems

There are many, lol.
- Single hostname for service: deadsfu.com
- Single hostname for FTL setup: ftl.deadsfu.com
- Wide-area spread SFUs and servers. (no Redis, or proxied)
- Both FTL and HTTPS based ingress
- Redis is not easily implemented for 
- Want to consider DDOS protectability 


### Explore / SFU to Proxy Signalling
- Redis is nice and easy, but not well suited for wide-area systems. (traditionally in-the-clear auth passwd)
- Redis 6 can do TLS, so this is an option
- The other option is to write an https-proto for SFU registration

### Explore / Redis vs HTTPs registration to proxy
1. Redis must be 2x-4x quicker to implement than a by-hand HTTPS registration protocol
2. We will still need Redis anyway (or similar) if we want to community between multiple front-line proxys
3. For these 2x reasons, it makes sense to just use Redis for both front-line proxy communication AND SFU to proxy communication



### thought experiment, what if we didn't support FTL, just HTTPS?

- no ftl proxy required
- but! still have these issues:
- still won't have a single IP per SFU, but could use port-based URL to avoid any or _ongoing_ https-proxying, can simply do a 307-redirect rather than _ongoing_ sni-proxying
- Actually, for a wildcard cert, we could do an https decode, and 307 redirect.
- But for non-wildcard certs, we would have to do an SNI proxy, and the target SFU would be required to do a 307 redirect.
- But!, remember the issue for non-wildcard certs is the letsencrypt load on the TLD. This presents a SPOF for DDOS, or issue for heavy used services. (what happens if LE hits rate limits? :( )
- Also, for wildcard-certs, while the proxy could do a decode and do a 307, it could also do an SNI proxy and let the target SFU do the decode and 307 redirect, which would allow for later doing non-wildcard certs.



## Decisions

### SFU certificate storage
- uses Redis when in cluster-mode

### FTL proxying
- uses Redis to learn mapping of channelid to IP/port for RTP

### SFU registration
- use Redis with TLS (ver 6+)

### Redis TLS .crt/.key/ca.crt aquisition
- Redis TLS is bootstrapped via HTTPS to get the 3s files needed for TLS
- A single URL with bearer token '...?access_token=xxx' is used by Sfus to aquire the three files. (a zip file)
- *This URL is stored in an env variable, and _not_ passed via command-line args*
- This URL (not 3x files) could/can be stored as a secret when using Docker Swarm: 
- https://docs.docker.com/engine/swarm/secrets/


### HTTPS proxying
- The proxy does an SNI proxy to the SFU
- The SFU does an 307 redirect to it's particular Hostname/PORT combination. (checking IP==hostname?)