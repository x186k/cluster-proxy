

# important things to know about FTL/OBS

FTL port is hardcoded to 8084 in ftl-sdk
https://github.com/microsoft/ftl-sdk/blob/d0c8469f66806b5ea738d607f7d2b000af8b1129/libftl/handshake.c#L53

There is an 'auto' mode which is covered a little in: notes/ftl-auto-ingest.md,
but it is unusable in vanilla OBS due to hardcoded *.mixer.com path.
It uses curl in C to get a list of hostnames (passing channelid in url), and
finds/uses the lowest latency ftl server.
*It is unusable in current-vanilla OBS (10/21)*

Channelid cannot be used to do SNI-style transparent proxying, because of the way the challenge works:
Server:gives random-bytes client:gives chanid+chal-response.
Because of this fact, to do FTL proxying, you must have a trusted, not an untrusted FTL proxy, unlike how
HTTPS SNI proxys may work.

