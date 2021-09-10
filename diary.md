

# 9/10/21
had a little internal debate about a mondo-single-process proxy vs a process-per ftl session.

a process-per approach has some benefits, as process-dumping bugs only terminate one session

but!

sfu's must register the userid/hmackey with <all> proxys, and if there is a single proxy,
it is quite simple via http, but if there is multiple proxys, then we really need
something like redis. to which I say yuck.

so just write a single process mondo proxy, and well, get it right,
cause termination will kill all ftl sessions.
:)

# 9/10/21

Decision: switch from mondo-udp-forwarder to forwarder-per-session.
Why: Because the implementation logic is simpler likely more robust.

