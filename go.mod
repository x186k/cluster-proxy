module github.com/x186k/ftl-proxy

go 1.17

require github.com/spf13/pflag v1.0.5

require (
	github.com/x186k/ftlserver v0.0.0-20210915032410-6c9799c55b19
	golang.org/x/sys v0.0.0-20210910150752-751e447fb3d0
)

replace github.com/x186k/ftlserver => ../ftlserver
