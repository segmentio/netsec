# netsec [![CircleCI](https://circleci.com/gh/segmentio/netsec.svg?style=shield&circle-token=586dc5f2f8f249b7f85b0bc22fe18067a27e0a1f)](https://circleci.com/gh/segmentio/netsec) [![Go Report Card](https://goreportcard.com/badge/github.com/segmentio/netsec)](https://goreportcard.com/report/github.com/segmentio/netsec) [![GoDoc](https://godoc.org/github.com/segmentio/netsec?status.svg)](https://godoc.org/github.com/segmentio/netsec)
Home of code related to security of network systems.

## Motivation

As we grow as a product and a company we have increasing needs to build secure
network services. This can be quite a challenging task as security issues can be
hard to anticipate and often depend on complex interactions in distributed
systems. The `netsec` package contains code which helps build and maintain
secure Go applications.

## Restricting connections to private networks

A common problem that services face is preventing unauthorized access to private
networks. This often comes up when the public endpoints of those services are
configured dynamically (like a webhook for example).

The `netsec` package helps protect against malicious use of those kinds of
applications by providing a decorator for the typical dial functions used to
establish network connections, which can be configured to allow or deny certain
IP network ranges.

Here is an example of how a program can leverage the `netsec` package to prevent
HTTP requests from going to private network addresses:
```go
import (
    "net/http"

    "github.com/segmentio/netsec"
)

func init() {
    t := http.DefaultTransport.(*http.Transport)
    // Modifies the dial function used by the default http transport to deny
    // requests that would reach private IP addresses.
    t.DialContext = netsec.RestrictedDial(t.DialContext,
        netsec.Denylist(netsec.PrivateIPNetworks),
    )
}

```