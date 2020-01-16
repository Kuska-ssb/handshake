[![codecov](https://codecov.io/gh/Kuska-ssb/kuska-handshake/branch/master/graph/badge.svg)](https://codecov.io/gh/Kuska-ssb/kuska-handshake)

# ssb-study

- FAQ
    - https://ssbc.github.io/docs/ssb/faq.html
- Protocol Guide
    - https://ssbc.github.io/scuttlebutt-protocol-guide/

The default implementation of ssb is in javascript.

## [secret-stack](https://github.com/ssbc/secret-stack)

Glue for everything

## [MuxRPC](https://github.com/ssbc/muxrpc)

RPC (as explained in the protocol guide) and multiplexing

## [secret-handshake](https://github.com/auditdrivencrypto/secret-handshake)

Handshake (as explained in the protocol guide)

## Plugins

RPCs are implemented as plugins for secret-stack.

https://github.com/ssbc/secret-stack/blob/master/PLUGINS.md

### [ssb-blobs](https://github.com/ssbc/ssb-blobs)

- [ "blobs", "..." ]

### [ssb-feed](https://github.com/ssb-junkyard/ssb-feed)

- legacy?

### [ssb-db](https://github.com/ssbc/ssb-db)

- Append only db (feed)

## RPC

Method types:
```
foo: 'async',        //a function with a callback.
bar: 'sync',         //a function that returns a value
                     //(note this is converted to an async function for the client)
allTheFoos: 'source' //a source pull-stream (aka, readable)
writeFoos: 'sink',   //a sink pull-stream (aka, writable)
fooPhone: 'duplex',  //a duplex pull-stream
```
