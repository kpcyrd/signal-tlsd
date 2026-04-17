# signal-tlsd

Standalone Rust implementation of Signal's domain fronting TLS proxy.

Negotiates an outer TLS handshake and listens for an incoming TLS connection from the Signal client. The inner TLS connection remains end-to-end encrypted between the client and the Signal server, while the outer TLS connection is terminated at the proxy.

```
-----------------------------.------------.
                          .-'              '-.
                        .'-------------------------.------.
                       /                         .'        '.
   www.example.com    |      chat.signal.org    /            \
                      |                        |              |
      encrypted       |         encrypted       \            /
                       \                         '.        .'
                        '.-------------------------'------'
                          '-.              .-'
-----------------------------'------------'
```

This evades censorship based on IP address blocking, DNS filtering, and SNI-based [deep packet inspection](https://en.wikipedia.org/wiki/Deep_packet_inspection).

It implements the protocol of the [official Signal-TLS-Proxy](https://github.com/signalapp/Signal-TLS-Proxy), but in a single process instead of two nginx instances glued together with docker-compose.

It was successfully field-tested in April 2026 to evade Russian censorship of Signal, through a VPS located in Kazakhstan.

## Usage

A real-world example invocation may look like this:

```
./signal-tlsd -B '[::]:443' \
    --cert /var/lib/acme-redirect/live/example.com/fullchain \
    --private-key /var/lib/acme-redirect/live/example.com/privkey \
    -F 127.0.0.1:8080 -v
```

You may use [acme-redirect](https://github.com/kpcyrd/acme-redirect) to obtain your TLS certificates, but anything else works too.

To privately share your proxy with your friends you can send them a link like:

```
https://signal.tube/#example.com
```

### Fallback endpoint

By default, if the inner connection either doesn't start with a TLS client hello, or the inner SNI value does not match any configured endpoints, the connection is shut down. When setting `-F 127.0.0.1:8080` those connections aren't dropped, but instead forwarded to this default endpoint (together with the buffered data). This can be used to host regular websites on your cover domain, while still allowing Signal to use the same domain for its TLS connections.

### Non-standard allow-list

Without any `-A` options used, it's using the built-in allow list of signal endpoints. If the `-A` option _is_ used, it starts with an empty allow list rejecting everything, and only the specified endpoints are allowed:

```
./signal-tlsd -B '[::]:443' \
    --cert /var/lib/acme-redirect/live/example.com/fullchain \
    --private-key /var/lib/acme-redirect/live/example.com/privkey \
    -A orcas.sink.yachts -A example.com
```

The special value `-` leaves the allow list unmodified, yet still counts as using the `-A` option, giving you an empty allow list instead of the standard built-in list.

### Running signal-tlsd as regular TLS termination proxy

It's possible to use signal-tlsd as a regular off-the-shelf TLS termination proxy, without using the inner TLS feature at all. For this mode of operation, use an empty allow list (`-A -`) together with the `-F <endpoint>` option, causing everything to be forwarded to the fallback unconditionally.

```
./signal-tlsd -B '[::]:443' \
    --cert /var/lib/acme-redirect/live/example.com/fullchain \
    --private-key /var/lib/acme-redirect/live/example.com/privkey \
    -A - -F 127.0.0.1:8080 -v
```

### Reload certificates

When receiving a `SIGHUP` signal, the certificates are reloaded from disk. This allows you to update the TLS certificate without needing to restart the server.

## Compiling

You need Rust to compile this project, if you don't have it installed already you can either get it from your operating system's package manager or from [rustup.rs](https://rustup.rs/).

```
git clone https://github.com/kpcyrd/signal-tlsd.git
cd signal-tlsd
cargo build --release
./target/release/signal-tlsd --help
```

### Compiling with Docker

Alternatively, you can use the provided Dockerfile:
```
docker build -t signal-tlsd .
docker run --rm signal-tlsd --help
```

### Testing inner TLS layer

This runs the server without the outer TLS layer, so you can connect directly to the inner TLS layer. This is useful for testing the inner TLS handling without needing to set up an outer TLS certificate, or if you terminate the outer TLS layer with a separate TLS proxy, like nginx.

```
# run this in other terminal
cargo run --release -- -v -A orca.toys -N -B 127.0.0.1:4443
# send a request
curl --resolve orca.toys:4443:127.0.0.1 https://orca.toys:4443/
```

### Testing outer TLS layer

This is the regular mode of operation, you need to provide a TLS certificate for the outer TLS layer. For testing, any self-signed certificate can be used. We use `socat` so `curl` can connect to the inner TLS layer directly, without needing to understand Signal's TLS proxying mechanism.

```
# generate certificate
sh4d0wup keygen tls > tls.pem
# run this in other terminal
cargo run --release -- -v -A orca.toys:443 -B 127.0.0.1:4443 --cert tls.pem --private-key tls.pem
# run this in yet other terminal
socat tcp-listen:4442,reuseaddr openssl:localhost:4443,verify=0
# send a request
curl --resolve orca.toys:4442:127.0.0.1 https://orca.toys:4442/
```

## License

`MIT-0`
