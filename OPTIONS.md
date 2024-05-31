# Options 
## services.hysteria.client.dir
Working directory of the OpenGFW service and home of `hysteria-client.user`.
### Type
```
(optionally newline-terminated) single-line string
```
### Default
```nix
"/var/lib/hysteria-client"
```
---
 
## services.hysteria.client.enable
Whether to enable Hysteria (client), a powerful, lightning fast and censorship resistant proxy.
.
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.client.logFormat
Format of the logs.
### Type
```
one of "json", "console"
```
### Default
```nix
"json"
```
### Example 
```nix
"console"
```
---
 
## services.hysteria.client.logLevel
Level of the logs.
### Type
```
one of "debug", "info", "warn", "error"
```
### Default
```nix
"info"
```
### Example 
```nix
"warn"
```
---
 
## services.hysteria.client.package
The hysteria package to use.
### Type
```
package
```
### Default
```nix
pkgs.hysteria
```
---
 
## services.hysteria.client.settings
Hysteria client settings
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.client.settings.auth
If the server uses the `userpass` authentication, the format must be `username:password`.
### Type
```
string
```
### Example 
```nix
"some_password"
```
---
 
## services.hysteria.client.settings.bandwidth
Hysteria has two built-in congestion control algorithms (BBR & Brutal).
Which one to use depends on whether bandwidth information is provided.
If you want to use BBR instead of Brutal, you can delete the entire bandwidth section.
For more details, see [Bandwidth negotiation process](https://v2.hysteria.network/docs/advanced/Full-Server-Config/#bandwidth-negotiation-process) and [Congestion control details](https://v2.hysteria.network/docs/advanced/Full-Server-Config/#congestion-control-details).

> ⚠️ Warning Higher bandwidth values are not always better; be very careful not to exceed the maximum bandwidth that your current network can support.
> Doing so will backfire, causing network congestion and unstable connections.

The client's actual upload speed will be the lesser of the value specified here and the server's maximum download speed (if set by the server).
Similarly, the client's actual download speed will be the lesser of the value specified here and the server's maximum upload speed (if set by the server).
One exception is that if the server has enabled the `ignoreClientBandwidth` option, the values specified here will be ignored.
Supported units are:
+ bps or b (bits per second)
+ kbps or kb or k (kilobits per second)
+ mbps or mb or m (megabits per second)
+ gbps or gb or g (gigabits per second)
+ tbps or tb or t (terabits per second)
### Type
```
submodule
```
### Default
```nix
{ }
```
---
 
## services.hysteria.client.settings.bandwidth.down
The client's download bandwidth.
### Type
```
string
```
### Default
```nix
"200 mbps"
```
### Example 
```nix
"500 mbps"
```
---
 
## services.hysteria.client.settings.bandwidth.up
The client's upload bandwidth.
### Type
```
string
```
### Default
```nix
"100 mbps"
```
### Example 
```nix
"50 mbps"
```
---
 
## services.hysteria.client.settings.fastOpen
Fast Open can shave one roundtrip time (RTT) off each connection,
but at the cost of the correct semantics of SOCKS5/HTTP proxy protocols.
When this is enabled, the client always immediately accepts a connection without confirming with the server that the destination is reachable.
If the server then fails or rejects the connection, the client will simply close the connection without sending any data back to the proxy client.
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.client.settings.http
An HTTP proxy server that can be used with any HTTP proxy-compatible application.
Supports both plaintext HTTP and HTTPS (CONNECT).
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.client.settings.http.listen
The address to listen on.
### Type
```
string
```
### Example 
```nix
"127.0.0.1:8080"
```
---
 
## services.hysteria.client.settings.http.password
Optional. The password to require for authentication.
### Type
```
null or string
```
### Default
```nix
null
```
### Example 
```nix
"kong"
```
---
 
## services.hysteria.client.settings.http.realm
Optional. The realm to require for authentication.
### Type
```
null or string
```
### Default
```nix
null
```
### Example 
```nix
"martian"
```
---
 
## services.hysteria.client.settings.http.username
Optional. The username to require for authentication.
### Type
```
null or string
```
### Default
```nix
null
```
### Example 
```nix
"king"
```
---
 
## services.hysteria.client.settings.lazy
When enabled, the client is "lazy" in the sense that it will only attempt to connect to the server if there is an incoming connection from one of the enabled client modes.
This differs from the default behavior, where the client attempts to connect to the server as soon as it starts up.
The `lazy` option can be useful if you're unsure when you'll use the client and want to avoid idle connections.
It's also useful if your Internet connection might not be ready when you start the Hysteria client.
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.client.settings.obfs
By default, the Hysteria protocol mimics HTTP/3.
If your network specifically blocks QUIC or HTTP/3 traffic (but not UDP in general), obfuscation can be used to work around this.
We currently have an obfuscation implementation called "Salamander" that converts packets into seamingly random bytes with no pattern.
This feature requires a password that must be identical on both the client and server sides.
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.client.settings.obfs.salamander.password
Replace with a strong password of your choice.
### Type
```
string
```
### Example 
```nix
"cry_me_a_r1ver"
```
---
 
## services.hysteria.client.settings.obfs.type
Obfuscation type
### Type
```
string
```
### Default
```nix
"salamander"
```
---
 
## services.hysteria.client.settings.quic.sockopts.bindInterface
Forces QUIC packets to be sent through this interface.
### Type
```
null or string
```
### Default
```nix
null
```
### Example 
```nix
"eth0"
```
---
 
## services.hysteria.client.settings.quic.sockopts.fdControlUnixSocket
Path to a Unix Socket that is listened to by other processes.
The Hysteria client will send the file descriptor (FD) used for the QUIC connection as ancillary information to this Unix Socket,
allowing the listening process to perform other custom configurations.
This option can be used in Android client development; please refer to the [FD Control Protocol](https://v2.hysteria.network/docs/advanced/FD-Control/) for more details.
### Type
```
null or string
```
### Default
```nix
null
```
### Example 
```nix
"./test.sock"
```
---
 
## services.hysteria.client.settings.quic.sockopts.fwmark
The `SO_MARK` tag to be added to QUIC packets.
### Type
```
null or signed integer
```
### Default
```nix
null
```
### Example 
```nix
1234
```
---
 
## services.hysteria.client.settings.server
The server field specifies the address of the Hysteria server that the client should connect to.
The address can be formatted as either `host:port` or just `host`. If the port is omitted, it defaults to 443.
You also have the option to use a Hysteria 2 URI (`hysteria2://`).
In this case, because the URI already includes the password and certain other settings, you don't (and can't) specify them separately in the configuration file.
### Type
```
string
```
### Example 
```nix
"example.com"
```
---
 
## services.hysteria.client.settings.socks5
A SOCKS5 proxy server that can be used with any SOCKS5-compatible application.
Supports both TCP and UDP.
### Type
```
submodule
```
---
 
## services.hysteria.client.settings.socks5.disableUDP
Optional. Disable UDP support.
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.client.settings.socks5.listen
The address to listen on.
### Type
```
string
```
### Example 
```nix
"127.0.0.1:1080"
```
---
 
## services.hysteria.client.settings.socks5.password
Optional. The password to require for authentication.
### Type
```
null or string
```
### Default
```nix
null
```
### Example 
```nix
"pass"
```
---
 
## services.hysteria.client.settings.socks5.username
Optional. The username to require for authentication.
### Type
```
null or string
```
### Default
```nix
null
```
### Example 
```nix
"user"
```
---
 
## services.hysteria.client.settings.tcpForwarding
TCP Forwarding allows you to forward one or more TCP ports from the server (or any remote host) to the client.
This is useful, for example, if you want to access a service that is only available on the server's network.
### Type
```
null or (list of (submodule))
```
### Default
```nix
null
```
---
 
## services.hysteria.client.settings.tcpForwarding.*.listen
The address to listen on.
### Type
```
string
```
### Example 
```nix
"127.0.0.1:6600"
```
---
 
## services.hysteria.client.settings.tcpForwarding.*.remote
The address to forward to.
### Type
```
string
```
### Example 
```nix
"other.machine.internal:6601"
```
---
 
## services.hysteria.client.settings.tcpRedirect
REDIRECT is essentially a special case of DNAT where the destination address is localhost.
This method predates TPROXY as an older way to implement a TCP transparent proxy.
We recommend using TPROXY instead if your kernel supports it.
[Example](https://v2.hysteria.network/docs/advanced/Full-Client-Config/#tcp-redirect-linux-only)
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.client.settings.tcpRedirect.listen
The address to listen on.
### Type
```
unspecified value
```
### Example 
```nix
":2500"
```
---
 
## services.hysteria.client.settings.tcpTProxy
TPROXY (transparent proxy) is a Linux-specific feature that allows you to transparently proxy TCP connections.
For information, please refer to [Setting up TPROXY](https://v2.hysteria.network/docs/advanced/TPROXY/).
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.client.settings.tcpTProxy.listen
The address to listen on.
### Type
```
unspecified value
```
### Example 
```nix
":2500"
```
---
 
## services.hysteria.client.settings.tls
TLS client settings
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.client.settings.tls.ca
Use a custom CA certificate for TLS verification.
### Type
```
null or path
```
### Default
```nix
null
```
### Example 
```nix
"custom_ca.crt"
```
---
 
## services.hysteria.client.settings.tls.insecure
Disable TLS verification.
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.client.settings.tls.pinSHA256
Verify the server's certificate fingerprint.
You can obtain the fingerprint of your certificate using openssl:
`openssl x509 -noout -fingerprint -sha256 -in your_cert.crt`
### Type
```
null or string
```
### Default
```nix
null
```
### Example 
```nix
"BA:88:45:17:A1..."
```
---
 
## services.hysteria.client.settings.tls.sni
Server name to use for TLS verification.
If omitted, the server name will be extracted from the `server` field.
### Type
```
null or string
```
### Default
```nix
null
```
### Example 
```nix
"another.example.com"
```
---
 
## services.hysteria.client.settings.transport
The `transport` section is for customizing the underlying protocol used by the QUIC connection.
Currently the only type available is `udp`, but we reserve it for possible future expansions.
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.client.settings.transport.options.type
Transport type selection
### Type
```
value "udp" (singular enum)
```
### Default
```nix
"udp"
```
---
 
## services.hysteria.client.settings.transport.options.udp.hopInterval
The port hopping interval.
This is only relevant if you're using a port hopping address.
See [Port Hopping](https://v2.hysteria.network/docs/advanced/Port-Hopping/) for more information.
### Type
```
string
```
### Default
```nix
"30s"
```
### Example 
```nix
"60s"
```
---
 
## services.hysteria.client.settings.tun
TUN mode is a cross-platform transparent proxy solution that creates a virtual network interface in the system and uses the system's routes to capture and redirect traffic.
It currently works on Windows, Linux, and macOS.
Unlike traditional L3 VPNs (such as WireGuard and OpenVPN), Hysteria's TUN mode can only handle TCP and UDP and does not support other protocols including ICMP (e.g. ping).
It also takes control of the TCP stack to speed up TCP connections.
Compared to Hysteria 1's implementation, Hysteria 2's TUN is based on sing-tun's "system" stack,
requiring a /30 IPv4 address and a /126 IPv6 address to be configured on the interface.
Hysteria will automatically set up the network interface, addresses, and routes.
> NOTE: ipv4Exclude/ipv6Exclude is important to avoid getting a routing loop. See the comments for these fields for more information.
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.client.settings.tun.address
Optional. Addresses to use on the interface.
Set to any private address that does not conflict with your LAN.
The defaults are as shown.
### Type
```
submodule
```
### Default
```nix
{ }
```
---
 
## services.hysteria.client.settings.tun.address.ipv4
The IPv4 address to use.
### Type
```
string
```
### Example 
```nix
"100.100.100.101/30"
```
---
 
## services.hysteria.client.settings.tun.address.ipv6
The IPv6 address to use.
### Type
```
string
```
### Example 
```nix
"2001::ffff:ffff:ffff:fff1/126"
```
---
 
## services.hysteria.client.settings.tun.mtu
Optional. The maximum packet size accepted by the TUN interface.
### Type
```
signed integer
```
### Default
```nix
1500
```
---
 
## services.hysteria.client.settings.tun.name
The name of the TUN interface.
### Type
```
string
```
### Example 
```nix
"hytun"
```
---
 
## services.hysteria.client.settings.tun.route
Optional. Routing rules. Omitting or skipping all fields means that no routes will be added automatically.
In most cases, just having `ipv4Exclude` or `ipv6Exclude` is enough.
### Type
```
submodule
```
### Default
```nix
{ }
```
---
 
## services.hysteria.client.settings.tun.route.ipv4
Optional. IPv4 prefix to proxy.
If any other field is configured, the default is 0.0.0.0/0.
### Type
```
string
```
### Example 
```nix
"[0.0.0.0/0]"
```
---
 
## services.hysteria.client.settings.tun.route.ipv4Exclude
Optional. IPv4 prefix to exclude.
**Add your Hysteria server address here to avoid a routing loop.**
If you want to disable IPv4 proxying completely, you can also put `0.0.0.0/0` here.
### Type
```
string
```
### Example 
```nix
"[192.0.2.1/32]"
```
---
 
## services.hysteria.client.settings.tun.route.ipv6
Optional. IPv6 prefix to proxy.
Due to YAML limitations, quotes are required.
If any other field is configured, the default is ::/0.
### Type
```
string
```
### Example 
```nix
"[\"2000::/3\"]"
```
---
 
## services.hysteria.client.settings.tun.route.ipv6Exclude
Optional. IPv6 prefix to exclude.
Due to YAML limitations, quotes are required.
**Add your Hysteria server address here to avoid a routing loop.**
If you want to disable IPv6 proxying completely, you can also put `"::/0"` here.
### Type
```
string
```
### Example 
```nix
"[\"2001:db8::1/128\"]"
```
---
 
## services.hysteria.client.settings.tun.timeout
Optional. UDP session timeout.
### Type
```
string
```
### Default
```nix
"5m"
```
### Example 
```nix
"10m"
```
---
 
## services.hysteria.client.settings.udpForwarding
UDP Forwarding allows you to forward one or more UDP ports from the server (or any remote host) to the client.
This is useful, for example, if you want to access a service that is only available on the server's network.
### Type
```
null or (list of (submodule))
```
### Default
```nix
null
```
---
 
## services.hysteria.client.settings.udpForwarding.*.listen
The address to listen on.
### Type
```
string
```
### Example 
```nix
"127.0.0.1:6600"
```
---
 
## services.hysteria.client.settings.udpForwarding.*.remote
The address to forward to.
### Type
```
string
```
### Example 
```nix
"other.machine.internal:5301"
```
---
 
## services.hysteria.client.settings.udpForwarding.*.timeout
Optional. The timeout for each UDP session.
If omitted, the default timeout is 60 seconds.
### Type
```
string
```
### Default
```nix
"60s"
```
### Example 
```nix
"20s"
```
---
 
## services.hysteria.client.settings.udpTProxy
TPROXY (transparent proxy) is a Linux-specific feature that allows you to transparently proxy UDP connections.
For information, please refer to [Setting up TPROXY](https://v2.hysteria.network/docs/advanced/TPROXY/).
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.client.settings.udpTProxy.listen
The address to listen on.
### Type
```
unspecified value
```
### Example 
```nix
":2500"
```
---
 
## services.hysteria.client.settings.udpTProxy.timeout
Optional. The timeout for each UDP session.
If omitted, the default timeout is 60 seconds.
### Type
```
string
```
### Default
```nix
"60s"
```
### Example 
```nix
"20s"
```
---
 
## services.hysteria.client.settingsFile
Path to file containing Hysteria settings.
### Type
```
null or path
```
### Default
```nix
null
```
---
 
## services.hysteria.client.user
Username of the Hysteria user
### Type
```
string
```
### Default
```nix
"hysteria-client"
```
---
 
## services.hysteria.server.dir
Working directory of the OpenGFW service and home of `hysteria-server.user`.
### Type
```
(optionally newline-terminated) single-line string
```
### Default
```nix
"/var/lib/hysteria-server"
```
---
 
## services.hysteria.server.enable
Whether to enable Hysteria (server), a powerful, lightning fast and censorship resistant proxy.
.
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.server.logFormat
Format of the logs.
### Type
```
one of "json", "console"
```
### Default
```nix
"json"
```
### Example 
```nix
"console"
```
---
 
## services.hysteria.server.logLevel
Level of the logs.
### Type
```
one of "debug", "info", "warn", "error"
```
### Default
```nix
"info"
```
### Example 
```nix
"warn"
```
---
 
## services.hysteria.server.openFirewall
Open the firewall for the Hysteria server.
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.server.package
The hysteria package to use.
### Type
```
package
```
### Default
```nix
pkgs.hysteria
```
---
 
## services.hysteria.server.settings
Hysteria server settings
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.server.settings.acl
ACL, often used in combination with outbounds, is a very powerful feature of the Hysteria server that allows you to customize the way client's requests are handled.
For example, you can use ACL to block certain addresses, or to use different outbounds for different websites.
For details on syntax, usage and other information, please refer to the [ACL documentation](https://v2.hysteria.network/docs/advanced/ACL/).
You can have either `file` or `inline`, but not both.

> NOTE: Hysteria currently uses the protobuf-based "dat" format for geoip/geosite data originating from v2ray.
> If you don't need any customization, you can omit the `geoip` or `geosite` fields and let Hysteria automatically download the latest version [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) to your working directory.
> The files will only be downloaded and used if your ACL has at least one rule that uses this feature.
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.server.settings.acl.file
The path to the ACL file.
### Type
```
null or path
```
### Default
```nix
null
```
### Example 
```nix
"./some.txt"
```
---
 
## services.hysteria.server.settings.acl.geoUpdateInterval
Optional. The interval at which to refresh the GeoIP/GeoSite databases.
168 hours (1 week) by default. Only applies if the GeoIP/GeoSite databases are automatically downloaded.
> Hysteria currently only downloads the GeoIP/GeoSite databases once at startup.
> You will need to use external tools to periodically restart the Hysteria server in order to update the databases regularly through geoUpdateInterval.
> This may change in future versions.
### Type
```
string
```
### Default
```nix
"168h"
```
### Example 
```nix
"100h"
```
---
 
## services.hysteria.server.settings.acl.geoip
Optional. The path to the GeoIP database file.
If this field is omitted, Hysteria will automatically download the latest database to your working directory.
### Type
```
null or path
```
### Default
```nix
null
```
### Example 
```nix
"./geoip.dat"
```
---
 
## services.hysteria.server.settings.acl.geosite
Optional. The path to the GeoSite database file.
If this field is omitted, Hysteria will automatically download the latest database to your working directory.
### Type
```
null or path
```
### Default
```nix
null
```
### Example 
```nix
"./geoip.dat"
```
---
 
## services.hysteria.server.settings.acl.inline
The list of inline ACL rules. [ACL documentation](https://v2.hysteria.network/docs/advanced/ACL/)]
### Type
```
null or (list of string)
```
### Default
```nix
null
```
### Example 
```nix
[
  "reject(suffix:v2ex.com)"
  "reject(all, udp/443)"
  "reject(geoip:cn)"
  "reject(geosite:netflix)"
]
```
---
 
## services.hysteria.server.settings.acme
ACME configuration.
### Type
```
null or (submodule)
```
### Default
```nix
''
  (cfg.server.settings.tls != null) -> null
''
```
---
 
## services.hysteria.server.settings.acme.altHTTPPort
Alternate HTTP challenge port.
(Note: If you want to use anything other than 80, you must set up port forward/HTTP reverse proxy from 80 to that port, otherwise ACME will not be able to issue the certificate.)
### Type
```
signed integer
```
### Default
```nix
80
```
---
 
## services.hysteria.server.settings.acme.altTLSALPNPort
Alternate TLS-ALPN challenge port.
(Note: If you want to use anything other than 443, you must set up port forward/SNI proxy from 443 to that port, otherwise ACME will not be able to issue the certificate.)
### Type
```
signed integer
```
### Default
```nix
443
```
---
 
## services.hysteria.server.settings.acme.ca
The CA to use.
### Type
```
one of "letsencrypt", "zerossl"
```
### Default
```nix
"letsencrypt"
```
### Example 
```nix
"zerossl"
```
---
 
## services.hysteria.server.settings.acme.dir
The directory to store the ACME account key and certificates.
### Type
```
string
```
### Default
```nix
"acme"
```
---
 
## services.hysteria.server.settings.acme.disableHTTP
Disable HTTP challenge.
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.server.settings.acme.disableTLSALPN
Disable TLS-ALPN challenge.
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.server.settings.acme.domains
Your domains
### Type
```
list of string
```
### Default
```nix
[ ]
```
### Example 
```nix
[
  "domain1.com"
  "domain2.org"
]
```
---
 
## services.hysteria.server.settings.acme.email
Your email address
### Type
```
string
```
### Default
```nix
null
```
### Example 
```nix
"your@email.net"
```
---
 
## services.hysteria.server.settings.acme.listenHost
The host address (not including the port) to listen on for the ACME challenge.
If omitted, the server will listen on all interfaces.
### Type
```
string
```
### Default
```nix
"0.0.0.0"
```
### Example 
```nix
"192.168.5.150"
```
---
 
## services.hysteria.server.settings.auth
Authentication payload:
```json
  {
     "addr": "123.123.123.123:44556", 
     "auth": "something_something", 
     "tx": 123456 
  }
```
### Type
```
submodule
```
---
 
## services.hysteria.server.settings.auth.command
The path to the command that handles authentication.
When using command authentication,
the server will execute the specified command with the following arguments from the authentication payload when a client attempts to connect:
```
/etc/some_command addr auth tx 
```
The command must print the client's unique identifier to `stdout` and return with exit code 0 if the client is allowed to connect,
or return with a non-zero exit code if the client is rejected.
If the command fails to execute, the client will be rejected.
### Type
```
null or string
```
### Default
```nix
null
```
### Example 
```nix
"/etc/some_command"
```
---
 
## services.hysteria.server.settings.auth.http
When using HTTP authentication, the server will send a `POST` request to the backend server with the authentication payload when a client attempts to connect.
Your endpoint must respond with a JSON object with the following fields:
```json
{
  "ok": true, 
    "id": "john_doe" 
}
```
> NOTE: The HTTP status code must be 200 for the authentication to be considered successful.
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.server.settings.auth.http.insecure
Disable TLS verification for the backend server (only applies to HTTPS URLs).
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.server.settings.auth.http.url
The URL of the backend server that handles authentication.
### Type
```
string
```
### Example 
```nix
"http://your.backend.com/auth"
```
---
 
## services.hysteria.server.settings.auth.password
Replace with a strong password of your choice.
### Type
```
null or string
```
### Default
```nix
null
```
### Example 
```nix
"your_password"
```
---
 
## services.hysteria.server.settings.auth.type
Authentication type.
### Type
```
string
```
### Default
```nix
"password"
```
---
 
## services.hysteria.server.settings.auth.userpass
A map of username-password pairs.
### Type
```
null or (attribute set of string)
```
### Default
```nix
null
```
### Example 
```nix
{
  user1 = "pass1";
  user2 = "pass2";
  user3 = "pass3";
}
```
---
 
## services.hysteria.server.settings.bandwidth
The bandwidth values on the server side act as speed limits, limiting the maximum rate at which the server will send and receive data (per client).
**Note that the server's upload speed is the client's download speed, and vice versa.**
You can omit these values or set them to zero on either or both sides, which would mean no limit.
Supported units are:
+ bps or b (bits per second)
+ kbps or kb or k (kilobits per second)
+ mbps or mb or m (megabits per second)
+ gbps or gb or g (gigabits per second)
+ tbps or tb or t (terabits per second)
### Type
```
submodule
```
### Default
```nix
{ }
```
---
 
## services.hysteria.server.settings.bandwidth.down
The server's download bandwidth.
### Type
```
string
```
### Default
```nix
"1 gbps"
```
### Example 
```nix
"0"
```
---
 
## services.hysteria.server.settings.bandwidth.up
The server's upload bandwidth.
### Type
```
string
```
### Default
```nix
"1 gbps"
```
### Example 
```nix
"0"
```
---
 
## services.hysteria.server.settings.disableUDP
`disableUDP` disables UDP forwarding, only allowing TCP connections.
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.server.settings.ignoreClientBandwidth
`ignoreClientBandwidth` is a special option that, when enabled, makes the server to disregard any bandwidth hints set by clients,
opting to use a more traditional congestion control algorithm (currently BBR) instead.
This effectively overrides any bandwidth values set by clients in both directions.
This feature is primarily useful for server owners who prefer congestion fairness over other network traffic,
or who do not trust users to accurately set their own bandwidth values.
[Bandwidth negotiation process](https://v2.hysteria.network/docs/advanced/Full-Server-Config/#bandwidth-negotiation-process)
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.server.settings.listen
The server's listen address.
When the IP address is omitted, the server will listen on all interfaces, both IPv4 and IPv6.
To listen on IPv4 only, you can use `0.0.0.0:443`.
To listen on IPv6 only, you can use `[::]:443`.
### Type
```
string
```
### Default
```nix
":443"
```
---
 
## services.hysteria.server.settings.masquerade
One of the keys to Hysteria's censorship resistance is its ability to masquerade as standard HTTP/3 traffic.
This means that not only do the packets appear as HTTP/3 to middleboxes, but the server also responds to HTTP requests like a regular web server.
However, this means that your server must actually serve some content to make it appear authentic to potential censors.
**If censorship is not a concern, you can omit the masquerade section entirely. In this case, Hysteria will always return "404 Not Found" for all HTTP requests.**
Currently, Hysteria provides the following masquerade modes:
+ `file`: Act as a static file server, serving files from a directory.
+ `proxy`: Act as a reverse proxy, serving content from another website.
+ `string`: Act as a server that always returns a user-supplied string.

[HTTP/HTTPS Masquerading documentation](https://v2.hysteria.network/docs/advanced/Full-Server-Config/#httphttps-masquerading)
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.server.settings.masquerade.file.dir
The directory to serve files from.
### Type
```
null or path
```
### Default
```nix
null
```
### Example 
```nix
"/www/masq"
```
---
 
## services.hysteria.server.settings.masquerade.forceHTTPS
Whether to force HTTPS.
If enabled, all HTTP requests will be redirected to HTTPS.
### Type
```
boolean
```
### Default
```nix
true
```
### Example 
```nix
false
```
---
 
## services.hysteria.server.settings.masquerade.listenHTTP
HTTP (TCP) listen address.
### Type
```
string
```
### Default
```nix
":80"
```
---
 
## services.hysteria.server.settings.masquerade.listenHTTPS
HTTPS (TCP) listen address.
### Type
```
string
```
### Default
```nix
":443"
```
---
 
## services.hysteria.server.settings.masquerade.proxy
Use a proxy for masquerading.
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.server.settings.masquerade.proxy.rewriteHost
Whether to rewrite the Host header to match the proxied website.
This is required if the target web server uses Host to determine which site to serve.
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.server.settings.masquerade.proxy.url
The URL of the website to proxy.
### Type
```
string
```
### Example 
```nix
"https://some.site.net"
```
---
 
## services.hysteria.server.settings.masquerade.string
Use a string for masquerading.
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.server.settings.masquerade.string.content
The string to return.
### Type
```
string
```
### Example 
```nix
"hello stupid world"
```
---
 
## services.hysteria.server.settings.masquerade.string.headers
Optional. The headers to return.
### Type
```
null or (attribute set of string)
```
### Default
```nix
null
```
---
 
## services.hysteria.server.settings.masquerade.string.statusCode
Optional. The status code to return.
### Type
```
signed integer
```
### Default
```nix
200
```
### Example 
```nix
404
```
---
 
## services.hysteria.server.settings.masquerade.type
Masquerade type
### Type
```
one of "file", "proxy", "string"
```
### Default
```nix
"proxy"
```
### Example 
```nix
"string"
```
---
 
## services.hysteria.server.settings.obfs
By default, the Hysteria protocol mimics HTTP/3.
If your network specifically blocks QUIC or HTTP/3 traffic (but not UDP in general), obfuscation can be used to work around this.
We currently have an obfuscation implementation called "Salamander" that converts packets into seamingly random bytes with no pattern.
This feature requires a password that must be identical on both the client and server sides.
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.server.settings.obfs.salamander.password
Replace with a strong password of your choice.
### Type
```
string
```
### Example 
```nix
"cry_me_a_r1ver"
```
---
 
## services.hysteria.server.settings.obfs.type
Obfuscation type
### Type
```
string
```
### Default
```nix
"salamander"
```
---
 
## services.hysteria.server.settings.outbounds
Outbounds are used to define the "exit" through which a connection should be routed.
For example, when [combined with ACL](https://v2.hysteria.network/docs/advanced/ACL/),
you can route all traffic except Netflix directly through the local interface, while routing Netflix traffic through a SOCKS5 proxy.
Currently, Hysteria supports the following outbound types:
+ direct: Direct connection through the local interface.
+ socks5: SOCKS5 proxy.
+ http: HTTP/HTTPS proxy.

> NOTE: HTTP/HTTPS proxies do not support UDP at the protocol level. Sending UDP traffic to HTTP outbounds will result in rejection.

**If you do not use ACL, all connections will always be routed through the first ("default") outbound in the list, and all other outbounds will be ignored.**
### Type
```
null or (list of (submodule))
```
### Default
```nix
null
```
### Example 
```nix
[
  {
    name = "my_outbound_1";
    type = "direct";
  }
  {
    name = "my_outbound_2";
    socks5 = {
      addr = "shady.proxy.ru:1080";
      password = "Elliot Alderson";
      username = "hackerman";
    };
    type = "socks5";
  }
  {
    http = {
      insecure = false;
      url = "http://username:password@sketchy-proxy.cc:8081";
    };
    name = "my_outbound_3";
    type = "http";
  }
  {
    direct = {
      bindDevice = "eth233";
      bindIPv4 = "2.4.6.8";
      bindIPv6 = "0:0:0:0:0:ffff:0204:0608";
      mode = "auto";
    };
    name = "hoho";
    type = "direct";
  }
]
```
---
 
## services.hysteria.server.settings.outbounds.*.direct
The direct outbound has a few additional options that can be used to customize its behavior:
> NOTE: The options `bindIPv4`, `bindIPv6`, and `bindDevice` are mutually exclusive.
> You can either specify `bindIPv4` and/or `bindIPv6` without `bindDevice`, or use `bindDevice` without `bindIPv4` and `bindIPv6`.
### Type
```
submodule
```
---
 
## services.hysteria.server.settings.outbounds.*.direct.bindDevice
The local network interface to bind to.
### Type
```
string
```
### Example 
```nix
"eth233"
```
---
 
## services.hysteria.server.settings.outbounds.*.direct.bindIPv4
The local IPv4 address to bind to.
### Type
```
string
```
### Example 
```nix
"2.4.6.8"
```
---
 
## services.hysteria.server.settings.outbounds.*.direct.bindIPv6
The local IPv6 address to bind to.
### Type
```
string
```
### Example 
```nix
"0:0:0:0:0:ffff:0204:0608"
```
---
 
## services.hysteria.server.settings.outbounds.*.direct.mode
The available mode values are:
+ `auto`: Default. Dual-stack "happy eyeballs" mode. The client will attempt to connect to the destination using both IPv4 and IPv6 addresses (if available), and use the first one that succeeds.
+ `64`: Always use IPv6 if available, otherwise use IPv4.
+ `46`: Always use IPv4 if available, otherwise use IPv6.
+ `6`: Always use IPv6. Fail if no IPv6 address is available.
+ `4`: Always use IPv4. Fail if no IPv4 address is available.
### Type
```
one of "auto", "64", "46", "6", "4"
```
### Default
```nix
"auto"
```
---
 
## services.hysteria.server.settings.outbounds.*.http.insecure
Optional. Whether to disable TLS verification. Applies to HTTPS proxies only.
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.server.settings.outbounds.*.http.url
The URL of the HTTP/HTTPS proxy. (Can be `http://` or `https://`)
### Type
```
string
```
### Example 
```nix
"http://username:password@sketchy-proxy.cc:8081"
```
---
 
## services.hysteria.server.settings.outbounds.*.name
The name of the outbound. This is used in ACL rules.
### Type
```
string
```
### Example 
```nix
"my_outbound_1"
```
---
 
## services.hysteria.server.settings.outbounds.*.socks5.addr
The address of the SOCKS5 proxy.
### Type
```
string
```
### Example 
```nix
"shady.proxy.ru:1080"
```
---
 
## services.hysteria.server.settings.outbounds.*.socks5.password
Optional. The password for the SOCKS5 proxy, if authentication is required.
### Type
```
null or string
```
### Default
```nix
null
```
### Example 
```nix
"Elliot Alderson"
```
---
 
## services.hysteria.server.settings.outbounds.*.socks5.username
Optional. The username for the SOCKS5 proxy, if authentication is required.
### Type
```
null or string
```
### Default
```nix
null
```
### Example 
```nix
"hackerman"
```
---
 
## services.hysteria.server.settings.outbounds.*.type
Type of outbound
### Type
```
one of "direct", "socks5", "http"
```
### Default
```nix
"direct"
```
### Example 
```nix
"socks5"
```
---
 
## services.hysteria.server.settings.quic
The default stream and connection receive window sizes are 8MB and 20MB, respectively.
**We do not recommend changing these values unless you fully understand what you are doing.**
If you choose to change these values, we recommend keeping the ratio of stream receive window to connection receive window at 2:5.
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.server.settings.quic.disablePathMTUDiscovery
Disable QUIC path MTU discovery.
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.server.settings.quic.initConnReceiveWindow
The initial QUIC connection receive window size.
### Type
```
signed integer
```
### Default
```nix
20971520
```
---
 
## services.hysteria.server.settings.quic.initStreamReceiveWindow
The initial QUIC stream receive window size.
### Type
```
signed integer
```
### Default
```nix
8388608
```
---
 
## services.hysteria.server.settings.quic.maxConnReceiveWindow
The maximum QUIC connection receive window size.
### Type
```
signed integer
```
### Default
```nix
20971520
```
---
 
## services.hysteria.server.settings.quic.maxIdleTimeout
The maximum idle timeout.
How long the server will consider the client still connected without any activity.
### Type
```
string
```
### Default
```nix
"30s"
```
### Example 
```nix
"60s"
```
---
 
## services.hysteria.server.settings.quic.maxIncomingStreams
The maximum number of concurrent incoming streams.
### Type
```
signed integer
```
### Default
```nix
1024
```
### Example 
```nix
2048
```
---
 
## services.hysteria.server.settings.quic.maxStreamReceiveWindow
The maximum QUIC stream receive window size.
### Type
```
signed integer
```
### Default
```nix
8388608
```
---
 
## services.hysteria.server.settings.resolver
You can specify what **resolver** (DNS server) to use to resolve domain names in client requests.
If omitted, Hysteria will use the system's default **resolver**.
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.server.settings.resolver.https.addr
The address of the HTTPS resolver.
### Type
```
string
```
### Default
```nix
"1.1.1.1:443"
```
---
 
## services.hysteria.server.settings.resolver.https.insecure
Disable TLS verification for the TLS resolver.
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.server.settings.resolver.https.sni
The SNI to use for the TLS resolver.
### Type
```
string
```
### Default
```nix
"cloudflare-dns.com"
```
---
 
## services.hysteria.server.settings.resolver.https.timeout
The timeout for DNS queries.
### Type
```
string
```
### Default
```nix
"10s"
```
### Example 
```nix
"5s"
```
---
 
## services.hysteria.server.settings.resolver.tcp.addr
The address of the TCP resolver.
### Type
```
string
```
### Default
```nix
"8.8.8.8:53"
```
---
 
## services.hysteria.server.settings.resolver.tcp.timeout
The timeout for DNS queries.
### Type
```
string
```
### Default
```nix
"4s"
```
### Example 
```nix
"8s"
```
---
 
## services.hysteria.server.settings.resolver.tls.addr
The address of the TLS resolver.
### Type
```
string
```
### Default
```nix
"1.1.1.1:853"
```
---
 
## services.hysteria.server.settings.resolver.tls.insecure
Disable TLS verification for the TLS resolver.
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.server.settings.resolver.tls.sni
The SNI to use for the TLS resolver.
### Type
```
string
```
### Default
```nix
"cloudflare-dns.com"
```
---
 
## services.hysteria.server.settings.resolver.tls.timeout
The timeout for DNS queries.
### Type
```
string
```
### Default
```nix
"10s"
```
---
 
## services.hysteria.server.settings.resolver.type
Resolver type
### Type
```
one of "tcp", "udp", "tls", "https"
```
### Example 
```nix
"tls"
```
---
 
## services.hysteria.server.settings.resolver.udp.addr
The address of the UDP resolver.
### Type
```
string
```
### Default
```nix
"8.8.4.4:53"
```
---
 
## services.hysteria.server.settings.resolver.udp.timeout
The timeout for DNS queries.
### Type
```
string
```
### Default
```nix
"4s"
```
### Example 
```nix
"8s"
```
---
 
## services.hysteria.server.settings.speedTest
`speedTest` enables the built-in speed test server.
When enabled, clients can test their download and upload speeds with the server.
For more information, see the [Speed Test documentation](https://v2.hysteria.network/docs/advanced/Speed-Test/).
### Type
```
boolean
```
### Default
```nix
false
```
### Example 
```nix
true
```
---
 
## services.hysteria.server.settings.tls
Certificates are read on every TLS handshake.
This means you can update the files without restarting the server.
### Type
```
null or (submodule)
```
### Default
```nix
''
  (cfg.server.settings.acme != null) -> null
''
```
---
 
## services.hysteria.server.settings.tls.cert
TLS certificate
### Type
```
path
```
### Example 
```nix
"./some.crt"
```
---
 
## services.hysteria.server.settings.tls.key
TLS private key
### Type
```
path
```
### Example 
```nix
"./some.key"
```
---
 
## services.hysteria.server.settings.trafficStats
The Traffic Stats API allows you to query the server's traffic statistics and kick clients using an HTTP API.
For endpoints and usage, please refer to the [Traffic Stats API documentation](https://v2.hysteria.network/docs/advanced/Traffic-Stats-API/).
> NOTE: If you don't set a secret, anyone with access to your API listening address will be able to see traffic stats and kick users.
> We strongly recommend setting a secret, or at least using ACL to block users from accessing the API.
### Type
```
null or (submodule)
```
### Default
```nix
null
```
---
 
## services.hysteria.server.settings.trafficStats.listen
The address to listen on.
### Type
```
string
```
### Example 
```nix
":9999"
```
---
 
## services.hysteria.server.settings.trafficStats.secret
The secret key to use for authentication. Attach this to the `Authorization` header in your HTTP requests.
### Type
```
string
```
### Example 
```nix
"some_secret"
```
---
 
## services.hysteria.server.settings.udpIdleTimeout
`udpIdleTimeout` specifies the amount of time the server will keep a local UDP port open for each UDP session that has no activity.
This is conceptually similar to the NAT UDP session timeout.
### Type
```
string
```
### Default
```nix
"60s"
```
### Example 
```nix
"120s"
```
---
 
## services.hysteria.server.settingsFile
Path to file containing Hysteria settings.
### Type
```
null or path
```
### Default
```nix
null
```
---
 
## services.hysteria.server.user
Username of the Hysteria user
### Type
```
string
```
### Default
```nix
"hysteria-server"
```
---
