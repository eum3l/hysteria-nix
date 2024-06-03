packages:
{
  lib,
  config,
  pkgs,
  ...
}:
let
  inherit (lib) optionals mkIf optionalAttrs;
  cfg = config.services.hysteria;
  mkFormatsOption =
    options:
    lib.mkOption (
      options
      // (optionalAttrs (!(options ? default)) {
        default = null;
        type = lib.types.nullOr options.type;
      })
    );
in
with lib.types;
{
  meta.maintainers = with lib.maintainers; [ eum3l ];
  imports =
    let
      mkHysteria =
        type:
        (
          let
            format = pkgs.formats.yaml { };
            cfg = config.services.hysteria.${type};
            settings =
              if cfg.settings != null then
                format.generate "hysteria-${type}-config.yaml" cfg.settings
              else
                cfg.settingsFile;
          in
          {
            boot.kernel.sysctl = mkIf (type == "client") (
              optionalAttrs (cfg.settings.tun != null) {
                "net.ipv4.conf.default.rp_filter" = 2;
                "net.ipv4.conf.all.rp_filter" = 2;
              }
            );

            networking.firewall.allowedTCPPorts =
              let
                getPort = address: lib.toInt (builtins.elemAt (builtins.split ":" address) 2);
              in
              mkIf (type == "server" && cfg.openFirewall) (
                optionals (cfg.settings != null) (
                  [ (getPort cfg.settings.listen) ]
                  ++ (optionals (cfg.settings.masquerade != null) [
                    (getPort cfg.settings.masquerade.listenHTTP)
                    (getPort cfg.settings.masquerade.listenHTTPS)
                  ])
                )
              );

            security.wrappers."hysteria-${type}" = rec {
              owner = cfg.user;
              group = owner;
              capabilities = "cap_net_bind_service${lib.optionalString (type == "client") ",cap_net_admin"}+ep";
              source = "${cfg.package}/bin/hysteria";
            };

            systemd.services."hysteria-${type}" = {
              description = "Hysteria ${type}";
              wantedBy = [ "multi-user.target" ];
              after = [ "network.target" ];

              preStart = mkIf (settings != null) "ln -sf ${settings} config.yaml";

              script = ''
                ${config.security.wrapperDir}/hysteria-${type} ${type} \
                  --disable-update-check \
                  -f ${cfg.logFormat} \
                  -l ${cfg.logLevel} \
                  -c config.yaml
              '';

              serviceConfig = {
                WorkingDirectory = cfg.dir;
                Restart = "always";
                User = cfg.user;
              };
            };

            users = {
              groups.${cfg.user} = { };
              users.${cfg.user} = {
                description = "hysteria ${type} user";
                isSystemUser = true;
                group = cfg.user;
                home = cfg.dir;
                createHome = true;
                homeMode = "750";
              };
            };
          }
        );
    in
    [
      (mkIf cfg.client.enable (mkHysteria "client"))
      (mkIf cfg.server.enable (mkHysteria "server"))
      {
        assertions =
          let
            set = value: value != null;
          in
          mkIf (set cfg.server.settings) [
            (mkIf (set cfg.server.settings.acl) {
              assertion = (!set cfg.server.settings.acl.inline) && (!set cfg.server.settings.acl.file);
              message = ''
                You can either set `file` or `inline`, but not both. (server.settings.acl)
              '';
            })
            {
              assertion = !((set cfg.server.settings.tls) && (set cfg.server.settings.acme));
              message = ''
                You can either set `tls` or `acme`, but not both. (server.settings)
              '';
            }
          ];
      }
    ];

  options.services.hysteria =
    let
      defaultOptions = type: {
        enable = lib.mkEnableOption ''
          Hysteria (${type}, a powerful, lightning fast and censorship resistant proxy.
        '';

        package = lib.mkPackageOption packages.${pkgs.system} "hysteria" { default = "hysteria"; };

        settingsFile = mkFormatsOption {
          type = path;
          description = ''
            Path to file containing Hysteria settings.
          '';
        };

        logFormat = mkFormatsOption {
          description = ''
            Format of the logs.
          '';
          default = "json";
          example = "console";
          type = enum [
            "json"
            "console"
          ];
        };

        logLevel = mkFormatsOption {
          description = ''
            Level of the logs.
          '';
          default = "info";
          example = "warn";
          type = enum [
            "debug"
            "info"
            "warn"
            "error"
          ];
        };

        dir = mkFormatsOption {
          default = "/var/lib/hysteria-${type}";
          type = singleLineStr;
          description = ''
            Working directory of the OpenGFW service and home of `hysteria-${type}.user`.
          '';
        };

        user = mkFormatsOption {
          description = "Username of the Hysteria user";
          type = str;
          default = "hysteria-${type}";
        };
      };
      defaultSettings = {
        obfs = mkFormatsOption {
          description = ''
            By default, the Hysteria protocol mimics HTTP/3.
            If your network specifically blocks QUIC or HTTP/3 traffic (but not UDP in general), obfuscation can be used to work around this.
            We currently have an obfuscation implementation called "Salamander" that converts packets into seamingly random bytes with no pattern.
            This feature requires a password that must be identical on both the client and server sides.
          '';

          type = submodule {
            options = {
              type = mkFormatsOption {
                description = "Obfuscation type";
                default = "salamander";
                type = enum [ "salamander" ];
              };
              salamander = {
                password = mkFormatsOption {
                  example = "cry_me_a_r1ver";
                  description = ''
                    Replace with a strong password of your choice.
                  '';
                  type = str;
                };
              };
            };
          };
        };

        quic = mkFormatsOption {
          description = ''
            The default stream and connection receive window sizes are 8MB and 20MB, respectively.
            **We do not recommend changing these values unless you fully understand what you are doing.**
            If you choose to change these values, we recommend keeping the ratio of stream receive window to connection receive window at 2:5.
          '';

          type = submodule {
            options = {
              initStreamReceiveWindow = mkFormatsOption {
                description = "The initial QUIC stream receive window size.";
                default = 8388608;
                type = int;
              };
              maxStreamReceiveWindow = mkFormatsOption {
                description = "The maximum QUIC stream receive window size.";
                default = 8388608;
                type = int;
              };
              initConnReceiveWindow = mkFormatsOption {
                description = "The initial QUIC connection receive window size.";
                default = 20971520;
                type = int;
              };
              maxConnReceiveWindow = mkFormatsOption {
                description = "The maximum QUIC connection receive window size.";
                default = 20971520;
                type = int;
              };
              maxIdleTimeout = mkFormatsOption {
                description = ''
                  The maximum idle timeout.
                  How long the server will consider the client still connected without any activity.
                '';
                default = "30s";
                example = "60s";
                type = str;
              };
              maxIncomingStreams = mkFormatsOption {
                description = "The maximum number of concurrent incoming streams.";
                default = 1024;
                example = 2048;
                type = int;
              };
              disablePathMTUDiscovery = mkFormatsOption {
                description = "Disable QUIC path MTU discovery.";
                default = false;
                example = true;
                type = bool;
              };
            };
          };
        };
      };
    in
    {
      server = (defaultOptions "server") // {
        openFirewall = mkFormatsOption {
          description = ''
            Open the firewall for the Hysteria server.
          '';
          default = false;
          example = true;
          type = bool;
        };

        settings = mkFormatsOption {
          description = "Hysteria server settings";
          type = submodule {
            options = defaultSettings // {
              listen = mkFormatsOption {
                default = ":443";
                type = str;
                description = ''
                  The server's listen address.
                  When the IP address is omitted, the server will listen on all interfaces, both IPv4 and IPv6.
                  To listen on IPv4 only, you can use `0.0.0.0:443`.
                  To listen on IPv6 only, you can use `[::]:443`.
                '';
              };

              tls = mkFormatsOption {
                description = ''
                  Certificates are read on every TLS handshake.
                  This means you can update the files without restarting the server.
                '';

                type = submodule {
                  options = {
                    cert = mkFormatsOption {
                      example = "./some.crt";
                      description = "TLS certificate";
                      type = path;
                    };
                    key = mkFormatsOption {
                      example = "./some.key";
                      description = "TLS private key";
                      type = path;
                    };
                  };
                };
              };

              acme = mkFormatsOption {
                description = "ACME configuration.";
                type = submodule {
                  options = {
                    domains = mkFormatsOption {
                      example = [
                        "domain1.com"
                        "domain2.org"
                      ];
                      default = lib.attrNames config.security.acme.certs;
                      description = "Your domains";
                      type = listOf str;
                    };
                    email = mkFormatsOption {
                      example = "your@email.net";
                      default = config.security.acme.defaults.email;
                      description = "Your email address";
                      type = str;
                    };
                    ca = mkFormatsOption {
                      default = "letsencrypt";
                      example = "zerossl";
                      description = ''
                        The CA to use.
                      '';
                      type = enum [
                        "letsencrypt"
                        "zerossl"
                      ];
                    };
                    disableHTTP = mkFormatsOption {
                      default = false;
                      example = true;
                      description = "Disable HTTP challenge.";
                      type = bool;
                    };
                    disableTLSALPN = mkFormatsOption {
                      default = false;
                      example = true;
                      description = "Disable TLS-ALPN challenge.";
                      type = bool;
                    };
                    altHTTPPort = mkFormatsOption {
                      default = 80;
                      description = ''
                        Alternate HTTP challenge port.
                        (**Note**: If you want to use anything other than 80, you must set up port forward/HTTP reverse proxy from 80 to that port, otherwise ACME will not be able to issue the certificate.)
                      '';
                      type = int;
                    };
                    altTLSALPNPort = mkFormatsOption {
                      default = 443;
                      description = ''
                        Alternate TLS-ALPN challenge port.
                        (**Note**: If you want to use anything other than 443, you must set up port forward/SNI proxy from 443 to that port, otherwise ACME will not be able to issue the certificate.)
                      '';
                      type = int;
                    };
                    dir = mkFormatsOption {
                      default = "acme";
                      description = "The directory to store the ACME account key and certificates.";
                      type = str;
                    };
                    listenHost = mkFormatsOption {
                      default = "0.0.0.0";
                      example = "192.168.5.150";
                      description = ''
                        The host address (not including the port) to listen on for the ACME challenge.
                        If omitted, the server will listen on all interfaces.
                      '';
                      type = str;
                    };
                  };
                };
              };

              bandwidth = mkFormatsOption {
                description = ''
                  The bandwidth values on the server side act as speed limits, limiting the maximum rate at which the server will send and receive data (per client).
                  **Note that the server's upload speed is the client's download speed, and vice versa.**
                  You can omit these values or set them to zero on either or both sides, which would mean no limit.
                  Supported units are:
                  + bps or b (bits per second)
                  + kbps or kb or k (kilobits per second)
                  + mbps or mb or m (megabits per second)
                  + gbps or gb or g (gigabits per second)
                  + tbps or tb or t (terabits per second)
                '';

                type = submodule {
                  options = {
                    up = mkFormatsOption {
                      description = "The server's upload bandwidth.";
                      default = "1 gbps";
                      example = "0";
                      type = str;
                    };
                    down = mkFormatsOption {
                      description = "The server's download bandwidth.";
                      default = "1 gbps";
                      example = "0";
                      type = str;
                    };
                  };
                };
              };

              ignoreClientBandwidth = mkFormatsOption {
                description = ''
                  `ignoreClientBandwidth` is a special option that, when enabled, makes the server to disregard any bandwidth hints set by clients,
                  opting to use a more traditional congestion control algorithm (currently BBR) instead.
                  This effectively overrides any bandwidth values set by clients in both directions.
                  This feature is primarily useful for server owners who prefer congestion fairness over other network traffic,
                  or who do not trust users to accurately set their own bandwidth values.
                  [Bandwidth negotiation process](https://v2.hysteria.network/docs/advanced/Full-Server-Config/#bandwidth-negotiation-process)
                '';
                default = false;
                example = true;
                type = bool;
              };

              speedTest = mkFormatsOption {
                description = ''
                  `speedTest` enables the built-in speed test server.
                  When enabled, clients can test their download and upload speeds with the server.
                  For more information, see the [Speed Test documentation](https://v2.hysteria.network/docs/advanced/Speed-Test/).
                '';
                default = false;
                example = true;
                type = bool;
              };

              disableUDP = mkFormatsOption {
                description = ''
                  `disableUDP` disables UDP forwarding, only allowing TCP connections.
                '';
                example = true;
                default = false;
                type = bool;
              };

              udpIdleTimeout = mkFormatsOption {
                description = ''
                  `udpIdleTimeout` specifies the amount of time the server will keep a local UDP port open for each UDP session that has no activity.
                  This is conceptually similar to the NAT UDP session timeout.
                '';
                default = "60s";
                example = "120s";
                type = str;
              };

              auth = mkFormatsOption {
                description = ''
                  Authentication payload:
                  ```json
                    {
                       "addr": "123.123.123.123:44556",
                       "auth": "something_something",
                       "tx": 123456
                    }
                  ```
                '';
                type = submodule {
                  options = {
                    type = mkFormatsOption {
                      description = "Authentication type.";
                      default = "password";
                      example = "userpass";
                      type = enum [
                        "password"
                        "userpass"
                        "http"
                        "command"
                      ];
                    };
                    password = mkFormatsOption {
                      description = "Replace with a strong password of your choice.";
                      example = "your_password";

                      type = str;
                    };
                    userpass = mkFormatsOption {
                      description = "A map of username-password pairs.";
                      example = {
                        user1 = "pass1";
                        user2 = "pass2";
                        user3 = "pass3";
                      };

                      type = attrsOf str;
                    };
                    http = mkFormatsOption {
                      description = ''
                        When using HTTP authentication, the server will send a `POST` request to the backend server with the authentication payload when a client attempts to connect.
                        Your endpoint must respond with a JSON object with the following fields:
                        ```json
                        {
                          "ok": true,
                            "id": "john_doe"
                        }
                        ```
                        > NOTE: The HTTP status code must be 200 for the authentication to be considered successful.
                      '';

                      type = submodule {
                        options = {
                          url = mkFormatsOption {
                            description = ''
                              The URL of the backend server that handles authentication.
                            '';
                            example = "http://your.backend.com/auth";
                            type = str;
                          };
                          insecure = mkFormatsOption {
                            description = ''
                              Disable TLS verification for the backend server (only applies to HTTPS URLs).
                            '';
                            example = true;
                            default = false;
                            type = bool;
                          };
                        };
                      };
                    };
                    command = mkFormatsOption {
                      description = ''
                        The path to the command that handles authentication.
                        When using command authentication,
                        the server will execute the specified command with the following arguments from the authentication payload when a client attempts to connect:
                        ```
                        /etc/some_command addr auth tx
                        ```
                        The command must print the client's unique identifier to `stdout` and return with exit code 0 if the client is allowed to connect,
                        or return with a non-zero exit code if the client is rejected.
                        If the command fails to execute, the client will be rejected.
                      '';
                      example = "/etc/some_command";

                      type = str;
                    };
                  };
                };
              };

              resolver = mkFormatsOption {
                description = ''
                  You can specify what **resolver** (DNS server) to use to resolve domain names in client requests.
                  If omitted, Hysteria will use the system's default **resolver**.
                '';
                type = submodule {
                  options =
                    let
                      timeoutDescription = "The timeout for DNS queries.";
                      sniDescription = "The SNI to use for the TLS resolver.";
                      insecureDescription = "Disable TLS verification for the TLS resolver.";
                    in
                    {
                      type = mkFormatsOption {
                        description = "Resolver type";
                        example = "tls";
                        type = enum [
                          "tcp"
                          "udp"
                          "tls"
                          "https"
                        ];
                      };
                      tcp = {
                        addr = mkFormatsOption {
                          description = "The address of the TCP resolver.";
                          default = "8.8.8.8:53";
                          type = str;
                        };
                        timeout = mkFormatsOption {
                          description = timeoutDescription;
                          default = "4s";
                          example = "8s";
                          type = str;
                        };
                      };
                      udp = {
                        addr = mkFormatsOption {
                          description = "The address of the UDP resolver.";
                          default = "8.8.4.4:53";
                          type = str;
                        };
                        timeout = mkFormatsOption {
                          description = timeoutDescription;
                          default = "4s";
                          example = "8s";
                          type = str;
                        };
                      };
                      tls = {
                        addr = mkFormatsOption {
                          description = "The address of the TLS resolver.";
                          default = "1.1.1.1:853";
                          type = str;
                        };
                        timeout = mkFormatsOption {
                          description = timeoutDescription;
                          default = "10s";
                          type = str;
                        };
                        sni = mkFormatsOption {
                          default = "cloudflare-dns.com";
                          description = sniDescription;
                          type = str;
                        };
                        insecure = mkFormatsOption {
                          description = insecureDescription;
                          default = false;
                          example = true;
                          type = bool;
                        };
                      };
                      https = {
                        addr = mkFormatsOption {
                          description = "The address of the HTTPS resolver.";
                          default = "1.1.1.1:443";
                          type = str;
                        };
                        timeout = mkFormatsOption {
                          description = timeoutDescription;
                          default = "10s";
                          example = "5s";
                          type = str;
                        };
                        sni = mkFormatsOption {
                          description = sniDescription;
                          default = "cloudflare-dns.com";
                          type = str;
                        };
                        insecure = mkFormatsOption {
                          description = insecureDescription;
                          default = false;
                          example = true;
                          type = bool;
                        };
                      };
                    };
                };
              };

              acl = mkFormatsOption {
                description = ''
                  ACL, often used in combination with outbounds, is a very powerful feature of the Hysteria server that allows you to customize the way client's requests are handled.
                  For example, you can use ACL to block certain addresses, or to use different outbounds for different websites.
                  For details on syntax, usage and other information, please refer to the [ACL documentation](https://v2.hysteria.network/docs/advanced/ACL/).
                  You can have either `file` or `inline`, but not both.

                  > NOTE: Hysteria currently uses the protobuf-based "dat" format for geoip/geosite data originating from v2ray.
                  > If you don't need any customization, you can omit the `geoip` or `geosite` fields and let Hysteria automatically download the latest version [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) to your working directory.
                  > The files will only be downloaded and used if your ACL has at least one rule that uses this feature.
                '';

                type = submodule {
                  options = {
                    file = mkFormatsOption {
                      description = "The path to the ACL file.";
                      example = "./some.txt";

                      type = path;
                    };
                    inline = mkFormatsOption {
                      description = "The list of inline ACL rules. [ACL documentation](https://v2.hysteria.network/docs/advanced/ACL/)]";

                      example = [
                        "reject(suffix:v2ex.com)"
                        "reject(all, udp/443)"
                        "reject(geoip:cn)"
                        "reject(geosite:netflix)"
                      ];
                      type = listOf str;
                    };
                    geoip = mkFormatsOption {
                      description = ''
                        Optional. The path to the GeoIP database file.
                        If this field is omitted, Hysteria will automatically download the latest database to your working directory.
                      '';
                      example = "./geoip.dat";

                      type = path;
                    };
                    geosite = mkFormatsOption {
                      description = ''
                        Optional. The path to the GeoSite database file.
                        If this field is omitted, Hysteria will automatically download the latest database to your working directory.
                      '';
                      example = "./geosite.dat";

                      type = path;
                    };
                    geoUpdateInterval = mkFormatsOption {
                      description = ''
                        Optional. The interval at which to refresh the GeoIP/GeoSite databases.
                        168 hours (1 week) by default. Only applies if the GeoIP/GeoSite databases are automatically downloaded.
                        > Hysteria currently only downloads the GeoIP/GeoSite databases once at startup.
                        > You will need to use external tools to periodically restart the Hysteria server in order to update the databases regularly through geoUpdateInterval.
                        > This may change in future versions.
                      '';
                      default = "168h";
                      example = "100h";
                      type = str;
                    };
                  };
                };
              };
              outbounds = mkFormatsOption {
                description = ''
                  Outbounds are used to define the "exit" through which a connection should be routed.
                  For example, when [combined with ACL](https://v2.hysteria.network/docs/advanced/ACL/),
                  you can route all traffic except Netflix directly through the local interface, while routing Netflix traffic through a SOCKS5 proxy.
                  Currently, Hysteria supports the following outbound types:
                  + direct: Direct connection through the local interface.
                  + socks5: SOCKS5 proxy.
                  + http: HTTP/HTTPS proxy.

                  > NOTE: HTTP/HTTPS proxies do not support UDP at the protocol level. Sending UDP traffic to HTTP outbounds will result in rejection.

                  **If you do not use ACL, all connections will always be routed through the first ("default") outbound in the list, and all other outbounds will be ignored.**
                '';

                example = [
                  {
                    name = "my_outbound_1";
                    type = "direct";
                  }
                  {
                    name = "my_outbound_2";
                    type = "socks5";
                    socks5 = {
                      addr = "shady.proxy.ru:1080";
                      username = "hackerman";
                      password = "Elliot Alderson";
                    };
                  }
                  {
                    name = "my_outbound_3";
                    type = "http";
                    http = {
                      url = "http://username:password@sketchy-proxy.cc:8081";
                      insecure = false;
                    };
                  }
                  {
                    name = "hoho";
                    type = "direct";
                    direct = {
                      mode = "auto";
                      bindIPv4 = "2.4.6.8";
                      bindIPv6 = "0:0:0:0:0:ffff:0204:0608";
                      bindDevice = "eth233";
                    };
                  }
                ];

                type = listOf (submodule {
                  options = {
                    name = mkFormatsOption {
                      description = "The name of the outbound. This is used in ACL rules.";
                      example = "my_outbound_1";
                      type = str;
                    };
                    type = mkFormatsOption {
                      description = "Type of outbound";
                      default = "direct";
                      example = "socks5";
                      type = enum [
                        "direct"
                        "socks5"
                        "http"
                      ];
                    };
                    socks5 = {
                      addr = mkFormatsOption {
                        description = "The address of the SOCKS5 proxy.";
                        example = "shady.proxy.ru:1080";
                        type = str;
                      };
                      username = mkFormatsOption {
                        description = "Optional. The username for the SOCKS5 proxy, if authentication is required.";
                        example = "hackerman";

                        type = str;
                      };
                      password = mkFormatsOption {
                        description = "Optional. The password for the SOCKS5 proxy, if authentication is required.";
                        example = "Elliot Alderson";

                        type = str;
                      };
                    };
                    http = {
                      url = mkFormatsOption {
                        description = "The URL of the HTTP/HTTPS proxy. (Can be `http://` or `https://`)";
                        example = "http://username:password@sketchy-proxy.cc:8081";
                        type = str;
                      };
                      insecure = mkFormatsOption {
                        description = "Optional. Whether to disable TLS verification. Applies to HTTPS proxies only.";
                        default = false;
                        example = true;
                        type = bool;
                      };
                    };
                    direct = mkFormatsOption {
                      description = ''
                        The direct outbound has a few additional options that can be used to customize its behavior:
                        > NOTE: The options `bindIPv4`, `bindIPv6`, and `bindDevice` are mutually exclusive.
                        > You can either specify `bindIPv4` and/or `bindIPv6` without `bindDevice`, or use `bindDevice` without `bindIPv4` and `bindIPv6`.
                      '';
                      type = submodule {
                        options = {
                          mode = mkFormatsOption {
                            description = ''
                              The available mode values are:
                              + `auto`: Default. Dual-stack "happy eyeballs" mode. The client will attempt to connect to the destination using both IPv4 and IPv6 addresses (if available), and use the first one that succeeds.
                              + `64`: Always use IPv6 if available, otherwise use IPv4.
                              + `46`: Always use IPv4 if available, otherwise use IPv6.
                              + `6`: Always use IPv6. Fail if no IPv6 address is available.
                              + `4`: Always use IPv4. Fail if no IPv4 address is available.
                            '';
                            default = "auto";
                            type = enum [
                              "auto"
                              "64"
                              "46"
                              "6"
                              "4"
                            ];
                          };
                          bindIPv4 = mkFormatsOption {
                            example = "2.4.6.8";
                            description = "The local IPv4 address to bind to.
";
                            type = str;
                          };
                          bindIPv6 = mkFormatsOption {
                            example = "0:0:0:0:0:ffff:0204:0608";
                            description = "The local IPv6 address to bind to.
";
                            type = str;
                          };
                          bindDevice = mkFormatsOption {
                            example = "eth233";
                            description = "The local network interface to bind to.
";
                            type = str;
                          };
                        };
                      };
                    };
                  };
                });
              };

              trafficStats = mkFormatsOption {
                description = ''
                  The Traffic Stats API allows you to query the server's traffic statistics and kick clients using an HTTP API.
                  For endpoints and usage, please refer to the [Traffic Stats API documentation](https://v2.hysteria.network/docs/advanced/Traffic-Stats-API/).
                  > NOTE: If you don't set a secret, anyone with access to your API listening address will be able to see traffic stats and kick users.
                  > We strongly recommend setting a secret, or at least using ACL to block users from accessing the API.
                '';

                type = submodule {
                  options = {
                    listen = mkFormatsOption {
                      description = "The address to listen on.";
                      example = ":9999";
                      type = str;
                    };
                    secret = mkFormatsOption {
                      description = "The secret key to use for authentication. Attach this to the `Authorization` header in your HTTP requests.";
                      example = "some_secret";
                      type = str;
                    };
                  };
                };
              };

              masquerade = mkFormatsOption {
                description = ''
                  One of the keys to Hysteria's censorship resistance is its ability to masquerade as standard HTTP/3 traffic.
                  This means that not only do the packets appear as HTTP/3 to middleboxes, but the server also responds to HTTP requests like a regular web server.
                  However, this means that your server must actually serve some content to make it appear authentic to potential censors.
                  **If censorship is not a concern, you can omit the masquerade section entirely. In this case, Hysteria will always return "404 Not Found" for all HTTP requests.**
                  Currently, Hysteria provides the following masquerade modes:
                  + `file`: Act as a static file server, serving files from a directory.
                  + `proxy`: Act as a reverse proxy, serving content from another website.
                  + `string`: Act as a server that always returns a user-supplied string.

                  [HTTP/HTTPS Masquerading documentation](https://v2.hysteria.network/docs/advanced/Full-Server-Config/#httphttps-masquerading)
                '';

                type = submodule {
                  options = {
                    type = mkFormatsOption {
                      description = "Masquerade type";
                      example = "string";
                      default = "proxy";
                      type = enum [
                        "file"
                        "proxy"
                        "string"
                      ];
                    };
                    file.dir = mkFormatsOption {
                      description = "The directory to serve files from.";
                      example = "/www/masq";
                      type = path;
                    };
                    proxy = mkFormatsOption {
                      description = ''
                        Use a proxy for masquerading.
                      '';

                      type = submodule {
                        options = {
                          url = mkFormatsOption {
                            description = "The URL of the website to proxy.";
                            example = "https://some.site.net";
                            type = str;
                          };
                          rewriteHost = mkFormatsOption {
                            description = ''
                              Whether to rewrite the Host header to match the proxied website.
                              This is required if the target web server uses Host to determine which site to serve.
                            '';
                            example = true;
                            default = false;
                            type = bool;
                          };
                        };
                      };
                    };
                    string = mkFormatsOption {
                      description = ''
                        Use a string for masquerading.
                      '';

                      type = submodule {
                        options = {
                          content = mkFormatsOption {
                            description = "The string to return.";
                            example = "hello stupid world";
                            type = str;
                          };
                          headers = mkFormatsOption {
                            description = "Optional. The headers to return.";

                            type = attrsOf str;
                          };
                          statusCode = mkFormatsOption {
                            description = "Optional. The status code to return.";
                            default = 200;
                            example = 404;
                            type = int;
                          };
                        };
                      };
                    };
                    listenHTTP = mkFormatsOption {
                      description = "HTTP (TCP) listen address.";
                      default = ":80";
                      type = str;
                    };
                    listenHTTPS = mkFormatsOption {
                      description = "HTTPS (TCP) listen address.";
                      default = ":443";
                      type = str;
                    };
                    forceHTTPS = mkFormatsOption {
                      description = ''
                        Whether to force HTTPS.
                        If enabled, all HTTP requests will be redirected to HTTPS.
                      '';
                      example = false;
                      default = true;
                      type = bool;
                    };
                  };
                };
              };
            };
          };
        };
      };
      client = (defaultOptions "client") // {
        settings = mkFormatsOption {
          description = "Hysteria client settings";
          type = submodule {
            options = defaultSettings // {
              server = mkFormatsOption {
                description = ''
                  The server field specifies the address of the Hysteria server that the client should connect to.
                  The address can be formatted as either `host:port` or just `host`. If the port is omitted, it defaults to 443.
                  You also have the option to use a Hysteria 2 URI (`hysteria2://`).
                  In this case, because the URI already includes the password and certain other settings, you don't (and can't) specify them separately in the configuration file.
                '';
                type = str;
                example = "example.com";
              };
              auth = mkFormatsOption {
                description = "If the server uses the `userpass` authentication, the format must be `username:password`.";
                type = str;
                example = "some_password";
              };
              tls = mkFormatsOption {
                description = "TLS client settings";

                type = submodule {
                  options = {
                    sni = mkFormatsOption {
                      description = ''
                        Server name to use for TLS verification.
                        If omitted, the server name will be extracted from the `server` field.
                      '';
                      type = str;

                      example = "another.example.com";
                    };
                    insecure = mkFormatsOption {
                      description = "Disable TLS verification.";
                      type = bool;
                      default = false;
                      example = true;
                    };
                    pinSHA256 = mkFormatsOption {
                      description = ''
                        Verify the server's certificate fingerprint.
                        You can obtain the fingerprint of your certificate using openssl:
                        `openssl x509 -noout -fingerprint -sha256 -in your_cert.crt`
                      '';
                      type = str;

                      example = "BA:88:45:17:A1...";
                    };
                    ca = mkFormatsOption {
                      description = "Use a custom CA certificate for TLS verification.";
                      type = path;

                      example = "custom_ca.crt";
                    };
                  };
                };
              };
              transport = mkFormatsOption {
                description = ''
                  The `transport` section is for customizing the underlying protocol used by the QUIC connection.
                  Currently the only type available is `udp`, but we reserve it for possible future expansions.
                '';

                type = submodule {
                  options = {
                    options = {
                      type = mkFormatsOption {
                        description = "Transport type selection";
                        type = enum [ "udp" ];
                        default = "udp";
                      };
                      udp = {
                        hopInterval = mkFormatsOption {
                          description = ''
                            The port hopping interval.
                            This is only relevant if you're using a port hopping address.
                            See [Port Hopping](https://v2.hysteria.network/docs/advanced/Port-Hopping/) for more information.
                          '';
                          type = str;
                          default = "30s";
                          example = "60s";
                        };
                      };
                    };
                  };
                };
              };
              quic.sockopts = {
                bindInterface = mkFormatsOption {
                  description = "Forces QUIC packets to be sent through this interface.";
                  type = str;

                  example = "eth0";
                };
                fwmark = mkFormatsOption {
                  description = "The `SO_MARK` tag to be added to QUIC packets.";

                  example = 1234;
                  type = int;
                };
                fdControlUnixSocket = mkFormatsOption {
                  description = ''
                    Path to a Unix Socket that is listened to by other processes.
                    The Hysteria client will send the file descriptor (FD) used for the QUIC connection as ancillary information to this Unix Socket,
                    allowing the listening process to perform other custom configurations.
                    This option can be used in Android client development; please refer to the [FD Control Protocol](https://v2.hysteria.network/docs/advanced/FD-Control/) for more details.
                  '';
                  example = "./test.sock";

                  type = str;
                };
              };
              bandwidth = mkFormatsOption {
                description = ''
                  Hysteria has two built-in congestion control algorithms (BBR & Brutal).
                  Which one to use depends on whether bandwidth information is provided.
                  If you want to use BBR instead of Brutal, you can delete the entire bandwidth section.
                  For more details, see [Bandwidth negotiation process](https://v2.hysteria.network/docs/advanced/Full-Server-Config/#bandwidth-negotiation-process) and [Congestion control details](https://v2.hysteria.network/docs/advanced/Full-Server-Config/#congestion-control-details).

                  > ⚠️ **Warning** Higher bandwidth values are not always better; be very careful not to exceed the maximum bandwidth that your current network can support.
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
                '';
                type = submodule {
                  options = {
                    up = mkFormatsOption {
                      description = "The client's upload bandwidth.";
                      default = "100 mbps";
                      example = "50 mbps";
                      type = str;
                    };
                    down = mkFormatsOption {
                      description = "The client's download bandwidth.";
                      default = "200 mbps";
                      example = "500 mbps";
                      type = str;
                    };
                  };
                };
              };
              fastOpen = mkFormatsOption {
                description = ''
                  Fast Open can shave one roundtrip time (RTT) off each connection,
                  but at the cost of the correct semantics of SOCKS5/HTTP proxy protocols.
                  When this is enabled, the client always immediately accepts a connection without confirming with the server that the destination is reachable.
                  If the server then fails or rejects the connection, the client will simply close the connection without sending any data back to the proxy client.
                '';
                default = false;
                example = true;
                type = bool;
              };
              lazy = mkFormatsOption {
                description = ''
                  When enabled, the client is "lazy" in the sense that it will only attempt to connect to the server if there is an incoming connection from one of the enabled client modes.
                  This differs from the default behavior, where the client attempts to connect to the server as soon as it starts up.
                  The `lazy` option can be useful if you're unsure when you'll use the client and want to avoid idle connections.
                  It's also useful if your Internet connection might not be ready when you start the Hysteria client.
                '';
                default = false;
                example = true;
                type = bool;
              };
              socks5 = mkFormatsOption {
                description = ''
                  A SOCKS5 proxy server that can be used with any SOCKS5-compatible application.
                  Supports both TCP and UDP.
                '';
                type = submodule {
                  options = {
                    listen = mkFormatsOption {
                      description = "The address to listen on.";
                      example = "127.0.0.1:1080";
                      type = str;
                    };
                    username = mkFormatsOption {
                      description = "Optional. The username to require for authentication.";
                      example = "user";

                      type = str;
                    };
                    password = mkFormatsOption {
                      description = "Optional. The password to require for authentication.";
                      example = "pass";

                      type = str;
                    };
                    disableUDP = mkFormatsOption {
                      description = "Optional. Disable UDP support.";
                      default = false;
                      example = true;
                      type = bool;
                    };
                  };
                };
              };
              http = mkFormatsOption {
                description = ''
                  An HTTP proxy server that can be used with any HTTP proxy-compatible application.
                  Supports both plaintext HTTP and HTTPS (CONNECT).
                '';

                type = submodule {
                  options = {
                    listen = mkFormatsOption {
                      description = "The address to listen on.";
                      example = "127.0.0.1:8080";
                      type = str;
                    };
                    username = mkFormatsOption {
                      description = "Optional. The username to require for authentication.";
                      example = "king";

                      type = str;
                    };
                    password = mkFormatsOption {
                      description = "Optional. The password to require for authentication.";
                      example = "kong";

                      type = str;
                    };
                    realm = mkFormatsOption {
                      description = "Optional. The realm to require for authentication.";
                      example = "martian";

                      type = str;
                    };
                  };
                };
              };
              tcpForwarding = mkFormatsOption {
                description = ''
                  TCP Forwarding allows you to forward one or more TCP ports from the server (or any remote host) to the client.
                  This is useful, for example, if you want to access a service that is only available on the server's network.
                '';

                type = listOf (submodule {
                  options = {
                    listen = mkFormatsOption {
                      description = "The address to listen on.";
                      example = "127.0.0.1:6600";
                      type = str;
                    };
                    remote = mkFormatsOption {
                      description = "The address to forward to.";
                      example = "other.machine.internal:6601";
                      type = str;
                    };
                  };
                });
              };
              udpForwarding = mkFormatsOption {
                description = ''
                  UDP Forwarding allows you to forward one or more UDP ports from the server (or any remote host) to the client.
                  This is useful, for example, if you want to access a service that is only available on the server's network.
                '';

                type = listOf (submodule {
                  options = {
                    listen = mkFormatsOption {
                      description = "The address to listen on.";
                      example = "127.0.0.1:6600";
                      type = str;
                    };
                    remote = mkFormatsOption {
                      description = "The address to forward to.";
                      example = "other.machine.internal:5301";
                      type = str;
                    };
                    timeout = mkFormatsOption {
                      description = ''
                        Optional. The timeout for each UDP session.
                        If omitted, the default timeout is 60 seconds.
                      '';
                      default = "60s";
                      example = "20s";
                      type = str;
                    };
                  };
                });
              };
              tcpTProxy = mkFormatsOption {
                description = ''
                  TPROXY (transparent proxy) is a Linux-specific feature that allows you to transparently proxy TCP connections.
                  For information, please refer to [Setting up TPROXY](https://v2.hysteria.network/docs/advanced/TPROXY/).
                '';

                type = submodule {
                  options = {
                    listen = mkFormatsOption {
                      description = "The address to listen on.";
                      example = ":2500";
                      type = str;
                    };
                  };
                };
              };
              udpTProxy = mkFormatsOption {
                description = ''
                  TPROXY (transparent proxy) is a Linux-specific feature that allows you to transparently proxy UDP connections.
                  For information, please refer to [Setting up TPROXY](https://v2.hysteria.network/docs/advanced/TPROXY/).
                '';

                type = submodule {
                  options = {
                    listen = mkFormatsOption {
                      description = "The address to listen on.";
                      example = ":2500";
                      type = str;
                    };
                    timeout = mkFormatsOption {
                      description = ''
                        Optional. The timeout for each UDP session.
                        If omitted, the default timeout is 60 seconds.
                      '';
                      default = "60s";
                      example = "20s";
                      type = str;
                    };
                  };
                };
              };
              tcpRedirect = mkFormatsOption {
                description = ''
                  REDIRECT is essentially a special case of DNAT where the destination address is localhost.
                  This method predates TPROXY as an older way to implement a TCP transparent proxy.
                  We recommend using TPROXY instead if your kernel supports it.
                  [Example](https://v2.hysteria.network/docs/advanced/Full-Client-Config/#tcp-redirect-linux-only)
                '';

                type = submodule {
                  options = {
                    listen = mkFormatsOption {
                      description = "The address to listen on.";
                      example = ":2500";
                      type = str;
                    };
                  };
                };
              };
              tun = mkFormatsOption {
                description = ''
                  TUN mode is a cross-platform transparent proxy solution that creates a virtual network interface in the system and uses the system's routes to capture and redirect traffic.
                  It currently works on Windows, Linux, and macOS.
                  Unlike traditional L3 VPNs (such as WireGuard and OpenVPN), Hysteria's TUN mode can only handle TCP and UDP and does not support other protocols including ICMP (e.g. ping).
                  It also takes control of the TCP stack to speed up TCP connections.
                  Compared to Hysteria 1's implementation, Hysteria 2's TUN is based on sing-tun's "system" stack,
                  requiring a /30 IPv4 address and a /126 IPv6 address to be configured on the interface.
                  Hysteria will automatically set up the network interface, addresses, and routes.
                  > NOTE: ipv4Exclude/ipv6Exclude is important to avoid getting a routing loop. See the comments for these fields for more information.
                '';

                type = submodule {
                  options = {
                    name = mkFormatsOption {
                      description = "The name of the TUN interface.";
                      example = "hytun";
                      type = str;
                    };
                    mtu = mkFormatsOption {
                      description = "Optional. The maximum packet size accepted by the TUN interface.";
                      default = 1500;
                      type = int;
                    };
                    timeout = mkFormatsOption {
                      description = "Optional. UDP session timeout.";
                      default = "5m";
                      example = "10m";
                      type = str;
                    };
                    address = mkFormatsOption {
                      description = ''
                        Optional. Addresses to use on the interface.
                        Set to any private address that does not conflict with your LAN.
                        The defaults are as shown.
                      '';

                      type = submodule {
                        options = {
                          ipv4 = mkFormatsOption {
                            description = "The IPv4 address to use.";
                            example = "100.100.100.101/30";
                            type = str;
                          };
                          ipv6 = mkFormatsOption {
                            description = "The IPv6 address to use.";
                            example = "2001::ffff:ffff:ffff:fff1/126";
                            type = str;
                          };
                        };
                      };
                    };
                    route = mkFormatsOption {
                      description = ''
                        Optional. Routing rules. Omitting or skipping all fields means that no routes will be added automatically.
                        In most cases, just having `ipv4Exclude` or `ipv6Exclude` is enough.
                      '';

                      type = submodule {
                        options = {
                          ipv4 = mkFormatsOption {
                            description = ''
                              Optional. IPv4 prefix to proxy.
                              If any other field is configured, the default is 0.0.0.0/0.
                            '';
                            type = listOf str;
                            example = [ "0.0.0.0/0" ];
                          };
                          ipv6 = mkFormatsOption {
                            description = ''
                              Optional. IPv6 prefix to proxy.
                              Due to YAML limitations, quotes are required.
                              If any other field is configured, the default is ::/0.
                            '';
                            type = listOf str;
                            example = [ "2000::/3" ];
                          };
                          ipv4Exclude = mkFormatsOption {
                            description = ''
                              Optional. IPv4 prefix to exclude.
                              **Add your Hysteria server address here to avoid a routing loop.**
                              If you want to disable IPv4 proxying completely, you can also put `0.0.0.0/0` here.
                            '';
                            example = [ "192.0.2.1/32" ];
                            type = listOf str;
                          };
                          ipv6Exclude = mkFormatsOption {
                            description = ''
                              Optional. IPv6 prefix to exclude.
                              Due to YAML limitations, quotes are required.
                              **Add your Hysteria server address here to avoid a routing loop.**
                              If you want to disable IPv6 proxying completely, you can also put `"::/0"` here.
                            '';
                            example = [ "2001:db8::1/128" ];
                            type = listOf str;
                          };
                        };
                      };
                    };
                  };
                };
              };
            };
          };
        };
      };
    };
}
