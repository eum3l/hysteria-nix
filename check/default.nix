{ testers, hysteria, ... }:
let
  password = "apfelmus";
in
testers.runNixOSTest {
  name = "hysteria";
  nodes = {
    machine =
      { ... }:
      {
        imports = [ hysteria ];
        services.hysteria = {
          server = {
            enable = true;
            settings = {
              sniff = {
                enable = true;
                tcpPorts = "all";
                udpPorts = "all";
              };
              tls = {
                cert = ./cert.crt;
                key = ./priv.key;
              };
              auth = {
                inherit password;
              };
            };
          };
          client = {
            enable = true;
            settings = {
              server = "127.0.0.1:443";
              tls.insecure = true;
              auth = password;
              socks5.listen = "127.0.0.1:1080";
              http.listen = "127.0.0.1:8080";
            };
          };
        };
      };
    loadtest =
      { ... }:
      {
        imports = [ hysteria ];
      };
  };

  testScript = ''
    machine.wait_for_unit("hysteria-server")
    machine.wait_for_unit("hysteria-client")
    for type in ["client", "server"]:
      machine.execute(f"journalctl -ru hysteria-{type} -o json > /tmp/hysteria-{type}.log")
      machine.copy_from_vm(f"/tmp/hysteria-{type}.log", ".")
      machine.copy_from_vm(f"/var/lib/hysteria-{type}/config.yaml", type)
  '';
}
