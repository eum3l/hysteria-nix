{
  lib,
  platforms,
  src,
  buildGoModule,
  go,
  runCommand,
  version,
  lastModifiedDate,
  rev,
}:
buildGoModule rec {
  inherit version src;
  pname = "hysteria";
  modRoot = "./app";
  vendorHash = "sha256-IRdC+imF4MwER9ZSH5vQnm3hu7jqNw5Pfi62JU6Y9l8=";
  env.GOWORK = "off";

  ldflags =
    let
      inherit (builtins)
        elemAt
        readFile
        split
        match
        ;
      cmd = "github.com/apernet/hysteria/app/v2/cmd";
      goVersion = (
        elemAt (match ".*(go.*)\n" (
          readFile (runCommand "go-version.txt" { } "${go}/bin/go version > $out")
        )) 0
      );
      goPlatform = index: elemAt (split "/" (elemAt (split " " goVersion) 2)) index;

    in
    [
      "-s"
      "-w"
    ]
    ++ builtins.map (list: "-X '${cmd}.${builtins.elemAt list 0}=${builtins.elemAt list 1}'") [
      [
        "appVersion"
        version
      ]
      [
        "appDate"
        lastModifiedDate
      ]
      [
        "appType"
        "release"
      ]
      [
        "appCommit"
        rev
      ]
      [
        "appPlatform"
        (goPlatform 0)
      ]
      [
        "appArch"
        (goPlatform 2)
      ]
      [
        "libVersion"
        (elemAt (split "\n" (
          elemAt (match ".*github.com\/apernet\/quic-go (.*)" (readFile (src + "/core/go.mod"))) 0
        )) 0)
      ]
      [
        "appToolchain"
        goVersion
      ]
    ];

  patchPhase = ''
    rm app/internal/http/server_test.go \
       app/internal/sockopts/sockopts_linux_test.go \
       app/internal/socks5/server_test.go \
       app/internal/utils/certloader_test.go
  '';

  postInstall = ''
    mv $out/bin/app $out/bin/hysteria
  '';

  meta = with lib; {
    inherit platforms;
    mainProgram = "hysteria";
    description = "A powerful, lightning fast and censorship resistant proxy.";
    homepage = "https://v2.hysteria.network/";
    license = licenses.mit;
  };
}
