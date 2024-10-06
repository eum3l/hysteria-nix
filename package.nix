{
  lib,
  platforms,
  src,
  buildGoModule,
  system,
  version,
  lastModifiedDate,
  rev,
}:
buildGoModule rec {
  inherit version src;
  pname = "hysteria";
  modRoot = "./app";
  vendorHash = "sha256-IKcgfyeiQ+JbeKdnpM+MfEJ5hcAPMn0rLhsLqbcmXSY=";
  env.GOWORK = "off";

  ldflags =
    let
      cmd = "github.com/apernet/hysteria/app/v2/cmd";
      pla-arc = index: builtins.elemAt (builtins.split "-" system) index;
    in
    [
      "-s"
      "-w"
      "-X ${cmd}.appVersion=${version}"
      "-X ${cmd}.appDate=${lastModifiedDate}"
      "-X ${cmd}.appType=release"
      "-X ${cmd}.appCommit=${rev}"
      "-X ${cmd}.appPlatform=${pla-arc 2}"
      "-X ${cmd}.appArch=${pla-arc 0}"
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
