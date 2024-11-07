{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  packages = with pkgs; [
    python311
    (poetry.override { python3 = python311; })
  ];
  shellHook = ''
    source .venv/bin/activate
  '';
}
