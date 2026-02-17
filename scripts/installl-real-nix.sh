#!/usr/bin/env bash

set -euxo pipefail

if [ -L /nix ]; then
  echo "fake nix detected, removing"
  rm /nix
  echo "installing real nix"
  sh <(curl --proto '=https' --tlsv1.2 -sSf -L https://nixos.org/nix/install) --no-daemon
elif  [ -d /nix ]; then
  echo "real nix detected, nothing to do"
elif [ -a /nix ]; then
  echo "/nix exists but is neither directory no symlink, unsure what is happening"
  exit 99
else
  echo "installing real nix"
  sh <(curl --proto '=https' --tlsv1.2 -sSf -L https://nixos.org/nix/install) --no-daemon
fi
