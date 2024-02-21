#!/usr/bin/env bash
set -euxo pipefail

if [ "$1" != "sync" ] && [ "$1" != "verify" ]; then
  echo "Usage: $0 <sync|verify>"
  exit
fi

cargo build --release --bin near-light-clientx --features $1
cp -f target/release/near-light-clientx build/$1 || true
export RUST_LOG=debug 
build/$1 build


