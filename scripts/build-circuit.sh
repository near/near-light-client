#!/usr/bin/env bash

export RUST_LOG=debug 

if [ "$1" != "sync" ] && [ "$1" != "verify" ]; then
  echo "Usage: $0 <sync|verify>"
  exit
fi

cargo build --bin near-light-clientx \
  --release \
  --features $1

mv -f target/release/near-light-clientx build/$1

TAILARGS="${@: 2}"

build/$1 build $TAILARGS

