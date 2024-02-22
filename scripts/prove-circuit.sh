#!/usr/bin/env bash

export RUST_LOG=debug

if [ "$1" != "sync" ] && [ "$1" != "verify" ]; then
  echo "Usage: $0 <sync|verify>"
  exit
fi

# If INPUT is not set, set it to input.json
if [ -z "$INPUT" ]; then
  INPUT="input.json"
fi

TAILARGS="${@: 2}"

# Append the rest of the arguments to this command
build/$1 prove $INPUT $TAILARGS

