#!/usr/bin/env bash

if [ ! -f ../.env ]
then
  export $(cat .env | grep -v '#' | sed 's/\r$//' | awk '/=/ {print $1}' )
fi

export VERSION="${VERSION:-v0.0.3}"
export ETH_RPC_URL="${ETH_RPC_URL:-https://rpc.sepolia.eth.gateway.fm}"
export NEAR_CHECKPOINT_HEADER_HASH="${NEAR_CHECKPOINT_HEADER_HASH:-0x63b87190ffbaa36d7dab50f918fe36f70ab26910a0e9d797161e2356561598e3}"
export CHAIN_ID=${CHAIN_ID:-11155111}

if [ -z "$ETH_PRIVATE_KEY" ]; then
  echo "You need to set ETH_PRIVATE_KEY"
  exit 1
fi

function script() {
  if [ -z "$SKIP_BROADCAST" ];then
    TAIL="--broadcast"
  fi

  if [ -z "$SKIP_VERIFY" ]; then
    TAIL="$TAIL --verify --verifier etherscan"
  fi

  if [ ! -z "$IS_LEGACY" ]; then
    TAIL="$TAIL --legacy"
  fi

  (
    cd ./nearx/contract && \
      forge script $1 \
      --ffi \
      --sender $ETH_PUBLIC_KEY \
      --rpc-url $ETH_RPC_URL \
      --private-key $ETH_PRIVATE_KEY \
      $TAIL
  )
}

function pullDeployment() {
  echo "Getting deployments"
  (cd "api/NEAR Light Client" && npx -y @usebruno/cli run "Succinct/Get Deployments.bru" --env testnet -o /tmp/result.json)
  RESULT=$(cat /tmp/result.json | jq '.results[0].response.data')
  RESULT=$(echo $RESULT | jq -r "[.[] | select(.chain_id == $CHAIN_ID)]")
  echo $RESULT
}

function extractInfo() {
  echo $RESULT | \
    jq -r \
    ".[] | select(.edges.release.name | contains(\"$1\") and contains(\"$VERSION\"))"
}

function init() {
  pullDeployment
  S_INFO=$(extractInfo Sync)
  V_INFO=$(extractInfo Verify)

  export GATEWAY_ID=${GATEWAY_ID:-$(echo $S_INFO | jq -r .gateway)}
  export SYNC_FUNCTION_ID=$(echo $S_INFO | jq -r .function_id)
  export VERIFY_FUNCTION_ID=$(echo $V_INFO | jq -r .function_id)

  echo $GATEWAY_ID
  echo $SYNC_FUNCTION_ID
  echo $VERIFY_FUNCTION_ID
  # TODO: could test chain_id here too to make sure we arent botching the releases
}

case "${1,,}" in
'deploy')
  script Deploy
;;
'initialise')
  init
  script Initialise
;;
'update-params')
  init
  SKIP_VERIFY=true script UpdateParams 
;;
'upgrade')
  script Upgrade
;;
'request-sync')
  script RequestSync
;;
'request-verify')
  script RequestVerify
;;
*)
  echo "Falling back to script: $@"
  script $1
;;
esac

