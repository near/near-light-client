#!/usr/bin/env bash

set -e

export $(cat .env | grep -v '#' | sed 's/\r$//' | awk '/=/ {print $1}' )
export $(cat "api/NEAR Light Client/.env" | grep -v '#' | sed 's/\r$//' | awk '/=/ {print $1}' )


cd "api/NEAR Light Client"

BRUNO="npx -y @usebruno/cli run"

# New entrypoint, for sync and verify

# Check release every 30s
# Once happy, pull verifying key to nearx contract directory
# Update name
# Update main contract


ENTRYPOINT=verify
echo "Creating new $ENTRYPOINT deployment"
$BRUNO "Succinct/Deploy/new-deployment.bru" --env testnet -o /tmp/$ENTRYPOINT-deployment-v$VERSION.json

echo "Checking $ENTRYPOINT release"
CONTINUE=true
while $CONTINUE
do
  $BRUNO "Succinct/Deploy/check-release.bru" --env testnet -o /tmp/$ENTRYPOINT-release-v$VERSION.json
  if [ $? -eq 0 ]; then
    CONTINUE=false
  fi
  sleep 30
done



# RESULT=$(cat /tmp/result.json | jq '.results[0].response.data')
# echo "Deployments: $RESULT"
#
# echo "Filtering deployments"
# export DEPLOYMENTSTR=$(echo $RESULT | \
#   jq \
#   ".[] | select(.edges.release.name | contains(\"$CIRCUIT\") and contains(\"$VERSION\"))")
#
# echo "Deployment: $DEPLOYMENTSTR"
#
#

