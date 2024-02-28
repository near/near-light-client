#!/usr/bin/env bash

if [ -z "$CIRCUIT" ]; then
  export CIRCUIT=Verify
fi

if [ -z "$VERSION" ]; then
  export VERSION=v0.0.3
fi

echo "Getting deployments"
(cd "api/NEAR Light Client" && npx -y @usebruno/cli run "Succinct/Get Deployments.bru" --env testnet -o /tmp/result.json)


RESULT=$(cat /tmp/result.json | jq '.results[0].response.data')
echo "Deployments: $RESULT"

echo "Filtering deployments"
export DEPLOYMENTSTR=$(echo $RESULT | \
  jq \
  ".[] | select(.edges.release.name | contains(\"$CIRCUIT\") and contains(\"$VERSION\"))")

echo "Deployment: $DEPLOYMENTSTR"

