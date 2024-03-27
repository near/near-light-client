#set export
#set dotenv-filename := ".env"
set dotenv-load 

ETH_RPC_URL := env('ETH_RPC_URL', 'https://rpc.sepolia.eth.gateway.fm')
CHAIN_ID := env('CHAIN_ID', '11155111')
ETH_PRIVATE_KEY := env_var('ETH_PRIVATE_KEY')
ETH_PUBLIC_KEY := env_var('ETH_PUBLIC_KEY')

BROADCAST := if env("BROADCAST", "") != "n" {"--broadcast "} else {""}
LEGACY := if env('LEGACY', "") != "" {"--legacy "} else {""} 
VERIFIER := env('VERIFIER', 'etherscan')
VERIFY := if env('VERIFY', "") != "n" {"--verify " + VERIFIER} else {""}

forge-script SCRIPT TAIL *ARGS:
    cd ./nearx/contract && \
        forge script {{SCRIPT}} \
            --ffi \
            --sender {{ETH_PUBLIC_KEY}} \
            --rpc-url {{ETH_RPC_URL}} \
            --private-key {{ETH_PRIVATE_KEY}} \
            {{TAIL}} {{ARGS}} -vvvv --json

# Deploy the NEARX contract 
deploy-contract: (forge-script "Deploy" BROADCAST + VERIFY + LEGACY)

# Initialise the NEARX contract with any parameters such as owner
init-contract: init
    forge-script Initialise

# Update the ids for the verifier
update-params: (forge-script "UpdateParams" BROADCAST + LEGACY)

# Upgrade the NEARX contract
upgrade: (forge-script "Upgrade" BROADCAST + VERIFY + LEGACY)

# Request a sync on-chain
request-sync: (forge-script "RequestSync" BROADCAST + LEGACY)

# Request a verify on-chain
request-verify: (forge-script "RequestVerify" BROADCAST + LEGACY)

brunoc := "npx -y @usebruno/cli run"

# Fetch the current active deployments
fetch-deployments OUTPUT:
    {{brunoc}} "api/succinct/Get Deployments.bru" --env testnet -o {{OUTPUT}}

# Filter deployments for the specified chain id
filter-chain DEPLOYMENTS CHAIN_ID:
    @cat {{DEPLOYMENTS}} | jq -r ".results[0].response.data" | jq -r "[.[] | select(.chain_id == {{CHAIN_ID}})]"

# Filter the deployments for the entrypoint
filter-version VERSION: 
    jq -r "[.[] | select((.edges.release.name | contains(\"{{VERSION}}\")))]"

# Filter the deployments for the entrypoint
filter-entrypoint ENTRYPOINT: 
    jq -r "[.[] | select((.edges.release.entrypoint | contains(\"{{ENTRYPOINT}}\")))]" 

filter-all OUTPUT $ENTRYPOINT: 
    #!/usr/bin/env bash
    set -euxo pipefail
    filtered=`just filter-chain {{OUTPUT}} $CHAIN_ID`
    filtered=`just filter-entrypoint $ENTRYPOINT <<< "$filtered"`
    just filter-version $VERSION <<< "$filtered"

init: (fetch-deployments "/tmp/deployments.json")
    #!/usr/bin/env bash
    set -euxo pipefail
    S_INFO=$(just filter-all /tmp/deployments.json sync)

    echo $S_INFO | jq -r .gateway
    echo $S_INFO | jq -r .function_id

    just filter-all /tmp/deployments.json verify | jq -r .function_id

call-brunoc REQUEST:
    {{brunoc}} "api/succinct/deploy/{{REQUEST}}.bru" --env testnet -o /tmp/{{REQUEST}}.json

# Deploy a succinct circuit
succinct-deploy $ENTRYPOINT $VERSION: 
    {{brunoc}} "Succinct/Deploy/new-deployment.bru" --env testnet -o /tmp/deploy.json

check $CHECK_RELEASE_NUM: 
    {{brunoc}} "api/succinct/deploy/check.bru" --env testnet -o /tmp/check.json

wait-for-success RELEASE_NUM:
    #!/usr/bin/env bash

    for ((count=0; count<20; count++)); do
        just check {{RELEASE_NUM}}
        if [ $? -ne 0 ]; then
            echo "non zero exit code: $?, trying in 30s"
            sleep 30s
        else
            echo "success"
            break
        fi
    done

extract-release-id:
    cat /tmp/new-deployment.json | jq -r ".results[0].response.data.release_id"

extract-release-num:
    cat /tmp/new-deployment.json | jq -r ".results[0].response.data.release_number"

current-release ENTRYPOINT:
    just filter-all /tmp/deployments.json {{ENTRYPOINT}} | jq -r .edges.release

update-name $RELEASE_ID $VERSION:
    npx -y @usebruno/cli run "api/succinct/deploy/update-name.bru" --env-var VERSION={{VERSION}} --env-var RELEASE_ID={{RELEASE_ID}} --env testnet -o /tmp/update-release-name.json

update-current-name ENTRYPOINT:
    #!/usr/bin/env bash
    
    ID=$(cat /tmp/{{ENTRYPOINT}}-release.json | jq -r .id)
    VERSION=$(cat /tmp/{{ENTRYPOINT}}-release.json | jq -r .git_ref)
    just update-name $ID $VERSION || exit 0

get-verifier OUTPUT:
    cat {{OUTPUT}} | jq -r '.bytecode'

release-dev ENTRYPOINT VERSION:
    #!/usr/bin/env bash
    set -euxo pipefail

    # just update-current-name {{ENTRYPOINT}} 

    # just call-brunoc "new-deployment"
    RELEASE_ID=`just extract-release-id`
    RELEASE_NUM=`just extract-release-num`
    # just wait-for-success $RELEASE_NUM 
    # 
    # just update-current-name $ENTRYPOINT
    # cat /tmp/check.json | jq -r ".results[0].response.data" > /tmp/{{ENTRYPOINT}}-release.json
    # just update-name $RELEASE_ID 

    export CREATE2_SALT=`cast th "$RANDOM$RANDOM$RANDOM$RANDOM" | cast to-uint256| cast tb`
    export FUNCTION_VERIFIER=`just get-verifier /tmp/{{ENTRYPOINT}}-release.json`

    export DEPLOYOUTPUT=`just forge-script "DeployAndRegisterFunction" {{BROADCAST}} | jq -R 'fromjson?'`
    export RETURN=$(jq '.returns' <<< $DEPLOYOUTPUT)
    export FUNCTION_ID=$(echo $RETURN | jq -r '."0".value')
    export VERIFIER_ADDRESS=$(echo $RETURN | jq -r '."1".value')
    export TX_HASH=`cat ./nearx/contract/broadcast/DeployAndRegisterVerifier.sol/{{CHAIN_ID}}/run-latest.json | jq '.receipts[0].transactionHash'`    
    npx -y @usebruno/cli run "api/succinct/deploy/notify-deployment.bru" \
        --env-var RELEASE_ID=$RELEASE_ID \
        --env-var VERIFIER_ADDRESS=$VERIFIER_ADDRESS \
        --env-var CHAIN_ID={{CHAIN_ID}} \
        --env-var FUNCTION_ID=$FUNCTION_ID \
        --env-var CREATE2_SALT=$CREATE2_SALT \
        --env-var TX_HASH=$TX_HASH \
        --env testnet -o /tmp/notify-deployment.json


