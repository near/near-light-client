.EXPORT_ALL_VARIABLES:
-include .env

TAG_PREFIX?=near
IMAGE_TAG?=0.0.3

docker:
	DOCKER_BUILDKIT=1 docker build --progress=plain -t $(TAG_PREFIX)/light-client:$(IMAGE_TAG) .

test:
	cargo test --workspace

# Runs all of the beefy tests that require a pretty good machine, builds all proofs in release mode
# NOTE: this might OOM if your machine is small! At least 32GB of ram is recommended with a very modern CPU.
# Likely OSX will not work and your fans will turn on! 
beefy-test:
	RUST_LOG=debug cargo test --workspace --ignored --release

# Verifiers from v.0.0.3-rc.1 https://alpha.succinct.xyz/near/near-light-client/deployments
SYNC_FUNCTION_ID=0xcf00114b5be928c0b55f7deb6ab988d9ab9f8a54d96443ed37d90bc8c636f89c
VERIFY_FUNCTION_ID=0x62dc66a6609f5884933c20c85b6792c5702e828d3a7f315deddbe6454dd70b3c

# Succinct gateway containing latest verifierss
GATEWAY_ID=0x6c7a05e0ae641c6559fd76ac56641778b6ecd776
NEAR_CHECKPOINT_HEADER_HASH=0x63b87190ffbaa36d7dab50f918fe36f70ab26910a0e9d797161e2356561598e3
ETH_RPC=https://rpc.goerli.eth.gateway.fm
CHAIN_ID=5

FORGE=cd ./nearx/contract && forge
FORGEREST= --rpc-url $(ETH_RPC) --private-key $$ETH_PRIVATE_KEY --broadcast --verify --verifier etherscan -vv

build-contracts:
	$(FORGE) build

deploy: build-contracts
	$(FORGE) script Deploy $(FORGEREST)

initialise: 
	$(FORGE) script Initialise $(FORGEREST)

upgrade:
	$(FORGE) script Upgrade $(FORGEREST)

request-sync:
	$(FORGE) script RequestSync $(FORGEREST)

request-verify:
	$(FORGE) script RequestVerify $(FORGEREST)
