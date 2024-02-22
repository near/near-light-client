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

# TODO: these should be configurable and need updating
SYNC_FUNCTION_ID=0x38a03ba7ecace39a1c7315d798cc9689418eceba384e154c01d6e2897bf000a9
VERIFY_FUNCTION_ID=0x76918ea14fc7b8d8e4919c970be635e1d0ed57576771cdc1f6fa581bce7fd418
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

verify:
	$(FORGE) script Verify $(FORGEREST)
