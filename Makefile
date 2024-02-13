.EXPORT_ALL_VARIABLES:
include .env

TAG_PREFIX?=near
IMAGE_TAG?=0.0.1

docker:
	DOCKER_BUILDKIT=1 docker build --progress=plain -t $(TAG_PREFIX)/light-client:$(IMAGE_TAG) .

BUILDCIRCUIT := cargo build --release --bin
MVCIRCUIT := mv -f target/release

build-sync-circuit:
	$(BUILDCIRCUIT) sync --features=sync
	$(MVCIRCUIT)/sync build/
	RUST_LOG=debug ./build/sync build
.PHONY: build-sync-circuit

# TODO: build various parameters of NUM:BATCH, e.g 1024x64 2x1, 128x4, etc
build-verify-circuit:
	$(BUILDCIRCUIT) verify --features=verify
	$(MVCIRCUIT)/verify build/
	RUST_LOG=debug ./build/verify build
.PHONY: build-verify-circuit


SYNC_FUNCTION_ID=0x350c2939eb7ff2185612710a2b641b4b46faab68e1e2c57b6f15e0af0674f5e9
VERIFY_FUNCTION_ID=0x39fb2562b80725bb7538dd7d850126964e565a1a837d2d7f2a018e185b08fc0e
ETH_RPC=https://goerli.gateway.tenderly.co
NEAR_CHECKPOINT_HEADER_HASH=0x63b87190ffbaa36d7dab50f918fe36f70ab26910a0e9d797161e2356561598e3
CHAIN_ID=5
CD_CONTRACTS=cd ./circuits/plonky2x/contract

build-contracts:
	$(CD_CONTRACTS) && forge build

deploy: build-contracts
	$(CD_CONTRACTS) && forge script Deploy \
		--rpc-url $(ETH_RPC) \
		--private-key $$ETH_PRIVATE_KEY \
		--broadcast \
		--verify \
		--verifier etherscan

initialise: 
	cd $(ETH_CONTRACTS_PATH) && forge script Initialise \
		--rpc-url $(ETH_RPC) \
		--private-key $$ETH_PRIVATE_KEY \
		--broadcast \
		--verify \
		--verifier etherscan

# TODO: upgrade

