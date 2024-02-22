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
SYNC_FUNCTION_ID=0x350c2939eb7ff2185612710a2b641b4b46faab68e1e2c57b6f15e0af0674f5e9
VERIFY_FUNCTION_ID=0x39fb2562b80725bb7538dd7d850126964e565a1a837d2d7f2a018e185b08fc0e
ETH_RPC=https://rpc.goerli.eth.gateway.fm
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
	$(CD_CONTRACTS) && forge script Initialise \
		--rpc-url $(ETH_RPC) \
		--private-key $$ETH_PRIVATE_KEY \
		--broadcast \
		--verify \
		--verifier etherscan
upgrade:
	$(CD_CONTRACTS) && forge script Upgrade \
		--rpc-url $(ETH_RPC) \
		--private-key $$ETH_PRIVATE_KEY \
		--broadcast \
		--verify \
		--verifier etherscan
verify:
	$(CD_CONTRACTS) && forge script Verify \
		--rpc-url $(ETH_RPC) \
		--private-key $$ETH_PRIVATE_KEY \
		--broadcast \
		--verify \
		--verifier etherscan

