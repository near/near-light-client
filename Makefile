.EXPORT_ALL_VARIABLES:
-include .env

TAG_PREFIX?=us-docker.pkg.dev/pagoda-solutions-dev/rollup-data-availability
IMAGE_TAG?=dev

docker-offchain:
	DOCKER_BUILDKIT=1 docker build --progress=plain -t $(TAG_PREFIX)/light-client:$(IMAGE_TAG) -f Dockerfile.offchain .

docker-operator:
	docker build -t $(TAG_PREFIX)/nearx-operator:$(IMAGE_TAG) -f Dockerfile.operator .

test:
	cargo test --workspace

# Runs all of the beefy tests that require a pretty good machine, builds all proofs in release mode
# NOTE: this might OOM if your machine is small! At least 32GB of ram is recommended with a very modern CPU.
# Likely OSX will not work and your fans will turn on! 
beefy-test:
	RUST_LOG=debug cargo test --workspace --ignored --release

slither:
	cd nearx/contracts && slither . --foundry-compile-all
