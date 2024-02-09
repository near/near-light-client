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

