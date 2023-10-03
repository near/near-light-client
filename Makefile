TAG_PREFIX?=near
IMAGE_TAG?=0.0.1

docker:
	DOCKER_BUILDKIT=1 docker build --progress=plain -t $(TAG_PREFIX)/light-client:$(IMAGE_TAG) .
