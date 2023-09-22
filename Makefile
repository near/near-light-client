docker:
	DOCKER_BUILDKIT=1 docker build --progress=plain -t near/light-client:latest .
