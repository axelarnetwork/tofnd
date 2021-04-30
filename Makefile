.PHONY: docker-image
docker-image:
	@DOCKER_BUILDKIT=1 docker build --ssh default -t axelar/tofnd .

.PHONY: docker-image-malicious
docker-image-malicious:
	@DOCKER_BUILDKIT=1 docker build --ssh default --build-arg features="malicious" -t axelar/tofnd-malicious .

.PHONY: docker-image-all
docker-image-all:
	make docker-image 
	make docker-image-malicious
