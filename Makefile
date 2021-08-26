.PHONY: docker-image
docker-image: git-submodule-setup
	@DOCKER_BUILDKIT=1 docker build --ssh default -t axelar/tofnd .

.PHONY: docker-image-malicious
docker-image-malicious: git-submodule-setup
	@DOCKER_BUILDKIT=1 docker build --ssh default --build-arg features="malicious" -t axelar/tofnd-malicious .


.PHONY: copy-binary
copy-binary-from-image: guard-SEMVER
	./scripts/copy-binaries-from-image.sh
	mv bin/tofnd bin/tofnd-linux-arm64-${SEMVER}
	cd bin && sha256sum * > SHA256SUMS

.PHONY: docker-image-all
docker-image-all: git-submodule-setup
	make docker-image
	make docker-image-malicious

.PHONY: git-submodule-setup
git-submodule-setup:
	git submodule init
	git submodule update

guard-%:
	@ if [ -z '${${*}}' ]; then echo 'Environment variable $* not set' && exit 1; fi