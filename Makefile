HOME:=$(shell pwd)
NAME:=rolodex
DOCKER_REPO := docker-registry.core.rcsops.com
DOCKER_REPO_DIR :=coreservices
DOCKER_REPO_URL := ${DOCKER_REPO}${DOCKER_REPO_DIR}
BUILD_CONTAINER := maven:3-jdk-8-alpine

BUILD_NUMBER ?= 3.0.1
BUILD := $(lastword $(subst ., ,$(BUILD_NUMBER)))
VERSION := $(firstword $(subst .$(BUILD), ,$(BUILD_NUMBER)))

all: docker-build docker-image helm

build:
	mvn package -Dversion=${VERSION}

docker-build:
	docker run --rm --name rolodex-build -v "${HOME}:/src" -w "/src" \
		-e HOME=/src \
		-t ${BUILD_CONTAINER} /bin/bash -c "mvn package -Dversion=${VERSION}"

test:
	mvn test -Dversion=${VERSION}

docker-test:
	docker run --rm --name rolodex-build -v "${HOME}:/src" -w "/src" \
		-t ${BUILD_CONTAINER} /bin/bash -c "mvn test -Dversion=${VERSION}"

clean:
	mvn clean -Dversion=${VERSION}

docker-clean:
	docker run --rm --name rolodex-build -v "${HOME}:/src" -w "/src" \
		-t ${BUILD_CONTAINER} /bin/bash -c "mvn clean -Dversion=${VERSION}"

.PHONY: docker-image
docker-image:
	docker build -t ${DOCKER_REPO}/${DOCKER_REPO_DIR}/${NAME}:latest \
		-t ${DOCKER_REPO}/${DOCKER_REPO_DIR}/${NAME}:${VERSION} \
		-t ${DOCKER_REPO}/${DOCKER_REPO_DIR}/${NAME}:${BASE_VERSION} \
		--build-arg ARTIFACT=target/rolodex-${VERSION}.jar \
		.

bin/helm:
	mkdir -p bin
	curl -L https://kubernetes-helm.storage.googleapis.com/helm-v2.7.0-linux-amd64.tar.gz -o /tmp/helm-v2.7.0-linux-amd64.tar.gz
	tar xvfz /tmp/helm-v2.7.0-linux-amd64.tar.gz -C /tmp
	mv /tmp/linux-amd64/helm bin/helm
	rm -rf /tmp/linux-amd64
	rm -f /tmp/helm-v2.7.0-linux-amd64.tar.gz

bin/yaml:
	mkdir -p bin
	curl -L https://artifactory.core.rcsops.com/artifactory/core-generic-local/yaml -o bin/yaml
	chmod +x bin/yaml

.PHONY: helm
helm: bin/helm bin/yaml
	./bin/helm init -c
	./bin/helm repo add coreservices https://artifactory.core.rcsops.com/artifactory/core-helm-local/
	./bin/helm dep up HelmCharts/${NAME}/
	./bin/yaml w -i HelmCharts/${NAME}/values.yaml image.tag ${BUILD_NUMBER}
	./bin/yaml w -i HelmCharts/${NAME}/Chart.yaml version ${BUILD_NUMBER}
	./bin/helm package HelmCharts/${NAME}/ --save=false -d HelmCharts/
	git config --global user.name "Rolodex CICD User"
	git config --global user.email "nobody@virtustream.com"
	rm -rf HelmCharts/coreservices-kubernetes/
	git clone git@github.emcrubicon.com:coreservices/coreservices-kubernetes.git HelmCharts/coreservices-kubernetes \
		&& cd HelmCharts/coreservices-kubernetes \
		&& cp ../${NAME}-${BUILD_NUMBER}.tgz charts/ \
		&& make \
		&& git add charts/ \
		&& git commit -m "added ${NAME} ${BUILD_NUMBER} helm chart" \
		&& git push 
