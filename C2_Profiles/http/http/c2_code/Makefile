.PHONY: default
default: build_linux ;

BINARY_NAME?=mythic_http_server
DEBUG_LEVEL?="debug"
MYTHIC_SERVER_HOST?="127.0.0.1"
MYTHIC_SERVER_PORT?="17443"

build:
	CGO_ENABLED=0 go build -o ${BINARY_NAME} .
	cp ${BINARY_NAME} /

build_local:
	CGO_ENABLED=0 go build -o ${BINARY_NAME} .

run:
	cp /${BINARY_NAME} .

build_macos:
	CGO_ENABLED=0 go build -o ${BINARY_NAME} .

run_custom: build_local
	DEBUG_LEVEL=${DEBUG_LEVEL} \
MYTHIC_SERVER_HOST=${MYTHIC_SERVER_HOST} \
MYTHIC_SERVER_PORT=${MYTHIC_SERVER_PORT} \
./${BINARY_NAME}
