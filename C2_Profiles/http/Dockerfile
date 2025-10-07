FROM golang:1.25 AS builder

WORKDIR /Mythic/

COPY [".", "."]

RUN make build

FROM alpine

RUN apk add make

COPY --from=builder /main /main
COPY --from=builder /mythic_http_server /mythic_http_server

WORKDIR /Mythic/

COPY [".", "."]

CMD make run