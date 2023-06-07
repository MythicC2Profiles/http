FROM itsafeaturemythic/mythic_go_base:latest

WORKDIR /Mythic/

COPY [".", "."]

RUN make build

FROM alpine

RUN apk add make

COPY --from=0 /main /main
COPY --from=0 /mythic_http_server /mythic_http_server

WORKDIR /Mythic/

CMD make run