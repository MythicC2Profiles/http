FROM itsafeaturemythic/mythic_base_image:0.0.2
WORKDIR /Mythic/

COPY [".", "."]

RUN go get -u github.com/MythicMeta/MythicContainer

RUN make build

CMD make run