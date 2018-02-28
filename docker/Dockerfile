FROM alpine
RUN apk add --no-cache curl tar gzip
COPY target/samlconf.tar.gz /samlconf.tar.gz
RUN mkdir -p /samlconf && tar xzvf /samlconf.tar.gz -C /samlconf

FROM anapsix/alpine-java:8_jdk
LABEL maintainer=codice

RUN apk add --no-cache bash

COPY --from=0 /samlconf /samlconf

ENTRYPOINT [ "/samlconf/bin/samltest.sh" ]
