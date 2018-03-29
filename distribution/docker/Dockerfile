# First conatiner is a throw away container
FROM alpine
RUN apk add --no-cache curl tar gzip
COPY build/samlconf.tar /samlconf.tar
RUN mkdir -p /samlconf && tar xvf /samlconf.tar
RUN mv -v /samlconf-1.0-SNAPSHOT/* /samlconf

FROM anapsix/alpine-java:8_jdk
LABEL maintainer=codice

RUN apk add --no-cache bash curl iputils

COPY --from=0 /samlconf /samlconf
COPY wait.sh wait.sh

ENTRYPOINT ["./wait.sh"]
