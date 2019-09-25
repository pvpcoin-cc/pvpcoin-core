FROM debian:stretch
LABEL maintainer="PlayerVsPlayerCoin Developers <dev@playervsplayercoin.org>"
LABEL description="Dockerised PlayerVsPlayerCoinCore, built from Travis"

RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -fr /var/cache/apt/*

COPY bin/* /usr/bin/
