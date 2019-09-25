#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

DOCKER_IMAGE=${DOCKER_IMAGE:-playervsplayercoinpay/playervsplayercoind-develop}
DOCKER_TAG=${DOCKER_TAG:-latest}

BUILD_DIR=${BUILD_DIR:-.}

rm docker/bin/*
mkdir docker/bin
cp $BUILD_DIR/src/playervsplayercoind docker/bin/
cp $BUILD_DIR/src/playervsplayercoin-cli docker/bin/
cp $BUILD_DIR/src/playervsplayercoin-tx docker/bin/
strip docker/bin/playervsplayercoind
strip docker/bin/playervsplayercoin-cli
strip docker/bin/playervsplayercoin-tx

docker build --pull -t $DOCKER_IMAGE:$DOCKER_TAG -f docker/Dockerfile docker
