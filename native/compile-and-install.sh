#!/usr/bin/env bash

LOCAL_PATH=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
CUR_PATH=$(pwd)

cd $LOCAL_PATH

set -e
cmake .
make

FOLDER=""

if [[ "$OSTYPE" == "linux-gnu" ]]; then
        FOLDER="linux_64"
elif [[ "$OSTYPE" == "darwin"* ]]; then
        FOLDER="osx_64"
elif [[ "$OSTYPE" == "cygwin" ]]; then
        FOLDER="windows_64"
elif [[ "$OSTYPE" == "msys" ]]; then
        FOLDER="windows_64"
elif [[ "$OSTYPE" == "freebsd"* ]]; then
        FOLDER="linux_64"
else
        exit 1
fi

echo "OS detected $FOLDER"

cp out/* ../src/main/resources/META-INF/lib/$FOLDER

cd $CUR_PATH