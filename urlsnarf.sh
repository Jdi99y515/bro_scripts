#!/bin/sh

FILE=$1

DIR=$(mktemp -t -d bro_urlsnarf.XXXXXXXXX)

cp *.bro $DIR

cd $DIR || exit 1

bro -f ip -C  -r $FILE urlsnarf.bro || true

cat http-requests.log|cf

rm -rf $DIR
