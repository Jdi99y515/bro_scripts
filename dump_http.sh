#!/bin/sh

FILE=$1

DIR=$(mktemp -t -d bro_urlsnarf.XXXXXXXXX)

cp dump_http.bro $DIR || exit 1

cd $DIR || exit 1

bro -f 'not ip6'  -C  -r $FILE dump_http.bro || true

cat http.txt

rm -rf $DIR
