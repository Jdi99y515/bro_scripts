#!/bin/sh

FILE=$1

DIR=$(mktemp -t -d bro_urlsnarf.XXXXXXXXX)

cd $DIR || exit 1

bro -f 'not ip6'  -C  -r $FILE || true

cat http.log | bro-cut -d -c | sed "s/fields.//;s/types.//" | egrep -v "^#(sep|set|emp|unset|path)"

rm -rf $DIR
