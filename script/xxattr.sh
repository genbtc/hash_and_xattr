#!/bin/bash
extract_xattr() {
  local file=$1 attr=$2 out=$3 prefix=$4
  getfattr -n "$attr" -e hex "$file" \
    | grep "^$attr=" \
    | sed "s/^$attr=$prefix//" \
    | xxd -r -p > "$out"
}
extract_xattr $@    #File  xname    outfile-raw
#Usage: ./xxattr.sh testA user.ima testA.user.ima
