#!/bin/sh

CFLAGS="-fPIC -Wall $CFLAGS"
LDFLAGS="-shared -llog -ldl $LDFLAGS"
[ -z "$CC" ] &&
  echo "please set CC to your android toolchain compiler" && exit 1
$CC $CFLAGS sniffas.c $LDFLAGS -o libKLab.NativeInput.Native.so
