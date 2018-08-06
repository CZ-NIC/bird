#!/bin/sh

set -e

filter_h="$1"
conf_h="$2"

objdir="$3"

TYPE_TMP="$objdir/conf/types-sc.tmp"
SYM_TMP="$objdir/conf/sym-sc.tmp"

sed -nr "/T_ENUM_(HI|LO)/d;/#define T_/{s/^#define T_//; s/ .*//; p;}" <"$filter_h" >"$TYPE_TMP"
sed -nr "/#define SYM_CLASS_/{s/^#define SYM_CLASS_//; s/ .*//; p;}" <"$conf_h" >"$SYM_TMP"

echo CF_DECLS

echo "%token <s>" `sed -r '/(CONSTANT|VARIABLE)/d; s/^/SYM_/' $SYM_TMP`
echo "%type <s> SYM_CONSTANT"
echo "%type <s> SYM_VARIABLE"

for T in `cat $TYPE_TMP`; do
  for S in CONSTANT VARIABLE; do
    echo "%token <s> SYM_"$S"_"$T
  done
done

echo "%type <s> SYM"

echo CF_GRAMMAR

for T in `cat $TYPE_TMP`; do
  for S in CONSTANT VARIABLE; do
    echo "SYM_"$S": SYM_"$S"_"$T" ;"
  done
done

sed 's/.*/SYM: SYM_& ;/' $SYM_TMP
