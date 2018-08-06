#!/bin/sh

set -e

filter_h="$1"
conf_h="$2"

objdir="$3"

TYPE_TMP="$objdir/conf/types-sctb.tmp"
SYM_TMP="$objdir/conf/sym-sctb.tmp"

sed -nr "/T_ENUM_(HI|LO)/d;/#define T_/{s/^#define T_//; s/ .*//; p;}" <"$filter_h" >"$TYPE_TMP"
sed -nr "/#define SYM_CLASS_/{s/^#define SYM_CLASS_//; s/ .*//; p;}" <"$conf_h" >"$SYM_TMP"

for T in `cat $TYPE_TMP`; do
  for S in CONSTANT VARIABLE; do
    echo "case (SYM_CLASS_"$S" | T_"$T"): return SYM_"$S"_"$T";"
  done
done

for S in `grep -Ev '(CONSTANT|VARIABLE)' $SYM_TMP`; do
  echo "case SYM_CLASS_"$S": return SYM_"$S";"
done
