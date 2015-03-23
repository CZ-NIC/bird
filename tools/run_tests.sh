#!/bin/sh

objdir=$1
srcdir=$2

all_tests=$(find $objdir -name '*_test')

num_all_tests=0
for i in $all_tests; do num_all_tests=$((num_all_tests + 1)); done

num_test=1
num_succ_tests=0
num_fail_tests=0
echo -e "  == Start all $num_all_tests unit tests ==\n"
for test in $all_tests ; do
	echo -e "  [$((num_test++))/$num_all_tests] $test"
	./$test							\
		&& num_succ_tests=$((num_succ_tests+1))		\
		|| num_fail_tests=$((num_fail_tests+1))
done

num_all_tests_src=0
for i in $(find $srcdir -name '*_test.c'); do num_all_tests_src=$((num_all_tests_src + 1)); done
num_build_fail_tests=$((num_all_tests_src - num_all_tests))

echo ""
echo "  ------------------------------"
echo "    Success: $num_succ_tests"
echo "    Failure: $num_fail_tests"
echo "    Build-Failure: $num_build_fail_tests"
echo "  ------------------------------"
