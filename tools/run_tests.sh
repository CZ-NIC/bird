#!/bin/sh

objdir=$1
srcdir=$2

all_tests=$(find "$objdir" -name '*_test')

num_all_tests=0
for i in $all_tests; do num_all_tests=$((num_all_tests + 1)); done

num_test=1
num_succ_tests=0
num_fail_tests=0
echo -e "  == Start all $num_all_tests unit tests ==\n"
for test in $all_tests ; do
	./$test ; exit_code=$?
	cols=$(tput cols)
	offset=$((cols-17))
	fmt="  [%2d/%-2d] %-${offset}s"
	printf "$fmt" $((num_test++)) $num_all_tests "$test"
	if [ $exit_code -eq 0 ]; then
		printf "[\e[1;32m OK \e[0m]"
		num_succ_tests=$((num_succ_tests+1))
	else
		printf "[\e[1;31mFAIL\e[0m]"
		num_fail_tests=$((num_fail_tests+1))
	fi
	printf "\n"
done

num_all_tests_src=0
for dir in client conf filter lib misc nest proto sysdep; do
	for i in $(find "$srcdir/$dir" -name '*_test.c'); do num_all_tests_src=$((num_all_tests_src + 1)); done
done
num_build_fail_tests=$((num_all_tests_src - num_all_tests))

echo ""
echo "  ------------------------------"
echo "    Success: $num_succ_tests"
echo "    Failure: $num_fail_tests"
echo "    Build-Failure: $num_build_fail_tests"
echo "  ------------------------------"
