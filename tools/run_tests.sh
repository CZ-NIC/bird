#!/bin/sh

objdir=$1
srcdir=$2

if [ -z "$TERM" ]; then
  export TERM=xterm
fi
tput init

# see if it supports colors...
ncolors=$(tput colors)

if test -n "$ncolors" && test $ncolors -ge 8; then
	bold="$(tput bold)"
	underline="$(tput smul)"
	standout="$(tput smso)"
	normal="$(tput sgr0)"
	black="$(tput setaf 0)"
	red="$(tput setaf 1)"
	green="$(tput setaf 2)"
	yellow="$(tput setaf 3)"
	blue="$(tput setaf 4)"
	magenta="$(tput setaf 5)"
	cyan="$(tput setaf 6)"
	white="$(tput setaf 7)"
fi

all_tests=$(find "$objdir" -name '*_test')

num_all_tests=0
for i in $all_tests; do num_all_tests=$((num_all_tests + 1)); done

num_test=1
num_succ_tests=0
num_fail_tests=0
echo -e "  == Start all $num_all_tests unit tests ==\n"
for test in $all_tests ; do
	./$test > /dev/null 2>&1 ; exit_code=$?
	cols=$(tput cols)
	offset=$((cols-17))
	fmt="  [%2d/%-2d] %-${offset}s"
	printf "$fmt" $num_test $num_all_tests "$test"
	num_test=$((num_test+1))
	if [ $exit_code -eq 0 ]; then
		printf "[${green}${bold} OK ${normal}]"
		num_succ_tests=$((num_succ_tests+1))
	else
		printf "[${red}${bold}FAIL${normal}]"
		num_fail_tests=$((num_fail_tests+1))
	fi
	printf "\n"
done

num_all_tests_src=0
for dir in client conf filter lib misc nest proto sysdep; do
	for i in $(find "$srcdir/$dir" -name '*_test.c'); do num_all_tests_src=$((num_all_tests_src + 1)); done
done

num_build_fail_tests=$((num_all_tests_src - num_all_tests))
if [ $num_build_fail_tests -lt 0 ]; then
	num_build_fail_tests=0
fi

echo ""
echo "  ------------------------------"
echo "    Success: $num_succ_tests"
echo "    Failure: $num_fail_tests"
echo "    Build-Failure: $num_build_fail_tests"
echo ""
