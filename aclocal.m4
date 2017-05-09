dnl ** Additional Autoconf tests for BIRD configure script
dnl ** (c) 1999 Martin Mares <mj@ucw.cz>

AC_DEFUN([BIRD_CHECK_STRUCT_ALIGN],
[AC_CACHE_CHECK([usual alignment of structures],bird_cv_c_struct_align,[
AC_TRY_RUN([
#include <stdio.h>

struct { char x; long int y; } ary[2];

int main(void)
{
  FILE *f = fopen("conftestresult", "w");
  if (!f) return 10;
  fprintf(f, "%d", sizeof(ary)/2);
  fclose(f);
  exit(0);
}
],[
bird_cv_c_struct_align=`cat conftestresult`
],[
AC_MSG_RESULT([test program failed])
AC_MSG_ERROR([Cannot determine structure alignment])
],[bird_cv_c_struct_align=16])
])
AC_DEFINE_UNQUOTED([CPU_STRUCT_ALIGN], [$bird_cv_c_struct_align], [Usual alignment of structures])
])

AC_DEFUN([BIRD_CHECK_TIME_T],
[AC_CACHE_CHECK([characteristics of time_t], bird_cv_type_time_t, [
AC_TRY_RUN([
#include <stdio.h>
#include <sys/time.h>
#include <limits.h>

int main(void)
{
  FILE *f = fopen("conftestresult", "w");
  if (!f) return 10;
  fprintf(f, "%d-bit ", sizeof(time_t)*CHAR_BIT);
  if ((time_t) -1 > 0) fprintf(f, "un");
  fprintf(f, "signed");
  fclose(f);
  exit(0);
}
],[bird_cv_type_time_t=`cat conftestresult`
],[	AC_MSG_RESULT([test program failed])
	AC_MSG_ERROR([Cannot determine time_t size and signedness.])
],[bird_cv_type_time_t="32-bit signed"])
])
case "$bird_cv_type_time_t" in
	*64-bit*)	AC_DEFINE([TIME_T_IS_64BIT], [1], [Define to 1 if time_t is 64 bit]) ;;
	esac
case "$bird_cv_type_time_t" in
	*unsigned*)	;;
	*)		AC_DEFINE([TIME_T_IS_SIGNED], [1], [Define to 1 if time_t is signed]) ;;
	esac
])

AC_DEFUN([BIRD_CHECK_PTHREADS],
[
  bird_tmp_cflags="$CFLAGS"

  CFLAGS="$CFLAGS -pthread"
  AC_CACHE_CHECK([whether POSIX threads are available], bird_cv_lib_pthreads,
    [AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <pthread.h>]], [[pthread_t pt; pthread_create(&pt, NULL, NULL, NULL); pthread_spinlock_t lock; pthread_spin_lock(&lock); ]])],
		    [bird_cv_lib_pthreads=yes], [bird_cv_lib_pthreads=no])])

  CFLAGS="$bird_tmp_cflags"
])

AC_DEFUN([BIRD_CHECK_GCC_OPTION],
[
  bird_tmp_cflags="$CFLAGS"

  CFLAGS="$3 $2"
  AC_CACHE_CHECK([whether CC supports $2], $1,
    [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])], [$1=yes], [$1=no])])

  CFLAGS="$bird_tmp_cflags"
])

AC_DEFUN([BIRD_ADD_GCC_OPTION],
[
  if test "$$1" = yes ; then
    CFLAGS="$CFLAGS $2"
  fi
])

# BIRD_CHECK_PROG_FLAVOR_GNU(PROGRAM-PATH, IF-SUCCESS, [IF-FAILURE])
# copied autoconf internal _AC_PATH_PROG_FLAVOR_GNU
AC_DEFUN([BIRD_CHECK_PROG_FLAVOR_GNU],
[# Check for GNU $1
case `"$1" --version 2>&1` in
*GNU*)
  $2;;
m4_ifval([$3],
[*)
  $3;;
])esac
])
