dnl ** Additional Autoconf tests for BIRD configure script
dnl ** (c) 1999 Martin Mares <mj@ucw.cz>

AC_DEFUN([BIRD_CHECK_PTHREADS],
[
  bird_tmp_cflags="$CFLAGS"
  CFLAGS="$CFLAGS -pthread"

  AC_CACHE_CHECK(
    [whether POSIX threads are available],
    [bird_cv_lib_pthreads],
    [
      AC_LINK_IFELSE(
	[
	  AC_LANG_PROGRAM(
	    [ #include <pthread.h> ],
	    [
	      pthread_t pt;
	      pthread_create(&pt, NULL, NULL, NULL);
	      pthread_spinlock_t lock;
	      pthread_spin_lock(&lock);
	    ]
	  )
	],
	[bird_cv_lib_pthreads=yes],
	[bird_cv_lib_pthreads=no]
      )
    ]
  )

  CFLAGS="$bird_tmp_cflags"
])

AC_DEFUN([BIRD_CHECK_GCC_OPTION],
[
  bird_tmp_cflags="$CFLAGS"
  CFLAGS="$3 $2"

  AC_CACHE_CHECK(
    [whether CC supports $2],
    [$1],
    [
      AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM()],
	[$1=yes],
	[$1=no]
      )
    ]
  )

  CFLAGS="$bird_tmp_cflags"
])

AC_DEFUN([BIRD_ADD_GCC_OPTION],
[
  if test "$$1" = yes ; then
    CFLAGS="$CFLAGS $2"
  fi
])

# BIRD_CHECK_PROG_FLAVOR_GNU(PROGRAM-PATH, IF-SUCCESS, [IF-FAILURE])
# copied from autoconf internal _AC_PATH_PROG_FLAVOR_GNU
AC_DEFUN([BIRD_CHECK_PROG_FLAVOR_GNU],
[
  # Check for GNU $1
  case `"$1" --version 2>&1` in
    *GNU*)
      $2
      ;;
  m4_ifval([$3],
    [*)
      $3
      ;;
    ]
  )
  esac
])
