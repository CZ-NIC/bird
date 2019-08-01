dnl ** Additional Autoconf tests for BIRD configure script
dnl ** (c) 1999 Martin Mares <mj@ucw.cz>

AC_DEFUN([BIRD_CHECK_THREAD_LOCAL],
[
  AC_CACHE_CHECK(
    [whether _Thread_local is known],
    [bird_cv_thread_local],
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM(
        [
	  _Thread_local static int x = 42;
	],
	[]
      )
    ],
    [bird_cv_thread_local=yes],
    [bird_cv_thread_local=no]
    )
  )
])

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

AC_DEFUN([BIRD_CHECK_MPLS_KERNEL],
[
  AC_CACHE_CHECK(
    [for Linux MPLS headers],
    [bird_cv_mpls_kernel],
    [
      AC_COMPILE_IFELSE(
	[
	  AC_LANG_PROGRAM(
	    [
	      #include <linux/lwtunnel.h>
	      #include <linux/netlink.h>
	      #include <linux/rtnetlink.h>
	      #include <sys/socket.h>
	      void t(int arg);
	    ],
	    [
	      t(AF_MPLS);
	      t(RTA_VIA);
	      t(RTA_NEWDST);
	      t(RTA_ENCAP_TYPE);
	      t(RTA_ENCAP);
	      struct rtvia rtvia;
	      t(LWTUNNEL_ENCAP_MPLS);
	    ]
	  )
	],
	[bird_cv_mpls_kernel=yes],
	[bird_cv_mpls_kernel=no]
      )
    ]
  )
])

AC_DEFUN([BIRD_CHECK_ANDROID_GLOB],
[
  AC_CACHE_CHECK(
    [for glob.h],
    [bird_cv_lib_glob],
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM(
        [
	  #include <glob.h>
	  #include <stdlib.h>
	],
        [ glob(NULL, 0, NULL, NULL); ]
      )
    ],
    [bird_cv_lib_glob=yes],
      [
        bird_tmp_libs="$LIBS"
        LIBS="$LIBS -landroid-glob"
        AC_LINK_IFELSE([
          AC_LANG_PROGRAM(
            [
	      #include <glob.h>
	      #include <stdlib.h>
	    ],
            [ glob(NULL, 0, NULL, NULL); ]
          )
        ],
        [bird_cv_lib_glob=-landroid-glob],
        [bird_cv_lib_glob=no]
        )
        LIBS="$bird_tmp_libs"
      ]
    )
  )
])

AC_DEFUN([BIRD_CHECK_ANDROID_LOG],
[
  AC_CACHE_CHECK(
    [for syslog lib flags],
    [bird_cv_lib_log],
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM(
        [ #include <sys/syslog.h> ],
        [ syslog(0, ""); ]
      )
    ],
    [bird_cv_lib_log=yes],
      [
        bird_tmp_libs="$LIBS"
        LIBS="$LIBS -llog"
        AC_LINK_IFELSE([
          AC_LANG_PROGRAM(
            [ #include <sys/syslog.h> ],
            [ syslog(0, ""); ]
          )
        ],
        [bird_cv_lib_log=-llog],
        [bird_cv_lib_log=no]
        )
        LIBS="$bird_tmp_libs"
      ]
    )
  )
])

AC_DEFUN([BIRD_CHECK_LTO],
[
  bird_tmp_cflags="$CFLAGS"
  bird_tmp_ldflags="$LDFLAGS"
  CFLAGS="-flto"
  LDFLAGS="-flto=4"

  AC_CACHE_CHECK(
    [whether link time optimizer is available],
    [bird_cv_c_lto],
    [
      AC_LINK_IFELSE(
	[AC_LANG_PROGRAM()],
	[bird_cv_c_lto=yes],
	[bird_cv_c_lto=no]
      )
    ]
  )

  CFLAGS="$bird_tmp_cflags"
  LDFLAGS="$bird_tmp_ldflags"
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

AC_DEFUN([BIRD_CHECK_BISON_VERSION],
[
  $1=`bison --version | ( read line; echo ${line##* } )`
  case "$$1" in
    1.* | 2.0* | 2.1* | 2.2* | 2.3*)
      AC_MSG_ERROR([Provided Bison version $$1 is too old, need at least 2.4])
      ;;
    2.*)
      bird_bison_synclines=no
      bird_bison_enhanced_error=no
      ;;
    3.* | 4.* | 5.* | 6.* | 7.* | 8.* | 9.*)
      bird_bison_synclines=yes
      bird_bison_enhanced_error=yes
      ;;
    *)
      AC_MSG_ERROR([Couldn't parse Bison version $$1. Call the developers for help.])
      ;;
  esac
])
