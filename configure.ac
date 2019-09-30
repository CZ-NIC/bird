dnl ** This is a configure script template for BIRD
dnl ** Process it with autoconf to get ./configure
dnl ** (c) 1999--2000 Martin Mares <mj@ucw.cz>

AC_INIT
AC_CONFIG_SRCDIR([conf/confbase.Y])
AC_CONFIG_AUX_DIR([tools])

AC_ARG_ENABLE([client],
  [AS_HELP_STRING([--enable-client], [enable building of BIRD client @<:@yes@:>@])],
  [],
  [enable_client=yes]
)

AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug], [enable internal debugging routines @<:@no@:>@])],
  [],
  [enable_debug=no]
)

AC_ARG_ENABLE([debug-generated],
  [AS_HELP_STRING([--enable-debug-generated], [enable this to abstain from generating #line @<:@no@:>@])],
  [],
  [enable_debug_generated=no]
)

AC_ARG_ENABLE([memcheck],
  [AS_HELP_STRING([--enable-memcheck], [check memory allocations when debugging @<:@yes@:>@])],
  [],
  [enable_memcheck=yes]
)

AC_ARG_ENABLE([pthreads],
  [AS_HELP_STRING([--enable-pthreads], [enable POSIX threads support @<:@try@:>@])],
  [],
  [enable_pthreads=try]
)

AC_ARG_ENABLE([libssh],
  [AS_HELP_STRING([--enable-libssh], [enable LibSSH support together with RPKI @<:@try@:>@])],
  [],
  [enable_libssh=try]
)

AC_ARG_ENABLE([mpls-kernel],
  [AS_HELP_STRING([--enable-mpls-kernel], [enable MPLS support in kernel protocol @<:@try@:>@])],
  [],
  [enable_mpls_kernel=try]
)

AC_ARG_WITH([protocols],
  [AS_HELP_STRING([--with-protocols=LIST], [include specified routing protocols @<:@all@:>@])],
  [],
  [with_protocols="all"]
)

AC_ARG_WITH([sysconfig],
  [AS_HELP_STRING([--with-sysconfig=FILE], [use specified BIRD system configuration file])]
)

AC_ARG_WITH([runtimedir],
  [AS_HELP_STRING([--with-runtimedir=PATH], [run-state data, obsolete variant of --runstatedir])],
  [runstatedir="$with_runtimedir"]
)

AC_ARG_WITH([iproutedir],
  [AS_HELP_STRING([--with-iproutedir=PATH], [path to iproute2 config files @<:@/etc/iproute2@:>@])],
  [given_iproutedir="yes"]
)

AC_ARG_VAR([FLEX], [location of the Flex program])
AC_ARG_VAR([BISON], [location of the Bison program])
AC_ARG_VAR([M4], [location of the M4 program])


if test "$srcdir" = . ; then
  # Building in current directory => create obj directory holding all objects
  objdir=obj
else
  # Building in separate directory
  objdir=.
fi

exedir=.

AC_SUBST([objdir])
AC_SUBST([exedir])
AC_SUBST([srcdir])

# Workaround for older Autoconfs that do not define runstatedir
AS_IF([test -z "${runstatedir}"], [runstatedir='${localstatedir}/run'])
AC_SUBST([runstatedir])

CONFIG_FILE="\$(sysconfdir)/bird.conf"
AC_SUBST([CONFIG_FILE])

CONTROL_SOCKET="\$(runstatedir)/bird.ctl"
AC_SUBST([CONTROL_SOCKET])

AC_SEARCH_LIBS([clock_gettime], [rt posix4],
  [],
  [AC_MSG_ERROR([Function clock_gettime not available.])]
)

AC_CANONICAL_HOST

# Store this value because ac_test_CFLAGS is overwritten by AC_PROG_CC
if test "$ac_test_CFLAGS" != set ; then
  bird_cflags_default=yes
fi

AC_PROG_CC
AC_PROG_CC_C99
if test -z "$GCC" ; then
  AC_MSG_ERROR([This program requires the GNU C Compiler.])
fi

BIRD_CHECK_THREAD_LOCAL
if test "$bird_cv_thread_local" = yes ; then
  AC_DEFINE([HAVE_THREAD_LOCAL], [1], [Define to 1 if _Thread_local is available])
fi

if test "$enable_pthreads" != no ; then
  BIRD_CHECK_PTHREADS

  if test "$bird_cv_lib_pthreads" = yes ; then
    AC_DEFINE([USE_PTHREADS], [1], [Define to 1 if pthreads are enabled])
    CFLAGS="$CFLAGS -pthread"
    LDFLAGS="$LDFLAGS -pthread"
    proto_bfd=bfd
  elif test "$enable_pthreads" = yes ; then
    AC_MSG_ERROR([POSIX threads not available.])
  fi

  if test "$enable_pthreads" = try ; then
    enable_pthreads="$bird_cv_lib_pthreads"
  fi
fi

# This is assumed to be necessary for proper BIRD build
CFLAGS="$CFLAGS -fno-strict-aliasing -fno-strict-overflow"

if test "$bird_cflags_default" = yes ; then
  BIRD_CHECK_GCC_OPTION([bird_cv_c_option_wno_pointer_sign], [-Wno-pointer-sign], [-Wall])
  BIRD_CHECK_GCC_OPTION([bird_cv_c_option_wno_missing_init], [-Wno-missing-field-initializers], [-Wall -Wextra])

  if test "$enable_debug" = no; then
    BIRD_CHECK_LTO
  fi

  if test "$bird_cv_c_lto" = yes; then
    CFLAGS="$CFLAGS -flto"
    LDFLAGS="$LDFLAGS -flto=4 -g"
  else
    LDFLAGS="$LDFLAGS -g"
  fi

  CFLAGS="$CFLAGS -Wall -Wextra -Wstrict-prototypes -Wno-parentheses"
  BIRD_ADD_GCC_OPTION([bird_cv_c_option_wno_pointer_sign], [-Wno-pointer-sign])
  BIRD_ADD_GCC_OPTION([bird_cv_c_option_wno_missing_init], [-Wno-missing-field-initializers])
fi


AC_MSG_CHECKING([CFLAGS])
AC_MSG_RESULT([$CFLAGS])

AC_MSG_CHECKING([LDFLAGS])
AC_MSG_RESULT([$LDFLAGS])

AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_CHECK_PROG([FLEX], [flex], [flex])
AC_CHECK_PROG([BISON], [bison], [bison])
AC_CHECK_PROGS([M4], [gm4 m4])

test -z "$FLEX"	 && AC_MSG_ERROR([Flex is missing.])
test -z "$BISON" && AC_MSG_ERROR([Bison is missing.])
test -z "$M4"	 && AC_MSG_ERROR([M4 is missing.])

AC_MSG_CHECKING([bison version])
BIRD_CHECK_BISON_VERSION(BISON_VERSION)
AC_MSG_RESULT([$BISON_VERSION])
if test "$bird_bison_synclines" = yes && test "$enable_debug_generated" = no; then
  M4FLAGS="$M4FLAGS -s"
fi

if test "$bird_bison_enhanced_error" = yes; then
  BISONFLAGS="$BISONFLAGS -Dparse.lac=full -Dparse.error=verbose"
fi

AC_SUBST([M4FLAGS])
AC_SUBST([BISONFLAGS])

BIRD_CHECK_PROG_FLAVOR_GNU([$M4],
  [],
  [AC_MSG_ERROR([Provided M4 is not GNU M4.])]
)

if test -n "$with_sysconfig" -a "$with_sysconfig" != no ; then
  if test -f $with_sysconfig ; then
    sysdesc=$with_sysconfig
  else
    sysdesc=$srcdir/sysdep/cf/$with_sysconfig
    if ! test -f $sysdesc ; then
      sysdesc=$sysdesc.h
    fi
  fi
elif test -f sysconfig.h ; then
  sysdesc=sysconfig
else
  case "$host_os" in
    linux*)
      sysdesc=linux
      default_iproutedir="/etc/iproute2"
      ;;
    freebsd*)
      sysdesc=bsd
      CPPFLAGS="$CPPFLAGS -I/usr/local/include"
      LDFLAGS="$LDFLAGS -L/usr/local/lib"
      ;;
    kfreebsd*)
      sysdesc=bsd
      ;;
    netbsd*)
      sysdesc=bsd
      CPPFLAGS="$CPPFLAGS -I/usr/pkg/include"
      LDFLAGS="$LDFLAGS -L/usr/pkg/lib -R/usr/pkg/lib"
      ;;
    openbsd*)
      sysdesc=bsd
      ;;
    dragonfly*)
      sysdesc=bsd
      ;;
    *)
      AC_MSG_ERROR([Cannot determine correct system configuration. Please use --with-sysconfig to set it manually.])
      ;;
    esac
    sysdesc=$srcdir/sysdep/cf/$sysdesc.h
fi
AC_MSG_CHECKING([which OS configuration should we use])
AC_MSG_RESULT([$sysdesc])
if ! test -f $sysdesc ; then
  AC_MSG_ERROR([The system configuration file is missing.])
fi
sysname=`echo $sysdesc | sed 's/\.h$//'`
AC_DEFINE_UNQUOTED([SYSCONF_INCLUDE], ["$sysdesc"], [Which sysdep header to include])

AC_MSG_CHECKING([system-dependent directories])
sysdep_dirs="`sed <$sysdesc '/^Link: /!d;s/^Link: \(.*\)$/\1/' | tr '\012' ' '`"
AC_MSG_RESULT([$sysdep_dirs])
AC_SUBST([sysdep_dirs])

if test "$with_iproutedir" = no ; then with_iproutedir= ; fi

if test -n "$given_iproutedir"
then iproutedir=$with_iproutedir
else iproutedir=$default_iproutedir
fi

AC_SUBST([iproutedir])

DAEMON_LIBS=
AC_SUBST(DAEMON_LIBS)

if test "$enable_libssh" != no ; then
  AC_CHECK_HEADER([libssh/libssh.h], [true], [fail=yes], [ ])
  AC_CHECK_LIB([ssh], [ssh_connect], [true], [fail=yes])

  if test "$fail" != yes ; then
    AC_DEFINE([HAVE_LIBSSH], [1], [Define to 1 if you have the `ssh' library (-lssh).])
    DAEMON_LIBS="-lssh $DAEMON_LIBS"
    proto_rpki=rpki
    enable_libssh=yes
  else
    if test "$enable_libssh" = yes ; then
      AC_MSG_ERROR([LibSSH not available.])
    else
      enable_libssh=no
    fi
  fi
fi

if test "$enable_mpls_kernel" != no ; then
  BIRD_CHECK_MPLS_KERNEL

  if test "$bird_cv_mpls_kernel" = yes ; then
    AC_DEFINE([HAVE_MPLS_KERNEL], [1], [Define to 1 if kernel is MPLS capable])
  elif test "$enable_mpls_kernel" = yes ; then
    AC_MSG_ERROR([Kernel MPLS support not found.])
  fi

  if test "$enable_mpls_kernel" = try ; then
    enable_mpls_kernel="$bird_cv_mpls_kernel"
  fi
fi

all_protocols="$proto_bfd babel bgp mrt ospf perf pipe radv rip $proto_rpki static"

all_protocols=`echo $all_protocols | sed 's/ /,/g'`

if test "$with_protocols" = all ; then
  with_protocols="$all_protocols"
fi

AH_TEMPLATE([CONFIG_BABEL], 	[Babel protocol])
AH_TEMPLATE([CONFIG_BFD],	[BFD protocol])
AH_TEMPLATE([CONFIG_BGP],	[BGP protocol])
AH_TEMPLATE([CONFIG_MRT],	[MRT protocol])
AH_TEMPLATE([CONFIG_OSPF],	[OSPF protocol])
AH_TEMPLATE([CONFIG_PIPE],	[Pipe protocol])
AH_TEMPLATE([CONFIG_RADV],	[RAdv protocol])
AH_TEMPLATE([CONFIG_RIP],	[RIP protocol])
AH_TEMPLATE([CONFIG_RPKI],	[RPKI protocol])
AH_TEMPLATE([CONFIG_STATIC],	[Static protocol])

AC_MSG_CHECKING([protocols])
protocols=`echo "$with_protocols" | sed 's/,/ /g'`
if test "$protocols" = no ; then protocols= ; fi
for a in $protocols ; do
  if ! test -f $srcdir/proto/$a/Makefile ; then
    AC_MSG_RESULT([failed])
    AC_MSG_ERROR([Requested protocol $a not found])
  fi
  AC_DEFINE_UNQUOTED([CONFIG_`echo $a | tr 'a-z' 'A-Z'`])
done
AC_MSG_RESULT([ok])
AC_SUBST([protocols])

case $sysdesc in
  */linux*)
    AC_CHECK_HEADER([linux/rtnetlink.h],
      [],
      [AC_MSG_ERROR([Appropriate version of Linux kernel headers not found.])],
      [
	dnl Some older versions of Linux kernel headers require these includes
	#include <asm/types.h>
	#include <sys/socket.h>
      ]
    )
    ;;
esac

AC_CHECK_HEADERS_ONCE([alloca.h syslog.h])
AC_CHECK_MEMBERS([struct sockaddr.sa_len], [], [], [#include <sys/socket.h>])

AC_C_BIGENDIAN(
  [AC_DEFINE([CPU_BIG_ENDIAN], [1], [Define to 1 if cpu is big endian])],
  [AC_DEFINE([CPU_LITTLE_ENDIAN], [1], [Define to 1 if cpu is little endian])],
  [AC_MSG_ERROR([Cannot determine CPU endianity.])]
)

BIRD_CHECK_ANDROID_GLOB
if test "$bird_cv_lib_glob" = no ; then
  AC_MSG_ERROR([glob.h not found.])
elif test "$bird_cv_lib_glob" != yes ; then
  LIBS="$LIBS $bird_cv_lib_glob"
fi

BIRD_CHECK_ANDROID_LOG
if test "$bird_cv_lib_log" = no ; then
  AC_MSG_ERROR([don't know how to link syslog.])
elif test "$bird_cv_lib_log" != yes ; then
  LIBS="$LIBS $bird_cv_lib_log"
fi

if test "$enable_debug" = yes ; then
  AC_DEFINE([DEBUGGING], [1], [Define to 1 if debugging is enabled])
  LDFLAGS="$LDFLAGS -rdynamic"
  CFLAGS="$CFLAGS -O0 -ggdb -g3"

  BIRD_CHECK_GCC_OPTION([bird_cv_c_option_dwarf4], [-gdwarf-4], [])
  BIRD_ADD_GCC_OPTION([bird_cv_c_option_dwarf4], [-gdwarf-4])

  AC_CHECK_HEADER([execinfo.h],
    [
      AC_DEFINE([HAVE_EXECINFO_H], [1], [Define to 1 if you have the <execinfo.h> header file.])
      AC_SEARCH_LIBS([backtrace], [execinfo],
	[],
	[AC_MSG_ERROR([Function backtrace not available.])]
      )
    ]
  )

  if test "$enable_memcheck" = yes ; then
    AC_CHECK_LIB([dmalloc], [dmalloc_debug])
    if test $ac_cv_lib_dmalloc_dmalloc_debug != yes ; then
      AC_CHECK_LIB([efence], [malloc])
    fi
  fi
fi

CLIENT=birdcl
CLIENT_LIBS=
if test "$enable_client" = yes ; then
  CLIENT="$CLIENT birdc"
  BASE_LIBS="$LIBS"
  LIBS=""

  AC_CHECK_HEADERS([curses.h],
    [],
    [AC_MSG_ERROR([The client requires ncurses library. Either install the library or use --disable-client to compile without the client.])],
    [AC_INCLUDES_DEFAULT]
  )

  AC_SEARCH_LIBS([tgetent], [tinfo tinfow ncurses curses termcap],
    [TINFO_LIBS="$LIBS"; LIBS=""],
    [AC_MSG_ERROR([The client requires ncurses library. Either install the library or use --disable-client to compile without the client.])],
  )

  AC_CHECK_HEADERS([readline/readline.h readline/history.h],
    [],
    [AC_MSG_ERROR([The client requires GNU Readline library. Either install the library or use --disable-client to compile without the client.])],
    [AC_INCLUDES_DEFAULT]
  )

  AC_SEARCH_LIBS([rl_callback_read_char], [readline],
    [READLINE_LIBS="$LIBS"; LIBS=""],
    [AC_MSG_ERROR([The client requires GNU Readline library. Either install the library or use --disable-client to compile without the client.])],
    [$TINFO_LIBS]
  )

  AC_CHECK_LIB([readline], [rl_crlf],
    [AC_DEFINE([HAVE_RL_CRLF], [1], [Define to 1 if you have rl_crlf()])],
    [],
    [$TINFO_LIBS]
  )

  AC_CHECK_LIB([readline], [rl_ding],
    [AC_DEFINE([HAVE_RL_DING], [1], [Define to 1 if you have rl_ding()])],
    [],
    [$TINFO_LIBS]
  )

  LIBS="$BASE_LIBS"
  CLIENT_LIBS="$READLINE_LIBS $TINFO_LIBS"
fi
AC_SUBST([CLIENT])
AC_SUBST([CLIENT_LIBS])

mkdir -p $objdir/sysdep
AC_CONFIG_HEADERS([$objdir/sysdep/autoconf.h:sysdep/autoconf.h.in])
AC_CONFIG_FILES([Makefile:Makefile.in])
AC_OUTPUT

AC_MSG_RESULT()
AC_MSG_RESULT([BIRD was configured with the following options:])
AC_MSG_RESULT([        Source directory:	$srcdir])
AC_MSG_RESULT([        Object directory:	$objdir])
AC_MSG_RESULT([        Iproute2 directory:	$iproutedir])
AC_MSG_RESULT([        System configuration:	$sysdesc])
AC_MSG_RESULT([        Debugging:		$enable_debug])
AC_MSG_RESULT([        POSIX threads:		$enable_pthreads])
AC_MSG_RESULT([        Routing protocols:	$protocols])
AC_MSG_RESULT([        Kernel MPLS support:	$enable_mpls_kernel])
AC_MSG_RESULT([        Client:			$enable_client])

rm -f $objdir/.*-stamp
