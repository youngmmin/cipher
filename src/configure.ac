AC_PREREQ(2.65)
AC_INIT([Petra Cipher], [3.2], [rnd-cipher@sinsiway.com])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign])


AC_OBJEXT
AC_PROG_CC          dnl Enable make rules CC, CFLAGS
AC_PROG_CXX         dnl Enable make rules CXX, CXXFLAGS
AC_PROG_LN_S        dnl Enable make rules LN_S
AC_PROG_AWK         dnl Enable make rules AWK, AWKFLAGS
AC_PROG_CPP         dnl Enable make rules CPP, CPPFLAGS
AC_PROG_MAKE_SET    dnl Enable make rules GREP, EGREP

dnl         check for host type
AC_CANONICAL_HOST

AREXT=a
SOEXT=so

AC_ARG_VAR([PETRA_ROOT_DIR], [Path to Petra root directory])
if test -z "$PETRA_ROOT_DIR"; then
    AC_MSG_ERROR([PETRA_ROOT_DIR is required])
fi

if test ! -d "$PETRA_ROOT_DIR"; then
    AC_MSG_ERROR([Cannot find the "$PETRA_ROOT_DIR" path assigned to PETRA_ROOT_DIR])
fi

PETRA_ROOT_DIR=$(cd $PETRA_ROOT_DIR; pwd)
AC_SUBST([PETRA_ROOT_DIR])


AC_ARG_VAR([PETRA_TOOLS_DIR], [Path to Petra tools directory])
if test -z "$PETRA_TOOLS_DIR"; then
    AC_MSG_ERROR([PETRA_TOOLS_DIR is required])
fi

if test ! -d "$PETRA_TOOLS_DIR"; then
    AC_MSG_ERROR([Cannot find the "$PETRA_TOOLS_DIR" path assigned to PETRA_TOOLS_DIR])
fi
PETRA_TOOLS_DIR=$(cd $PETRA_TOOLS_DIR; pwd)
AC_SUBST([PETRA_TOOLS_DIR])

AC_ARG_ENABLE([b64],
              [AS_HELP_STRING([--enable-b64],
                              [Use -m64 flag on Linux and Solaris, -maix64 on AIX, -mlp64 on HP-UX if supported (@<:@default=yes@:>@)])],
              [],
              [enable_b64=yes])

AS_IF([test "x$enable_b64" = "xyes"], [suffix=64], [suffix=32])

case "$host_os" in
    *linux*|*solaris*)
        # Use -m64 on Linux, Solaris if supported, otherwise use -m32
        AC_MSG_CHECKING([whether $CC and $CXX accept -m64])
        CFLAGS="$CFLAGS -m$suffix"
        CXXFLAGS="$CXXFLAGS -m$suffix"
        ;;
    ia64-*-hpux*)
        # On the PA-RISC (hppa) architecture in HP-UX, compilation is performed based on the system architecture.
        # Therefore, for HP-UX, the options are applied only in an ia64 environment using the C/aC++ compiler.
        # Use -mlp64 on HP-UX if supported, otherwise use -mlp32
        AC_MSG_CHECKING([whether $CC and $CXX accept -mlp64])
        CFLAGS="$CFLAGS -mlp$suffix"
        CXXFLAGS="$CXXFLAGS -mlp$suffix"
        ;;
    *-*-hpux*)
        # On the PA-RISC (hppa) architecture in HP-UX, compilation is performed based on the system architecture.
        SOEXT=sl
        ;;
    *aix*)
        # Use -maix64 on AIX if supported, otherwise use -maix32
        AC_MSG_CHECKING([whether $CC and $CXX accept -maix64])
        CFLAGS="$CFLAGS -maix$suffix"
        CXXFLAGS="$CXXFLAGS -maix$suffix"
        ;;
    *)
        AC_MSG_ERROR([unsupported operating system "$host_os"])
        ;;
esac

AC_ARG_WITH([pic],
    [AS_HELP_STRING([--with-pic], [build position independent code @<:@default=yes@:>@])],
    [],
    [with_pic=yes]
)

AS_IF([test "x$with_pic" = "xyes" || "x$with_pic" = "x"],
            [
                CFLAGS="$CFLAGS -fPIC"
                CXXFLAGS="$CXXFLAGS -fPIC"
            ]
        )

# srcdir=$(pwd)

SHLDXX="$CXX -shared"
AC_SUBST([SHLDXX])
AC_SUBST([SOEXT])
AC_SUBST([AREXT])

AC_CHECK_LIB(m, main)
AC_CHECK_LIB(dl, main)
AC_CHECK_LIB(rt, main)
AC_CHECK_LIB(pthread, main)

AC_CONFIG_FILES([Makefile.inc])

AC_OUTPUT