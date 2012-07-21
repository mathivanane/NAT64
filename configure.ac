AC_INIT([WrapSix], [0.1.99.0], [xhire@mujmalysvet.cz])
AM_INIT_AUTOMAKE([-Wall -Werror])

# prevent automatic adding of "-g -O2" to CFLAGS
OLD_CFLAGS=$CFLAGS
AC_PROG_CC
CFLAGS=$OLD_CFLAGS

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])

###
# Configuration options
###

AC_ARG_ENABLE([debug],
	      AS_HELP_STRING([--enable-debug], [enable debugging]),
	      [debug=$enableval],
	      [debug=no])

if test "x$debug" = "xyes"; then
	AM_CFLAGS="${AM_CFLAGS} -g -ggdb -O0 -pipe -pedantic -Wshadow -Wall -Wextra -Wno-missing-field-initializers -Wno-unused-parameter -Wold-style-definition -Wdeclaration-after-statement -Wmissing-declarations -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Winline -Wformat-nonliteral -Wformat-security -Wswitch-enum -Winit-self -Wmissing-include-dirs -Wundef -Waggregate-return -Wnested-externs -Wunsafe-loop-optimizations"
	AC_DEFINE([DEBUG])
else
        AM_CFLAGS="${AM_CFLAGS} -O2"
fi

###
# Final commands
###

AC_SUBST([AM_CFLAGS])

AC_OUTPUT
