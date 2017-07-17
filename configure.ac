#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_LANG(C++)

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
# AC_CHECK_LIB([boost_program_options], [boost::program_options::notify])
AC_CHECK_LIB([crypto], [OPENSSL_init])
AC_CHECK_LIB([dl], [dlopen])
AC_CHECK_LIB([gmp], [__gmpz_init])
# AX_CXX_CHECK_LIB([gmpxx], [mpz_class::get_mpz_t])
AC_CHECK_LIB([pthread], [pthread_create])

AC_C_BIGENDIAN
AC_CHECK_HEADERS([endian.h sys/endian.h byteswap.h stdio.h stdlib.h unistd.h strings.h sys/types.h sys/stat.h sys/select.h sys/prctl.h])
AC_SEARCH_LIBS([getaddrinfo_a], [anl], [AC_DEFINE(HAVE_GETADDRINFO_A, 1, [Define this symbol if you have getaddrinfo_a])])
AC_SEARCH_LIBS([inet_pton], [nsl resolv], [AC_DEFINE(HAVE_INET_PTON, 1, [Define this symbol if you have inet_pton])])
AC_CHECK_DECLS([strnlen])
AC_CHECK_DECLS([le16toh, le32toh, le64toh, htole16, htole32, htole64, be16toh, be32toh, be64toh, htobe16, htobe32, htobe64],,,
		[#if HAVE_ENDIAN_H
                 #include <endian.h>
                 #elif HAVE_SYS_ENDIAN_H
                 #include <sys/endian.h>
                 #endif])
AC_CHECK_DECLS([bswap_16, bswap_32, bswap_64],,,
		[#if HAVE_BYTESWAP_H
                 #include <byteswap.h>
                 #endif])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h malloc.h memory.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AX_BOOST_BASE
AX_BOOST_SYSTEM
AX_BOOST_FILESYSTEM
AX_BOOST_PROGRAM_OPTIONS
AX_BOOST_THREAD
AX_BOOST_CHRONO

BOOST_LIBS="$BOOST_LDFLAGS $BOOST_SYSTEM_LIB $BOOST_FILESYSTEM_LIB $BOOST_PROGRAM_OPTIONS_LIB $BOOST_THREAD_LIB $BOOST_CHRONO_LIB"

dnl Boost >= 1.50 uses sleep_for rather than the now-deprecated sleep, however
dnl it was broken from 1.50 to 1.52 when backed by nanosleep. Use sleep_for if
dnl a working version is available, else fall back to sleep. sleep was removed
dnl after 1.56.
dnl If neither is available, abort.
TEMP_LIBS="$LIBS"
LIBS="$BOOST_LIBS $LIBS"
TEMP_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $BOOST_CPPFLAGS"
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
  #include <boost/thread/thread.hpp>
  #include <boost/version.hpp>
  ]],[[
  #if BOOST_VERSION >= 105000 && (!defined(BOOST_HAS_NANOSLEEP) || BOOST_VERSION >= 105200)
      boost::this_thread::sleep_for(boost::chrono::milliseconds(0));
  #else
   choke me
  #endif
  ]])],
  [boost_sleep=yes;
     AC_DEFINE(HAVE_WORKING_BOOST_SLEEP_FOR, 1, [Define this symbol if boost sleep_for works])],
  [boost_sleep=no])
LIBS="$TEMP_LIBS"
CPPFLAGS="$TEMP_CPPFLAGS"

AC_MSG_CHECKING([for working boost reduced exports])
TEMP_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$BOOST_CPPFLAGS $CPPFLAGS"
AC_PREPROC_IFELSE([AC_LANG_PROGRAM([[
		@%:@include <boost/version.hpp>
	]], [[
		#if BOOST_VERSION >= 104900
		// Everything is okay
		#else
		#  error Boost version is too old
		#endif
	]])],[
		AC_MSG_RESULT(yes)
	],[
	AC_MSG_ERROR([boost versions < 1.49 are known to be broken with reduced exports. Use --disable-reduce-exports.])
])
CPPFLAGS="$TEMP_CPPFLAGS"

TEMP_LIBS="$LIBS"
LIBS="$BOOST_LIBS $LIBS"
TEMP_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $BOOST_CPPFLAGS"
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
  #include <boost/version.hpp>
  #include <boost/thread.hpp>
  #include <boost/date_time/posix_time/posix_time_types.hpp>
  ]],[[
  #if BOOST_VERSION <= 105600
      boost::this_thread::sleep(boost::posix_time::milliseconds(0));
  #else
   choke me
  #endif
  ]])],
  [boost_sleep=yes; AC_DEFINE(HAVE_WORKING_BOOST_SLEEP, 1, [Define this symbol if boost sleep works])],
  [boost_sleep=no])
LIBS="$TEMP_LIBS"
CPPFLAGS="$TEMP_CPPFLAGS"

#glibc absorbed clock_gettime in 2.17. librt (its previous location) is safe to link
#in anyway for back-compat.
AC_CHECK_LIB([rt],[clock_gettime],, AC_MSG_ERROR(lib missing))

#__fdelt_chk's params and return type have changed from long unsigned int to long int.
# See which one is present here.
AC_MSG_CHECKING(__fdelt_chk type)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#ifdef _FORTIFY_SOURCE
									#undef _FORTIFY_SOURCE
								#endif
								#define _FORTIFY_SOURCE 2
								#include <sys/select.h>
	 extern "C" long unsigned int __fdelt_warn(long unsigned int);]],[[]])],
	[ fdelt_type="long unsigned int"],
	[ fdelt_type="long int"])
AC_MSG_RESULT($fdelt_type)
AC_DEFINE_UNQUOTED(FDELT_TYPE, $fdelt_type,[parameter and return value type for __fdelt_chk])

# Checks for library functions.
# AC_FUNC_ERROR_AT_LINE
# AC_FUNC_MMAP
# AC_FUNC_STRNLEN
AC_CHECK_FUNCS([clock_gettime gettimeofday memchr memmove memset munmap pow sqrt strtol strtoul])

AC_CONFIG_FILES([Makefile
								 demo/Makefile
								 zcash/Makefile])
# AC_CONFIG_SUBDIRS([demo])
AC_OUTPUT
