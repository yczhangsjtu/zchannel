#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

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

# Checks for library functions.
# AC_FUNC_ERROR_AT_LINE
# AC_FUNC_MMAP
# AC_FUNC_STRNLEN
AC_CHECK_FUNCS([clock_gettime gettimeofday memchr memmove memset munmap pow sqrt strtol strtoul])

AC_CONFIG_FILES([Makefile
								 demo/Makefile])
# AC_CONFIG_SUBDIRS([demo])
AC_OUTPUT
