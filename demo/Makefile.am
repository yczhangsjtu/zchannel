OPTIONS = -std=c++11 -DCURVE_ALT_BN128 -DNO_PROCPS -ggdb
ADDLIBS = -lsnark -lzm -lsodium -lsecp256k1 -lgmp -lstdc++ -lgmpxx# -lprocps
INCLUDE = -I$(top_srcdir)/libsnark/src -I$(top_srcdir)/libsnark/depinst/include -I$(top_srcdir)/libsodium/src/libsodium/include -I$(top_srcdir)/zcash/secp256k1/include -I$(top_srcdir)/zcash
LIBPATH = -L$(top_srcdir)/libsnark -L$(top_srcdir)/libsnark/depinst/lib -L$(top_srcdir)/libsodium/src/libsodium/.libs -L$(top_srcdir)/zcash/secp256k1/.libs

AM_CPPFLAGS = $(INCLUDE) $(OPTIONS)

bin_PROGRAMS = circuit
circuit_SOURCES = main.cpp
circuit_LDADD = $(LIBPATH) $(ADDLIBS)
