OPTIONS = -std=c++11 -ggdb
ADDLIBS = -lcrypto
AM_CPPFLAGS = $(OPTIONS)
bin_PROGRAMS = dkg

dkg_SOURCES = schnorr/dkg.cpp schnorr/schnorr.cpp
dkg_LDADD = $(ADDLIBS)
