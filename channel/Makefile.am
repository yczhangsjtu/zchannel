OPTIONS = -std=c++11 -ggdb
ADDLIBS = -lcrypto
AM_CPPFLAGS = $(OPTIONS)
bin_PROGRAMS = testschnorr benchschnorr

testschnorr_SOURCES = schnorr/dkg.cpp schnorr/schnorr.cpp schnorr/test.cpp schnorr/digest.cpp
testschnorr_LDADD = $(ADDLIBS)

benchschnorr_SOURCES = schnorr/dkg.cpp schnorr/schnorr.cpp schnorr/bench.cpp schnorr/digest.cpp
benchschnorr_LDADD = $(ADDLIBS)
