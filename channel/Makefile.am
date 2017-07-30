OPTIONS = -std=c++11 -ggdb
ADDLIBS = -lcrypto
AM_CPPFLAGS = $(OPTIONS)
bin_PROGRAMS = testschnorr

testschnorr_SOURCES = schnorr/dkg.cpp schnorr/schnorr.cpp schnorr/test.cpp
testschnorr_LDADD = $(ADDLIBS)
