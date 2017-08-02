OPTIONS = -std=c++11 -ggdb
ADDLIBS = -lcrypto -lACE
AM_CPPFLAGS = $(OPTIONS)
bin_PROGRAMS = testschnorr benchschnorr testchannel msgsender

testschnorr_SOURCES = schnorr/dkg.cpp schnorr/schnorr.cpp schnorr/test.cpp schnorr/digest.cpp
testschnorr_LDADD = $(ADDLIBS)

benchschnorr_SOURCES = schnorr/dkg.cpp schnorr/schnorr.cpp schnorr/bench.cpp schnorr/digest.cpp
benchschnorr_LDADD = $(ADDLIBS)

testchannel_SOURCES = test.cpp channel.cpp schnorr/digest.cpp schnorr/dkg.cpp schnorr/schnorr.cpp
testchannel_LDADD = $(ADDLIBS)

msgsender_SOURCES = msgsender.cpp
msgsender_LDADD = $(ADDLIBS)
