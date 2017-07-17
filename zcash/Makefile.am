OPTIONS = -std=c++11 -DCURVE_ALT_BN128 -DNO_PROCPS -ggdb
ADDLIBS = -lsnark -lsodium -lsecp256k1 -lgmp -lstdc++ -lgmpxx -lboost_thread -lboost_filesystem -lboost_system -lboost_program_options -lprocps
INCLUDE = -I$(top_srcdir)/libsnark/src -I$(top_srcdir)/libsnark/depinst/include -I$(top_srcdir)/libsodium/src/libsodium/include -I$(top_srcdir)/zcash/secp256k1/include -I$(top_srcdir)/zcash -I$(top_srcdir)
LIBPATH = -L$(top_srcdir)/libsnark -L$(top_srcdir)/libsnark/depinst/lib -L$(top_srcdir)/libsodium/src/libsodium/.libs -L$(top_srcdir)/zcash/secp256k1/.libs

AM_CPPFLAGS = $(INCLUDE) $(OPTIONS) $(ENDIANS)

bin_PROGRAMS = generate
generate_SOURCES = GenerateParams.cpp Address.cpp amount.cpp hash.cpp \
	IncrementalMerkleTree.cpp JoinSplit.cpp Note.cpp NoteEncryption.cpp prf.cpp \
	Proof.cpp pubkey.cpp random.cpp sync.cpp util.cpp utilstrencodings.cpp \
	utiltime.cpp zcashutil.cpp \
	compat/glibc_compat.cpp compat/glibc_sanity.cpp compat/glibcxx_sanity.cpp \
	compat/strnlen.cpp uint256.cpp crypto/sha512.cpp crypto/sha256.cpp \
	crypto/hmac_sha256.cpp crypto/sha1.cpp crypto/ripemd160.cpp \
	crypto/hmac_sha512.cpp crypto/equihash.cpp support/pagelocker.cpp \
	support/cleanse.cpp
generate_LDADD = $(LIBPATH) $(ADDLIBS)

# include_HEADERS = Address.hpp amount.h compat.h hash.h \
# 	IncrementalMerkleTree.hpp JoinSplit.hpp NoteEncryption.hpp Note.hpp prf.h \
# 	Proof.hpp pubkey.h serialize.h streams.h sync.h threadsafety.h tinyformat.h \
# 	uint252.h uint256.h util.h utilstrencodings.h utiltime.h version.h Zcash.h \
# 	zcashutil.h \
# 	circuit/commitment.tcc circuit/gadget.tcc circuit/merkle.tcc \
# 	circuit/note.tcc circuit/prfs.tcc circuit/utils.tcc \
# 	compat/byteswap.h compat/endian.h compat/sanity.h \
# 	crypto/common.h crypto/equihash.h crypto/equihash.tcc crypto/hmac_sha256.h \
# 	crypto/hmac_sha512.h crypto/ripemd160.h crypto/sha1.h crypto/sha256.h \
# 	crypto/sha512.h \
# 	secp256k1/include/secp256k1_ecdh.h secp256k1/include/secp256k1.h \
# 	secp256k1/include/secp256k1_recovery.h \
# 	support/cleanse.h support/events.h support/pagelocker.h \
# 	support/allocators/secure.h support/allocators/zeroafterfree.h
