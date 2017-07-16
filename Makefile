OPTIONS = -std=c++11 -DCURVE_ALT_BN128 -DNO_PROCPS -ggdb
INCLUDE = -Ilibsnark/src -Ilibsnark/depinst/include -Ilibsodium/src/libsodium/include -Izcash/secp256k1/include
LIBPATH = -Llibsnark -Llibsnark/depinst/lib -Llibsodium/src/libsodium
LIBS    = -lsnark -lzm -lsodium -lgmp -lstdc++ -lgmpxx# -lprocps
GCC			= g++

circuit: main.cpp
	$(GCC) $< -o $@ $(OPTIONS) $(INCLUDE) $(LIBPATH) $(LIBS)
