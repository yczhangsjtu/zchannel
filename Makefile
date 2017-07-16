OPTIONS = -std=c++11 -DCURVE_ALT_BN128 -DNO_PROCPS -ggdb
INCLUDE = -Ilibsnark/src -Ilibsnark/depinst/include
LIBPATH = -Llibsnark -Llibsnark/depinst/lib
LIBS    = -lsnark -lzm -lgmp -lstdc++ -lgmpxx # -lprocps
GCC			= g++

circuit: main.cpp
	$(GCC) $< -o $@ $(OPTIONS) $(INCLUDE) $(LIBPATH) $(LIBS)
