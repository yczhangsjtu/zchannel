#ifndef __DIGEST_H
#define __DIGEST_H

#include <array>

template<size_t n>
class Digest {
protected:
	std::array<unsigned char,n> md;
public:
	Digest(){}
	Digest(std::array<unsigned char,n> md):md(md){}
	size_t size()const{return n;}
};

class SHA256Digest: public Digest<32> {
public:
	SHA256Digest() = delete;
	SHA256Digest(const unsigned char* msg, size_t len);
	SHA256Digest(const unsigned char* msg1, size_t len1, const unsigned char* msg2, size_t len2);
};

#endif
