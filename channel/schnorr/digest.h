#ifndef __DIGEST_H
#define __DIGEST_H

#include <array>
#include <string>
#include <vector>

template<size_t n>
class Digest {
protected:
	std::array<unsigned char,n> md;
public:
	Digest(){}
	Digest(std::array<unsigned char,n> md):md(md){}
	static constexpr size_t size(){return n;}
	const unsigned char* data()const{return md.data();}
	const std::array<unsigned char,n> getArray() const {return md;}
};

class SHA256Digest: public Digest<32> {
public:
	SHA256Digest(){}
	SHA256Digest(const unsigned char* msg, size_t len);
	SHA256Digest(const unsigned char* msg1, size_t len1,
			         const unsigned char* msg2, size_t len2);
	SHA256Digest(const unsigned char* msg1, size_t len1,
							 const unsigned char* msg2, size_t len2,
							 const unsigned char* msg3, size_t len3);
	SHA256Digest(std::array<unsigned char,size()> md):Digest<size()>(md){}
	SHA256Digest(std::string msg):SHA256Digest((const unsigned char *)msg.c_str(),msg.size()){}
	SHA256Digest(std::vector<std::array<unsigned char,size()>> mds);
};

#endif
