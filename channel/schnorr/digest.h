#ifndef __DIGEST_H
#define __DIGEST_H

#include <array>
#include <string>
#include <vector>
#include <cassert>

inline unsigned char x2c(char x) {
	if(x>='0'&&x<='9') return x-'0';
	if(x>='a'&&x<='f') return x-'a'+0xa;
	if(x>='A'&&x<='F') return x-'A'+0xA;
	assert(0);
}

template<size_t size>
std::string bin2hex(const std::array<unsigned char,size> &data) {
	char buf[size*2+1];
	for(size_t i = 0; i < size; i++) {
		sprintf(&buf[2*i],"%02x",data[i]);
	}
	buf[size*2] = '\0';
	return std::string(buf);
}

template<size_t size>
std::array<unsigned char,size> hex2bin(const std::string& s) {
	assert(s.size() == size*2);
	std::array<unsigned char,size> n;
	for(size_t i = 0; i < size; i++)
		n[i] = (x2c(s[2*i])<<4)|(x2c(s[2*i+1]));
	return n;
}

inline void hex2bin(const std::string& s, unsigned char buf[]) {
	size_t size = s.size()/2;
	assert(s.size() == size*2);
	for(size_t i = 0; i < size; i++)
		buf[i] = (x2c(s[2*i])<<4)|(x2c(s[2*i+1]));
}

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
	std::string toHex() const {
		return bin2hex<n>(md);
	}
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
