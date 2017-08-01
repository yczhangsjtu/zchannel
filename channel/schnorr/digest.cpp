#include <vector>
#include <openssl/sha.h>
#include "digest.h"

SHA256Digest::SHA256Digest(const unsigned char* msg, size_t len) {
	SHA256(msg,len,md.data());
}

SHA256Digest::SHA256Digest(const unsigned char* msg1, size_t len1,
													 const unsigned char* msg2, size_t len2) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx,msg1,len1);
	SHA256_Update(&ctx,msg2,len2);
	SHA256_Final(md.data(),&ctx);
}

SHA256Digest::SHA256Digest(const unsigned char* msg1, size_t len1,
													 const unsigned char* msg2, size_t len2,
													 const unsigned char* msg3, size_t len3) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx,msg1,len1);
	SHA256_Update(&ctx,msg2,len2);
	SHA256_Update(&ctx,msg3,len3);
	SHA256_Final(md.data(),&ctx);
}

SHA256Digest::SHA256Digest(std::vector<std::array<unsigned char,size()>> mds) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	for(size_t i = 0; i < mds.size(); i++) {
		SHA256_Update(&ctx,mds.data(),size());
	}
	SHA256_Final(md.data(),&ctx);
}
