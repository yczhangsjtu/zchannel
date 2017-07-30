#include <openssl/sha.h>
#include "digest.h"

SHA256Digest::SHA256Digest(const unsigned char* msg, size_t len) {
	SHA256(msg,len,md.data());
}

SHA256Digest::SHA256Digest(const unsigned char* msg1, size_t len1, const unsigned char* msg2, size_t len2) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx,msg1,len1);
	SHA256_Update(&ctx,msg2,len2);
	SHA256_Final(md.data(),&ctx);
}
