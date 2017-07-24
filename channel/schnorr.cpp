#include <mutex>
#include <string>
#include <iostream>

#include <string.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>

#include "schnorr.h"

EC_GROUP *SchnorrSignature::group;
BIGNUM *SchnorrSignature::n;
BN_CTX *SchnorrSignature::ctx;
std::once_flag SchnorrSignature::initflag;

void SchnorrSignature::set(BIGNUM **dst, BIGNUM *bn) {
	if(bn == NULL) {
		if(*dst) BN_free(*dst);
		*dst = NULL;
	} else {
		if(!*dst) *dst = BN_new();
		BN_copy(*dst,bn);
	}
}

void SchnorrSignature::initSchnorr() {
	ctx = BN_CTX_new();
	n = BN_new();
	group = EC_GROUP_new_by_curve_name(NID_secp256k1);

	EC_GROUP_get_order(group,n,ctx);
}

SchnorrKeyPair SchnorrSignature::keygen() {
	std::call_once(initflag,initSchnorr);
	EC_POINT *p = EC_POINT_new(group);
	BIGNUM *a = BN_new();
	BN_rand_range(a,n);
	EC_POINT_mul(group,p,a,NULL,NULL,ctx);
	return SchnorrKeyPair(a,p);
}

SchnorrSignature SchnorrSignature::sign(const unsigned char *msg, size_t msglen, BIGNUM *a) {
	std::call_once(initflag,initSchnorr);

	int res = 0;
	BIGNUM *k = NULL;
	BIGNUM *e = NULL;
	BIGNUM *s = NULL;
	BIGNUM *x0 = NULL;
	BIGNUM *y0 = NULL;
	unsigned char x0bin[33];
	unsigned char ebin[32];
	size_t x0len;

	EC_POINT *kG = NULL;

	// Initialize all structures -----------------------
	k = BN_new();
	if(!k) {
		fprintf(stderr,"%s: Failedto create k\n",__func__);
		goto error;
	}
	e = BN_new();
	if(!e) {
		fprintf(stderr,"%s: Failedto create e\n",__func__);
		goto error;
	}
	s = BN_new();
	if(!s) {
		fprintf(stderr,"%s: Failedto create s\n",__func__);
		goto error;
	}
	x0 = BN_new();
	if(!x0) {
		fprintf(stderr,"%s: Failedto create x0\n",__func__);
		goto error;
	}
	y0 = BN_new();
	if(!y0) {
		fprintf(stderr,"%s: Failedto create y0\n",__func__);
		goto error;
	}
	kG = EC_POINT_new(group);
	if(!kG) {
		fprintf(stderr,"%s: Failed to create kG\n",__func__);
		goto error;
	}

	// Start the algorithm -----------------------------
	//
	// 1. k <-R- (0,n)
	BN_rand_range(k,n);
	// 2. (x0,y0) <- kG
	EC_POINT_mul(group,kG,k,NULL,NULL,ctx);
	EC_POINT_get_affine_coordinates_GFp(group,kG,x0,y0,ctx);
	x0len = BN_num_bytes(x0);
	BN_bn2bin(x0,x0bin);
	// 3. e <- H(x0||M)
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256,x0bin,x0len);
	SHA256_Update(&sha256,msg,msglen);
	SHA256_Final(ebin,&sha256);
	BN_bin2bn(ebin,32,e);
	// 4. s = k-ae
	BN_mod_mul(s,a,e,n,ctx);
	BN_mod_sub(s,k,s,n,ctx);

	res = 1;
error:
	if(!res) {
		fprintf(stderr,"Error in schnorr sign!\n");
	}
	SchnorrSignature sig;
	if(res == 1) {
		sig.setE(e);
		sig.setS(s);
	}
	if(k) BN_free(k);
	if(e) BN_free(e);
	if(s) BN_free(s);
	if(x0) BN_free(x0);
	if(y0) BN_free(y0);
	if(kG) EC_POINT_free(kG);
	return sig;
}

bool SchnorrSignature::verify(const unsigned char *msg, size_t msglen, EC_POINT *p) {
	int res = 0;
	bool ret;
	BIGNUM *ev = NULL;
	BIGNUM *x0 = NULL;
	BIGNUM *y0 = NULL;
	EC_POINT *kG = NULL;
	unsigned char x0bin[33];
	unsigned char ebin[32];
	size_t x0len;

	ev = BN_new();
	if(!ev) {
		fprintf(stderr,"%s: Failedto create ev\n",__func__);
		goto error;
	}
	x0 = BN_new();
	if(!x0) {
		fprintf(stderr,"%s: Failedto create x0\n",__func__);
		goto error;
	}
	y0 = BN_new();
	if(!y0) {
		fprintf(stderr,"%s: Failedto create y0\n",__func__);
		goto error;
	}
	kG = EC_POINT_new(group);
	if(!kG) {
		fprintf(stderr,"%s: Failed to create kG\n",__func__);
		goto error;
	}

	// Start verification
	EC_POINT_mul(group,kG,s,p,e,ctx);
	EC_POINT_get_affine_coordinates_GFp(group,kG,x0,y0,ctx);
	x0len = BN_num_bytes(x0);
	BN_bn2bin(x0,x0bin);
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256,x0bin,x0len);
	SHA256_Update(&sha256,msg,msglen);
	SHA256_Final(ebin,&sha256);
	BN_bin2bn(ebin,32,ev);
	ret = BN_cmp(e,ev) == 0;
	res = 1;
error:
	if(!res) {
		fprintf(stderr,"Error in schnorr verify!\n");
	}
	if(ev) BN_free(ev);
	if(x0) BN_free(x0);
	if(y0) BN_free(y0);
	if(kG) EC_POINT_free(kG);
	return ret;
}

unsigned char *SchnorrSignature::toBin() {
	unsigned char *pbuf = NULL;
	ECDSA_SIG* sig = ECDSA_SIG_new();
	sig->r = e;
	sig->s = s;
	buflen = i2d_ECDSA_SIG(sig,&pbuf);
	pbuf = buf;
	i2d_ECDSA_SIG(sig,&pbuf);
	return buf;
}

std::string SchnorrSignature::toHex() {
	if(!buflen) {
		toBin();
	}
	char hexbuf[141];
	for(int i = 0; i < buflen; i++) {
		sprintf(hexbuf+i*2,"%02x",buf[i]);
	}
	return std::string(hexbuf);
}

int main() {
	const unsigned char *msg = (const unsigned char*)"abc";
	size_t msglen = strlen((const char*)msg);
	SchnorrKeyPair keypair = SchnorrSignature::keygen();
	SchnorrSignature sig = SchnorrSignature::sign(msg,msglen,keypair.getPriv());
	std::cout << sig.toHex() << std::endl;
	std::cout << sig.verify(msg,msglen,keypair.getPub()) << std::endl;
	return 0;
}
