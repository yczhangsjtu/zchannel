#include <mutex>
#include <string>
#include <iostream>
#include <cassert>

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

SchnorrSignature& SchnorrSignature::operator=(const SchnorrSignature& sig) {
	if(e) BN_free(e);
	if(s) BN_free(s);
	e = s = NULL;
	set(&e,sig.e);
	set(&s,sig.s);
	if(sig.buflen > 0) {
		buf = sig.buf;
	}
	buflen = sig.buflen;
}

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
		sig = SchnorrSignature(e,s);
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

size_t SchnorrSignature::toBin(unsigned char *dst) {
	unsigned char *pbuf = NULL;
	ECDSA_SIG* sig = ECDSA_SIG_new();
	sig->r = e;
	sig->s = s;
	buflen = i2d_ECDSA_SIG(sig,&pbuf);
	pbuf = buf.data();
	i2d_ECDSA_SIG(sig,&pbuf);
	if(dst && dst != buf.data()) {
		for(size_t i = 0; i < buflen; i++)
			dst[i] = buf[i];
	}
	return buflen;
}

std::string SchnorrSignature::toHex() {
	if(!buflen) {
		toBin(NULL);
	}
	char hexbuf[141];
	for(size_t i = 0; i < buflen; i++) {
		sprintf(hexbuf+i*2,"%02x",buf[i]);
	}
	return std::string(hexbuf);
}

SchnorrKeyPair& SchnorrKeyPair::operator=(const SchnorrKeyPair& keypair) {
	if(p) EC_POINT_free(p);
	if(a) BN_free(a);
	p = NULL;
	a = NULL;
	if(keypair.p) {
		p = EC_POINT_new(SchnorrSignature::group);
		EC_POINT_copy(p,keypair.p);
		if(keypair.publen > 0) {
			pubbuf = keypair.pubbuf;
		}
		publen = keypair.publen;
	}
	if(keypair.a) {
		a = BN_new();
		BN_copy(a,keypair.a);
		if(keypair.privlen > 0) {
			privlen = keypair.privlen;
		}
		privbuf = keypair.privbuf;
	}
}

SchnorrKeyPair SchnorrKeyPair::operator+(const SchnorrKeyPair& rh) const {
	SchnorrKeyPair sum(*this);
	if(sum.a && rh.a) {
		BIGNUM *suma = BN_new();
		BN_add(suma,sum.a,rh.a);
		sum.setPriv(suma);
	} else {
		sum.setPriv(NULL);
	}
	if(sum.p && rh.p) {
		EC_POINT *sump = EC_POINT_new(SchnorrSignature::group);
		EC_POINT_add(SchnorrSignature::group,sump,sum.p,rh.p,SchnorrSignature::ctx);
		sum.setPub(sump);
	} else if(sum.getPub()) {
		sum.getPub();
	} else {
		sum.setPub(NULL);
	}
	if(sum.p) {
		assert(sum.check());
	}
	return sum;
}

SchnorrKeyPair& SchnorrKeyPair::operator+=(const SchnorrKeyPair& rh) {
	SchnorrKeyPair sum = (*this)+rh;
	*this = sum;
	return *this;
}

Commitment SchnorrKeyPair::commit() {
	if(!publen) pubToBin(NULL);
	std::array<unsigned char,32> md;
	SHA256(pubbuf.data(),publen,md.data());
	return Commitment(md);
}

size_t SchnorrKeyPair::pubToBin(unsigned char *dst) {
	unsigned char *ppubbuf = pubbuf.data();
	publen = EC_POINT_point2oct(SchnorrSignature::group,p,
			POINT_CONVERSION_UNCOMPRESSED,ppubbuf,65,SchnorrSignature::ctx);
	if(dst && dst != pubbuf.data()) {
		for(size_t i = 0; i < publen; i++)
			dst[i] = pubbuf[i];
	}
	return publen;
}

size_t SchnorrKeyPair::privToBin(unsigned char *dst) {
	unsigned char *pprivbuf = privbuf.data();
	privlen = BN_num_bytes(a);
	BN_bn2bin(a,pprivbuf);
	if(dst && dst != pubbuf.data()) {
		for(size_t i = 0; i < privlen; i++)
			dst[i] = privbuf[i];
	}
	return privlen;
}

std::string SchnorrKeyPair::pubToHex() {
	if(!publen) {
		pubToBin(NULL);
	}
	char hexbuf[131];
	for(size_t i = 0; i < publen; i++) {
		sprintf(hexbuf+i*2,"%02x",pubbuf[i]);
	}
	return std::string(hexbuf);
}

std::string SchnorrKeyPair::privToHex() {
	if(!privlen) {
		privToBin(NULL);
	}
	char hexbuf[131];
	for(size_t i = 0; i < privlen; i++) {
		sprintf(hexbuf+i*2,"%02x",privbuf[i]);
	}
	return std::string(hexbuf);
}
