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
BIGNUM *SchnorrSignature::order;
BN_CTX *SchnorrSignature::ctx;
std::once_flag SchnorrSignature::initflag;
EC_GROUP *SchnorrKeyPair::group;
BIGNUM *SchnorrKeyPair::order;
BN_CTX *SchnorrKeyPair::ctx;
std::once_flag SchnorrKeyPair::initflag;

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

SchnorrSignature SchnorrSignature::operator+(const SchnorrSignature& rh) const {
	assert(e); assert(rh.e);
	assert(s); assert(rh.s);
	SchnorrSignature res;
	res.e = BN_new();
	res.s = BN_new();
	BN_add(res.e,e,rh.e);
	BN_add(res.s,s,rh.s);
	return res;
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
	order = BN_new();
	group = EC_GROUP_new_by_curve_name(NID_secp256k1);

	EC_GROUP_get_order(group,order,ctx);

	SchnorrKeyPair::group = group;
	SchnorrKeyPair::order = order;
	SchnorrKeyPair::ctx = ctx;
}

SchnorrKeyPair SchnorrKeyPair::keygen() {
	std::call_once(initflag,SchnorrSignature::initSchnorr);
	EC_POINT *p = EC_POINT_new(group);
	BIGNUM *a = BN_new();
	BN_rand_range(a,order);
	EC_POINT_mul(group,p,a,NULL,NULL,ctx);
	return SchnorrKeyPair(a,p);
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
