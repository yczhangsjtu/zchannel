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
	// if(sig.buflen > 0) {
	// 	buf = sig.buf;
	// }
	// buflen = sig.buflen;
}

SchnorrSignature SchnorrSignature::operator+(const SchnorrSignature& rh) const {
	assert(e); assert(rh.e);
	assert(s); assert(rh.s);
	assert(BN_cmp(e,rh.e)==0);
	SchnorrSignature res;
	res.e = BN_new();
	res.s = BN_new();
	BN_copy(res.e,e);
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

size_t SchnorrSignature::toBin(unsigned char *dst) const {
	unsigned char *pbuf = dst;
	ECDSA_SIG *sig = ECDSA_SIG_new();
	sig->r = e;
	sig->s = s;
	return i2d_ECDSA_SIG(sig,&pbuf);
}

std::string SchnorrSignature::toHex() const {
	unsigned char buf[100];
	char hexbuf[200];
	size_t len = toBin(buf);
	for(size_t i = 0; i < len; i++) {
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
	}
	if(keypair.a) {
		a = BN_new();
		BN_copy(a,keypair.a);
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

Commitment SchnorrKeyPair::commit() const {
	unsigned char buf[100];
	size_t len = pubToBin(buf);
	std::array<unsigned char,32> md;
	SHA256(buf,len,md.data());
	return Commitment(md);
}

size_t SchnorrKeyPair::pubToBin(unsigned char *dst) const {
	if(!p) return 0;
	unsigned char *ppubbuf = dst;
	size_t publen = EC_POINT_point2oct(SchnorrSignature::group,p,
			POINT_CONVERSION_UNCOMPRESSED,ppubbuf,65,SchnorrSignature::ctx);
	return publen;
}

size_t SchnorrKeyPair::privToBin(unsigned char *dst) const {
	if(!a) return 0;
	unsigned char *pprivbuf = dst;
	size_t privlen = BN_bn2bin(a,pprivbuf);
	return privlen;
}

SchnorrKeyPair SchnorrKeyPair::fromHex(const std::string &s) {
	EC_POINT *p = EC_POINT_hex2point(group,s.c_str(),NULL,ctx);
	if(p) {
		SchnorrKeyPair keypair(NULL,p);
		EC_POINT_free(p);
		return keypair;
	} else return SchnorrKeyPair();
}

std::string SchnorrKeyPair::pubToHex() const {
	if(!p) return "";
	char *hex = EC_POINT_point2hex(group,p,POINT_CONVERSION_UNCOMPRESSED,ctx);
	if(hex) {
		std::string ret(hex);
		OPENSSL_free(hex);
		return ret;
	} else return "";
}

std::string SchnorrKeyPair::privToHex() const {
	if(!a) return "";
	char *hex = BN_bn2hex(a);
	if(hex) {
		std::string ret(hex);
		OPENSSL_free(hex);
		return ret;
	} else return "";
}
