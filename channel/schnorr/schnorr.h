#ifndef __SCHNORR_H__
#define __SCHNORR_H__

#include <mutex>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <string>
#include <iostream>

class Commitment {
	std::array<unsigned char,32> digest;
public:
	Commitment(){}
	Commitment(std::array<unsigned char,32> md): digest(md){}
};

class SchnorrKeyPair;
class SchnorrSignature {
	friend SchnorrKeyPair;

	BIGNUM *e,*s;
	std::array<unsigned char,70> buf;
	size_t buflen = 0;

	static EC_GROUP *group;
	static BIGNUM *n;
	static BN_CTX *ctx;
	static std::once_flag initflag;

	void set(BIGNUM **dst, BIGNUM *bn);
	static void initSchnorr();

public:

	SchnorrSignature():e(NULL),s(NULL){}
	SchnorrSignature(BIGNUM *_e, BIGNUM *_s) {
		e = s = NULL;
		set(&e,_e);
		set(&s,_s);
	}
	SchnorrSignature(const SchnorrSignature& sig): SchnorrSignature(sig.e,sig.s) {
	}
	SchnorrSignature& operator=(const SchnorrSignature& sig);
	SchnorrSignature operator+(const SchnorrSignature& rh) const;
	~SchnorrSignature(){
		if(e) BN_free(e);
		if(s) BN_free(s);
	}

	size_t toBin(unsigned char *dst);
	std::string toHex();
};

class SchnorrKeyPair {
	friend SchnorrSignature;
	BIGNUM *a;
	EC_POINT *p;
	std::array<unsigned char,65> pubbuf;
	std::array<unsigned char,32> privbuf;
	size_t publen = 0;
	size_t privlen = 0;

	static std::once_flag initflag;
	static EC_GROUP *group;
	static BIGNUM *n;
	static BN_CTX *ctx;
public:
	SchnorrKeyPair():a(NULL),p(NULL){}
	SchnorrKeyPair(BIGNUM *_a,EC_POINT *_p){
		std::call_once(SchnorrSignature::initflag,SchnorrSignature::initSchnorr);
		a = NULL;
		p = NULL;
		setPub(_p);
		setPriv(_a);
	}
	SchnorrKeyPair(const SchnorrKeyPair& keypair):SchnorrKeyPair(keypair.a,keypair.p) {
	}
	~SchnorrKeyPair() {
		if(p) EC_POINT_free(p);
		if(a) BN_free(a);
	}
	SchnorrKeyPair& operator=(const SchnorrKeyPair& keypair);
	SchnorrKeyPair operator+(const SchnorrKeyPair& rh) const;
	SchnorrKeyPair& operator+=(const SchnorrKeyPair& rh);
	EC_POINT *getPub() {
		if(a && !p) {
			p = EC_POINT_new(SchnorrSignature::group);
			EC_POINT_mul(SchnorrSignature::group,p,a,NULL,NULL,SchnorrSignature::ctx);
		}
		return p;
	}
	inline BIGNUM *getPriv() {
		return a;
	}
	void setPub(const EC_POINT* pub) {
		if(p) EC_POINT_free(p);
		if(pub) {
			p = EC_POINT_new(SchnorrSignature::group);
			EC_POINT_copy(p,pub);
		}
		else p = NULL;
	}
	void setPriv(const BIGNUM *priv) {
		if(a) BN_free(a);
		if(priv) {
			a = BN_new();
			BN_copy(a,priv);
		} else a = NULL;
	}

	bool check() {
		bool ret;
		if(a && p) {
			EC_POINT *tmp = EC_POINT_new(SchnorrSignature::group);
			EC_POINT_mul(SchnorrSignature::group,tmp,a,NULL,NULL,SchnorrSignature::ctx);
			ret = EC_POINT_cmp(SchnorrSignature::group,tmp,p,SchnorrSignature::ctx) == 0;
			EC_POINT_free(tmp);
		} else {
			ret = true;
		}
		return ret;
	}

	Commitment commit();
	
	inline SchnorrKeyPair pubkey() {
		return SchnorrKeyPair(NULL,p);
	}
	inline SchnorrKeyPair privkey() {
		return SchnorrKeyPair(a,NULL);
	}
	static SchnorrKeyPair keygen();
	SchnorrSignature sign(const unsigned char *msg, size_t msglen) const;
	bool verify(const unsigned char *msg, size_t msglen, const SchnorrSignature &sig) const;
	size_t pubToBin(unsigned char* dst);
	size_t privToBin(unsigned char* dst);
	std::string pubToHex();
	std::string privToHex();
	inline void print() {
		std::cout << "pub  key:" << pubToHex() << std::endl;
		std::cout << "priv key:" << privToHex() << std::endl;
	}
};

#endif
