#ifndef __SCHNORR_H__
#define __SCHNORR_H__

#include <mutex>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <string>
#include <iostream>

class SchnorrKeyPair;
class SchnorrSignature {
	friend SchnorrKeyPair;

	BIGNUM *e,*s;
	unsigned char buf[70];
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
	~SchnorrSignature(){
		if(e) BN_free(e);
		if(s) BN_free(s);
	}

	static SchnorrKeyPair keygen();
	static SchnorrSignature sign(const unsigned char *msg, size_t msglen, BIGNUM *a);
	bool verify(const unsigned char *msg, size_t msglen, EC_POINT *p);
	size_t toBin(unsigned char *dst);
	std::string toHex();
};

class SchnorrKeyPair {
	friend SchnorrSignature;
	BIGNUM *a;
	EC_POINT *p;
	unsigned char pubbuf[65];
	unsigned char privbuf[32];
	size_t publen = 0;
	size_t privlen = 0;
public:
	SchnorrKeyPair():a(NULL),p(NULL){}
	SchnorrKeyPair(BIGNUM *_a,EC_POINT *_p){
		std::call_once(SchnorrSignature::initflag,SchnorrSignature::initSchnorr);
		if(_p) {
			p = EC_POINT_new(SchnorrSignature::group);
			EC_POINT_copy(p,_p);
		}
		else p = NULL;
		if(_a) {
			a = BN_new();
			BN_copy(a,_a);
		} else a = NULL;
	}
	SchnorrKeyPair(const SchnorrKeyPair& keypair):SchnorrKeyPair(keypair.a,keypair.p) {
	}
	~SchnorrKeyPair() {
		if(p) EC_POINT_free(p);
		if(a) BN_free(a);
	}
	SchnorrKeyPair& operator=(const SchnorrKeyPair& keypair);
	inline EC_POINT *getPub() {
		return p;
	}
	inline BIGNUM *getPriv() {
		return a;
	}
	inline SchnorrKeyPair pubkey() {
		return SchnorrKeyPair(NULL,p);
	}
	inline SchnorrKeyPair privkey() {
		return SchnorrKeyPair(a,NULL);
	}
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
