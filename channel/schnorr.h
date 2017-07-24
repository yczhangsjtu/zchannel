#include <mutex>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <string>

class SchnorrKeyPair;
class SchnorrSignature {
	friend SchnorrKeyPair;

	BIGNUM *e,*s;

	static EC_GROUP *group;
	static BIGNUM *n;
	static BN_CTX *ctx;
	static std::once_flag initflag;

	void set(BIGNUM **dst, BIGNUM *bn);
	static void initSchnorr();
	unsigned char buf[70];
	size_t buflen = 0;
public:
	SchnorrSignature():e(NULL),s(NULL){}
	~SchnorrSignature(){
		if(e) BN_free(e);
		if(s) BN_free(s);
	}
	inline void setE(BIGNUM *bn) {
		set(&e,bn);
	}
	inline void setS(BIGNUM *bn) {
		set(&s,bn);
	}
	static SchnorrKeyPair keygen();
	static SchnorrSignature sign(const unsigned char *msg, size_t msglen, BIGNUM *a);
	bool verify(const unsigned char *msg, size_t msglen, EC_POINT *p);
	unsigned char *toBin();
	std::string toHex();
};

class SchnorrKeyPair {
	friend SchnorrSignature;
	BIGNUM *a;
	EC_POINT *p;
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
	~SchnorrKeyPair() {
		if(p) EC_POINT_free(p);
		if(a) BN_free(a);
	}
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
};
