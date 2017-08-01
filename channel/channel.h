#ifndef __CHANNEL_H
#define __CHANNEL_H

#include <unordered_map>
#include <vector>
#include <cassert>
#include "schnorr/schnorr.h"
#include "schnorr/dkg.h"

using ValueType = uint64_t;
using BHeight = uint64_t;

class uint256: public std::array<unsigned char,32> {
public:
	uint256(){}
	uint256(uint64_t n){
		*((uint64_t*)data()) = n;
	}
	uint256(const std::array<unsigned char,32> &data)
		:std::array<unsigned char,32>(data){}
	uint256(const Digest<32> &data)
		:std::array<unsigned char,32>(data.getArray()){}
	Commitment commit() const;
	Commitment commit(const uint256 &trapdoor) const;
};

class ValuePair: public std::array<ValueType,2> {
};

class KeypairPair: public std::array<SchnorrKeyPair,2> {
};

class Message {
	int type;
	std::string data;
};

class Coin {
	ValueType v;
	uint256 apk,r,rho,pkcm;
	BHeight tlock;
public:
	Coin():v(0){}
	Coin(ValueType v, const uint256& apk, const uint256& r, const uint256& rho,
			 const uint256& pkcm, BHeight tlock)
		:v(v),apk(apk),r(r),rho(rho),pkcm(pkcm),tlock(tlock)
	{
	}
	inline ValueType getV()const{return v;}
	inline const uint256& getAPK()const{return apk;}
	inline const uint256& getR()const{return r;}
	inline const uint256& getRHO()const{return rho;}
	inline const uint256& getPKCM()const{return pkcm;}
	inline uint256 commit() const {
		return SHA256Digest({apk,uint256(v),r,rho,pkcm,uint256(tlock)});
	}
	inline uint256 serial(const uint256 &ask) const {
		return SHA256Digest({ask,rho});
	}
	inline BHeight getTlock()const{return tlock;}
};

class Note {
	uint256 cm1,cm2,sn1,sn2;
	SchnorrSignature sig;
public:
	Note(uint256 cm1,uint256 cm2,uint256 sn1,uint256 sn2)
		:cm1(cm1),cm2(cm2),sn1(sn1),sn2(sn2)
	{}
	inline uint256 getDigest() {
		return SHA256Digest({sn1,sn2,cm1,cm2});
	}
	inline void setSignature(const SchnorrSignature &sig) {
		this->sig = sig;
	}
	inline const SchnorrSignature& getSignature() const {
		return sig;
	}
};

class NotePair: public std::array<Note,2> {
};

class ZChannel {
	using DigestType = SHA256Digest;
	uint256 seed, ask, apk;

	enum class State { READY, WAIT_FOR_CONFIRM_SHARE,
		ESTABLISHED, WAIT_FOR_CONFIRM_CLOSE, WAIT_FOR_CONFIRM_REDEEM};

	static unsigned char ASK_LABEL;
	static unsigned char R_LABEL;
	static unsigned char RHO_LABEL;
	static unsigned char FUND_LABEL;
	static unsigned char SHARE_LABEL;
	static unsigned char CLOSE_LABEL;
	static unsigned char REDEEM_LABEL;
	static unsigned char REVOKE_LABEL;
	static constexpr BHeight MTL = ((BHeight)(-1))>>1;
	static constexpr BHeight T = 1000;

	SchnorrDKG<DigestType> shareKey, closeKey;
	KeypairPair fundKeys, closeKeys, redeemKeys, revokeKeys;

	bool useCache;
	std::unordered_map<std::string,uint256> cache;
	std::unordered_map<std::string,Message> messagePool;

	int myindex;
	int otherindex;
	State state;

	std::vector<ValuePair> values;
	std::vector<NotePair> closeNotes;
	std::vector<Note> redeemNotes;
	std::vector<Note> revocations;

	inline std::string getTag(unsigned char l1, unsigned char l2, uint64_t seq, int index, bool t) const {
		if(t) return std::to_string(l1)+":"+std::to_string(seq)+"::"+std::to_string(index);
		return std::to_string(l1)+"::"+std::to_string(l2)+":"+std::to_string(index);
	}

	inline unsigned char getLabelIndex(unsigned char label, int index) const {
		return (label&(0x3f)) | ((unsigned char)index)<<6;
	}
	inline uint256 computeASK() const {
		return SHA256Digest(seed.data(),32,&ASK_LABEL,1);
	}
	inline uint256 computeAPK() const {
		return SHA256Digest(ask.data(),32,&ASK_LABEL,1);
	}
	inline uint256 compute(unsigned char l1, unsigned char l2, uint64_t seq, int index, bool t) const {
		unsigned char indexlabel = getLabelIndex(l1,index);
		if(t) return SHA256Digest(seed.data(),32,&indexlabel,1,(unsigned char*)&seq,8);
		return SHA256Digest(seed.data(),32,&indexlabel,1,&l2,1);
	}
	inline const uint256& getASK() const {
		return ask;
	}
	inline const uint256 getAPK() const {
		return apk;
	}
	uint256 getUint256(unsigned char l1, unsigned char l2, uint64_t seq, int index, bool t);
	uint256 getR(unsigned char label, int index);
	uint256 getCloseR(uint64_t seq, int index1, int index2);
	uint256 getRHO(unsigned char label, int index);
	uint256 getCloseRHO(uint64_t seq, int index1, int index2);
public:
	ZChannel(int index):myindex(index),otherindex(1-index),useCache(false) {
		assert(index==1 || index==0);
	}
	Coin getShareCoin();
	Coin getFundCoin(int index);
	Coin getCloseCoin(uint64_t seq, int index1, int index2);
	Coin getRedeemCoin(uint64_t seq, int index);
	Coin getRevokeCoin(uint64_t seq, int index);
	Note getNote(uint64_t seq, int index);
	Note getRedeem(uint64_t seq, int index1, int index2);
	Note getRevoke(uint64_t seq, int index);

};

#endif
