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
	uint256(std::array<unsigned char,32> data)
		:std::array<unsigned char,32>(data){}
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
	uint256 r,rho,pkcm;
	BHeight tlock;
};

class Note {
	uint256 cm1,cm2,sn1,sn2;
	SchnorrSignature sig;
public:
	Note(uint256 cm1,uint256 cm2,uint256 sn1,uint256 sn2)
		:cm1(cm1),cm2(cm2),sn1(sn1),sn2(sn2)
	{}
	inline uint256 getDigest() {
		return SHA256Digest({sn1,sn2,cm1,cm2}).getArray();
	}
	inline void setSignature(const SchnorrSignature &sig) {
		this->sig = sig;
	}
	inline const SchnorrSignature& getSignature() const {
		return sig;
	}
};

class ZChannel {
	using DigestType = SHA256Digest;
	uint256 seed, ask, apk;

	enum class State { READY, WAIT_FOR_CONFIRM_SHARE,
		ESTABLISHED, WAIT_FOR_CONFIRM_CLOSE, WAIT_FOR_CONFIRM_REDEEM};

	SchnorrDKG<DigestType> shareKey, closeKey;
	KeypairPair fundKeys, closeKeys, redeemKeys, revokeKeys;

	bool useCache;
	std::unordered_map<std::string,uint256> cache;
	std::unordered_map<std::string,Message> messagePool;

	int myindex;
	int otherindex;
	State state;

	std::vector<ValuePair> v;
public:
	ZChannel(int index):myindex(index),otherindex(1-index) {
		assert(index==1 || index==0);
	}
	Coin getShareCoin(int seq, int index);
	Coin getFundCoin(int index);
	Coin getCloseCoin(int seq, int index);
	Coin getRedeemCoin(int seq, int index);
	Coin getRevokeCoin(int seq, int index);
	Note getNote(int seq, int index);

};

#endif
