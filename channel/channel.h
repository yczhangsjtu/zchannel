#ifndef __CHANNEL_H
#define __CHANNEL_H

#include <unordered_map>
#include <vector>
#include <cassert>
#include <mutex>
#include <cstdio>
#include "openssl/rand.h"
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
	static constexpr uint64_t size() {return 32;}
	uint256(const std::array<unsigned char,32> &data)
		:std::array<unsigned char,32>(data){}
	uint256(const Digest<32> &data)
		:std::array<unsigned char,32>(data.getArray()){}
	Commitment commit() const;
	Commitment commit(const uint256 &trapdoor) const;

	inline std::string toHex() const {
		return bin2hex(*this);
	}

	inline static uint256 fromHex(const std::string& s) {
		return hex2bin<32>(s);
	}

	inline void randomize() {
		RAND_bytes(data(),size());
	}

	inline static uint256 rand() {
		uint256 n;
		n.randomize();
		return n;
	}

	inline uint256 &operator^=(const uint256& rh) {
		for(size_t i = 0; i < size(); i++) {
			data()[i] ^= rh.data()[i];
		}
		return *this;
	}
};

class ValuePair: public std::array<ValueType,2> {
public:
	ValuePair(const std::vector<ValueType>& v) {
		assert(v.size() == 2);
		data()[0] = v.at(0);
		data()[1] = v.at(1);
	}
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
	using DKGType = SchnorrDKG<DigestType>;
	using DKGSpec = DKGType::Spec;
	using SignatureType = SchnorrSignature;
	
	static constexpr auto SEND_COMMIT = DKGSpec::SEND_COMMIT;
	static constexpr auto SEND_PUBKEY = DKGSpec::SEND_PUBKEY;

	uint256 seed, ask, apk;

	/**
	 * UNINIT -> init(lport,rport): INITED
	 * 		generate keys locally,
	 * 		setup connections,
	 * 		agrees on seed,
	 * 		tell each other local keys,
	 *		distributed key gen
	 * INITED -> establish(active): WAIT_CONF
	 * 		sign first closing notes
	 *    confirm coins (fund coins, share coin)
	 * WAIT_CONF -> wait(): ESTABLISH
	 * ESTABLISH -> update(balance): ESTABLISH
	 *    generate all needed notes
	 *    sign closing notes for index 0
	 *    sign closing notes for index 1
	 *    sign redeem notes for index 0
	 *    sign redeem notes for index 1
	 *    sign revocation for index 0
	 *    sign revocation for index 1
	 * ESTABLISH -> close(): WAIT_CONF_CLOSE
	 *    confirm notes
	 * WAIT_CONF_CLOSE -> wait(): WAIT_CONF_REDEEM
	 * WAIT_CONF_REDEEM -> wait(): UNINIT
	 */
	enum class State {
		UNINITIALIZED,
		INITIALIZED, WAIT_FOR_CONFIRM_SHARE, // States during establishment
		ESTABLISHED, // Working state
		WAIT_FOR_CONFIRM_CLOSE, // States during closure
		WAIT_FOR_CONFIRM_REDEEM};

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

	uint64_t dkgSeq;
	uint64_t dkgSigSeq;
	DKGType shareKey, closeKey;
	KeypairPair fundKeys, closeKeys, redeemKeys, revokeKeys;

	bool useCache;
	uint64_t closeSeq;
	std::unordered_map<std::string,uint256> cache;
	std::unordered_map<std::string,Message> messagePool;
	std::mutex messagePoolMutex;

	int myindex;
	int otherindex;
	State state;

	uint16_t lport;
	uint16_t rport;

	std::vector<ValuePair> values;
	std::vector<Note> closeNotes;
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
		return DigestType(seed.data(),32,&ASK_LABEL,1);
	}
	inline uint256 computeAPK() const {
		return DigestType(ask.data(),32,&ASK_LABEL,1);
	}
	inline uint256 compute(unsigned char l1, unsigned char l2, uint64_t seq, int index, bool t) const {
		unsigned char indexlabel = getLabelIndex(l1,index);
		if(t) return DigestType(seed.data(),32,&indexlabel,1,(unsigned char*)&seq,8);
		return DigestType(seed.data(),32,&indexlabel,1,&l2,1);
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

	void sendMessage(const std::string& label, const std::string& content){}
	std::string receiveMessage(const std::string& label){}

	inline void sendPubkey(const std::string& label, const SchnorrKeyPair& pubkey) {
		sendMessage(label,pubkey.toHex());}
	inline void sendPubkey(uint64_t seq, const SchnorrKeyPair& pubkey) {
		sendPubkey(std::to_string(seq),pubkey);}
	inline SchnorrKeyPair receivePubkey(const std::string& label) {
		return SchnorrKeyPair::fromHex(receiveMessage(label));}
	SchnorrKeyPair receivePubkey(uint64_t seq) {
		return receivePubkey(std::to_string(seq));}

	void sendPubkeyAux(const std::string& label, const SchnorrKeyPair& pubkey){}
	inline void sendPubkeyAux(uint64_t seq, const SchnorrKeyPair& pubkey) {
		sendPubkeyAux(std::to_string(seq),pubkey);}
	SchnorrKeyPair receivePubkeyAux(const std::string& label) {
		return SchnorrKeyPair::fromHex(receiveMessage(label));}
	SchnorrKeyPair receivePubkeyAux(uint64_t seq) {
		return receivePubkeyAux(std::to_string(seq));}

	void sendCommit(const std::string& label, const Commitment& commitment) {
		sendMessage(label,commitment.toHex());}
	inline void sendCommit(uint64_t seq, const Commitment& commitment) {
		sendCommit(std::to_string(seq),commitment);}
	Commitment receiveCommit(const std::string& label) {
		return Commitment::fromHex(receiveMessage(label));}
	inline Commitment receiveCommit(uint64_t seq){
		return receiveCommit(std::to_string(seq));}

	void sendCommitAux(const std::string& label, const Commitment& commitment){}
	void sendCommitAux(uint64_t seq, const Commitment& commitment) {
		sendCommitAux(std::to_string(seq),commitment);}
	Commitment receiveCommitAux(const std::string& label) {
		return Commitment::fromHex(receiveMessage(label));}
	inline Commitment receiveCommitAux(uint64_t seq){
		return receiveCommitAux(std::to_string(seq));}

	void sendSigShare(const std::string& label, const SignatureType& sig) {
		sendMessage(label,sig.toHex());}
	void sendSigShare(uint64_t seq, const SignatureType& sig) {
		sendSigShare(std::to_string(seq),sig);}
	SignatureType receiveSigShare(const std::string& label) {
		return SignatureType::fromHex(receiveMessage(label));}
	inline SignatureType receiveSigShare(uint64_t seq){
		return receiveSigShare(std::to_string(seq));}

	void sendUint256(const std::string& label, const uint256& n) {
		sendMessage(label,n.toHex());}
	uint256 receiveUint256(const std::string& label) {
		return uint256::fromHex(receiveMessage(label));}

	void distKeygen(DKGType& dkg);
	SignatureType distSigGen(const DigestType& md, DKGType& dkg, bool forme);

	void signCloseRedeemNotes(uint64_t seq);
	void publish(const Coin& coin){}
	void publish(const Note& note){}
	void waitForMessage(const std::string& label);

public:
	ZChannel(int index):myindex(index),otherindex(1-index),
		useCache(false),state(State::UNINITIALIZED) {
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

	void init(uint16_t lport, uint16_t rport, ValuePair v);
	void establish();
	void update();
	void close(bool active);

};

#endif
