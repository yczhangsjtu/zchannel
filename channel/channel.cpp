#include "schnorr/schnorr.h"
#include "schnorr/dkg.h"
#include "schnorr/digest.h"
#include "schnorr/schnorr.h"
#include "channel.h"

unsigned char ZChannel::ASK_LABEL = 0x00;
unsigned char ZChannel::R_LABEL = 0x01;
unsigned char ZChannel::RHO_LABEL = 0x02;
unsigned char ZChannel::FUND_LABEL = 0x03;
unsigned char ZChannel::SHARE_LABEL = 0x04;
unsigned char ZChannel::CLOSE_LABEL = 0x05;
unsigned char ZChannel::REDEEM_LABEL = 0x06;
unsigned char ZChannel::REVOKE_LABEL = 0x07;

Commitment uint256::commit() const {
	SHA256Digest digest(data(),32);
	return digest.getArray();
}

Commitment uint256::commit(const uint256 &trapdoor) const {
	SHA256Digest digest(trapdoor.data(),32,data(),32);
	return digest.getArray();
}

/**
 * ValueType v;
 * uint256 apk,r,rho,pkcm;
 * BHeight tlock;
 */
Coin ZChannel::getShareCoin() {
	ValueType v = values.at(0)[0] + values.at(0)[1];
	auto r = getR(SHARE_LABEL,0);
	auto rho = getRHO(SHARE_LABEL,0);
	auto pkcm = shareKey.commit().getData();
	BHeight tlock = MTL;
	return Coin(v,apk,r,rho,pkcm,tlock);
}

Coin ZChannel::getFundCoin(int index) {
	assert(index == 0 || index == 1);
	ValueType v = values.at(0)[index];
	auto r = getR(FUND_LABEL,index);
	auto rho = getRHO(FUND_LABEL,index);
	auto pkcm = fundKeys[index].commit().getData();
	BHeight tlock = MTL;
	return Coin(v,apk,r,rho,pkcm,tlock);
}

Coin ZChannel::getCloseCoin(uint64_t seq, int index1, int index2) {
	assert(index1 == 0 || index1 == 1);
	assert(index2 == 0 || index2 == 1);
	ValueType v = values.at(seq)[index1];
	auto r = getCloseR(CLOSE_LABEL,index1,index2);
	auto rho = getCloseRHO(CLOSE_LABEL,index1,index2);
	if(index1 == index2) {
		auto pkcm = closeKey.commit().getData();
		BHeight tlock = T;
		return Coin(v,apk,r,rho,pkcm,tlock);
	} else {
		auto pkcm = closeKeys[index1].commit().getData();
		BHeight tlock = MTL;
		return Coin(v,apk,r,rho,pkcm,tlock);
	}
}

Coin ZChannel::getRedeemCoin(uint64_t seq, int index) {
	assert(index == 0 || index == 1);
	ValueType v = values.at(seq)[index];
	auto r = getR(REDEEM_LABEL,index);
	auto rho = getRHO(REDEEM_LABEL,index);
	auto pkcm = redeemKeys[index].commit().getData();
	BHeight tlock = MTL;
	return Coin(v,apk,r,rho,pkcm,tlock);
}

Coin ZChannel::getRevokeCoin(uint64_t seq, int index) {
	assert(index == 0 || index == 1);
	ValueType v = values.at(seq)[index];
	auto r = getR(REVOKE_LABEL,index);
	auto rho = getRHO(REVOKE_LABEL,index);
	auto pkcm = revokeKeys[index].commit().getData();
	BHeight tlock = MTL;
	return Coin(v,apk,r,rho,pkcm,tlock);
}

Note ZChannel::getNote(uint64_t seq, int index) {
	assert(index == 0 || index == 1);
	Coin share = getShareCoin();
	Coin dummy = Coin();
	Coin c1 = getCloseCoin(seq,index,0);
	Coin c2 = getCloseCoin(seq,index,1);
	return Note(share.serial(ask),dummy.serial(ask),c1.commit(),c2.commit());
}

Note ZChannel::getRedeem(uint64_t seq, int index1, int index2) {
	assert(index1 == 0 || index1 == 1);
	assert(index2 == 0 || index2 == 1);
	Coin c1 = getCloseCoin(seq,index1,index2);
	Coin dummy1 = Coin();
	Coin r1 = getRedeemCoin(seq,index1);
	Coin dummy2 = Coin();
	return Note(c1.serial(ask),dummy1.serial(ask),r1.commit(),dummy2.commit());
}

Note ZChannel::getRevoke(uint64_t seq, int index) {
	assert(index == 0 || index == 1);
	Coin c1 = getCloseCoin(seq,1-index,1-index);
	Coin dummy1 = Coin();
	Coin r1 = getRevokeCoin(seq,index);
	Coin dummy2 = Coin();
	return Note(c1.serial(ask),dummy1.serial(ask),r1.commit(),dummy2.commit());
}

uint256 ZChannel::getUint256(unsigned char l1, unsigned char l2, uint64_t seq, int index, bool t) {
	if(!useCache) return compute(l1,l2,seq,index,t);
	else {
		std::string tag = getTag(l1,l2,seq,index,t);
		auto res = cache.find(tag);
		if(res != cache.end())
			return res->second;
		else {
			uint256 r = compute(l1,l2,seq,index,t);
			cache[tag] = r;
			return r;
		}
	}
}

uint256 ZChannel::getR(unsigned char label, int index) {
	return getUint256(R_LABEL,label,0,index,false);
}

uint256 ZChannel::getCloseR(uint64_t seq, int index1, int index2) {
	return getUint256(R_LABEL,0,seq,index1+index2<<1,true);
}

uint256 ZChannel::getRHO(unsigned char label, int index) {
	return getUint256(RHO_LABEL,label,0,index,false);
}

uint256 ZChannel::getCloseRHO(uint64_t seq, int index1, int index2) {
	return getUint256(RHO_LABEL,0,seq,index1+index2<<1,true);
}

