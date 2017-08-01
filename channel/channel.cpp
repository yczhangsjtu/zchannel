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

Coin ZChannel::getShareCoin(uint64_t seq) const {
}

Coin ZChannel::getFundCoin(int index) const {
}

Coin ZChannel::getCloseCoin(uint64_t seq, int index) const {
}

Coin ZChannel::getRedeemCoin(uint64_t seq, int index) const {
}

Coin ZChannel::getRevokeCoin(uint64_t seq, int index) const {
}

Note ZChannel::getNote(uint64_t seq, int index) const {
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

uint256 ZChannel::getCloseR(uint64_t seq, int index) {
	return getUint256(R_LABEL,0,seq,index,true);
}

uint256 ZChannel::getRHO(unsigned char label, int index) {
	return getUint256(RHO_LABEL,label,0,index,false);
}

uint256 ZChannel::getCloseRHO(uint64_t seq, int index) {
	return getUint256(RHO_LABEL,0,seq,index,true);
}

