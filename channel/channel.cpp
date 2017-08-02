#include <iostream>
#include <sstream>
#include <cassert>

#include <ace/INET_Addr.h>
#include <ace/SOCK_Connector.h>
#include <ace/SOCK_Stream.h>
#include <ace/SOCK_Acceptor.h>
#include <ace/Log_Msg.h>

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

// #define THREAD_MESSAGES

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

Note ZChannel::getShareNote() {
	Coin c1 = getFundCoin(0);
	Coin c2 = getFundCoin(1);
	Coin share = getShareCoin();
	Coin dummy = Coin();
	return Note(c1.serial(ask),c2.serial(ask),share.commit(),dummy.commit());
}

Note ZChannel::getNote(uint64_t seq, int index) {
	assert(index == 0 || index == 1);
	if(index == myindex && seq < closeNotes.size())
		return closeNotes.at(seq);
	Coin share = getShareCoin();
	Coin dummy = Coin();
	Coin c1 = getCloseCoin(seq,index,0);
	Coin c2 = getCloseCoin(seq,index,1);
	return Note(share.serial(ask),dummy.serial(ask),c1.commit(),c2.commit());
}

Note ZChannel::getRedeem(uint64_t seq, int index1, int index2) {
	assert(index1 == 0 || index1 == 1);
	assert(index2 == 0 || index2 == 1);
	if(index1 == myindex && seq < redeemNotes.size())
		return redeemNotes.at(seq);
	Coin c1 = getCloseCoin(seq,index1,index2);
	Coin dummy1 = Coin();
	Coin r1 = getRedeemCoin(seq,index1);
	Coin dummy2 = Coin();
	return Note(c1.serial(ask),dummy1.serial(ask),r1.commit(),dummy2.commit());
}

Note ZChannel::getRevoke(uint64_t seq, int index) {
	assert(index == 0 || index == 1);
	if(index == myindex && seq < revocations.size())
		return revocations.at(seq);
	Coin c1 = getCloseCoin(seq,1-index,1-index);
	Coin dummy1 = Coin();
	Coin r1 = getRevokeCoin(seq,index);
	Coin dummy2 = Coin();
	return Note(c1.serial(ask),dummy1.serial(ask),r1.commit(),dummy2.commit());
}

uint256 ZChannel::getUint256(unsigned char l1, unsigned char l2, uint64_t seq, int index, bool t) {
	assert(state != State::UNINITIALIZED);
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

void ZChannel::signCloseRedeemNotes(uint64_t seq) {
	auto closeNote0 = getNote(seq,0);
	auto closeNote1 = getNote(seq,1);
	auto redeemNote0 = getRedeem(seq,0,0);
	auto redeemNote1 = getRedeem(seq,1,1);
	{
		auto sig0 = distSigGen(closeNote0.getDigest(),shareKey,myindex==0);
		auto sig1 = distSigGen(closeNote1.getDigest(),shareKey,myindex==1);
		assert(closeNotes.size() == seq);
		if(myindex == 0) {
			closeNote0.setSignature(sig0);
			closeNotes.push_back(closeNote0);
		} else {
			closeNote1.setSignature(sig1);
			closeNotes.push_back(closeNote1);
		}
	}
	{
		auto sig0 = distSigGen(redeemNote0.getDigest(),closeKey,myindex==0);
		auto sig1 = distSigGen(redeemNote1.getDigest(),closeKey,myindex==1);
		assert(redeemNotes.size() == seq);
		if(myindex == 0) {
			redeemNote0.setSignature(sig0);
			redeemNotes.push_back(redeemNote0);
		} else {
			redeemNote1.setSignature(sig1);
			redeemNotes.push_back(redeemNote1);
		}
	}
}

void ZChannel::sendMessage(const std::string& label, const std::string& content) {
	std::cerr << "  [Sending message] " << label << std::endl;
	std::lock_guard<std::mutex> guard(sendMessagePoolMutex);
	sendMessagePool.push_back(Message(label,content));
}

std::string ZChannel::receiveMessage(const std::string& label) {
	std::cerr << "  [Receiving message] " << label << std::endl;
	while(true) {
		std::lock_guard<std::mutex> guard(receiveMessagePoolMutex);
		auto iter = receiveMessagePool.find(label);
		if(iter != receiveMessagePool.end()) {
			std::cerr << "  [Receiving message] " << "Received " << label << std::endl;
			return iter->second.getContent();
		}
	}
}

void ZChannel::waitForMessage(const std::string& label) {
	while(true) {
		std::lock_guard<std::mutex> guard(receiveMessagePoolMutex);
		auto iter = receiveMessagePool.find(label);
		if(iter != receiveMessagePool.end())
			break;
	}
}

void ZChannel::init(uint16_t lport, uint16_t rport, const std::string& ip, ValuePair v) {

	std::cerr << "[init] Start initializing ZChannel" << std::endl;

	assert(state == State::UNINITIALIZED);

	std::cerr << "[init] Clearing everything " << std::endl;
	values.clear();
	cache.clear();
	receiveMessagePool.clear();
	closeNotes.clear();
	redeemNotes.clear();
	revocations.clear();
	dkgSeq = 0;
	dkgSigSeq = 0;

	std::cerr << "[init] Cleared everything " << std::endl;

	std::cerr << "[init] Set local port to " << lport << std::endl;
	this->lport = lport;

	std::cerr << "[init] Set remote host to " << ip << std::endl;
	this->ip = ip;

	std::cerr << "[init] Set remote port to " << rport << std::endl;
	this->rport = rport;

	std::cerr << "[init] Set initial balance " << v << std::endl;
	values.push_back(v);

	std::cerr << "[init] Run key generation for local keys" << std::endl;
	fundKeys[myindex]   = SchnorrKeyPair::keygen();
	closeKeys[myindex]  = SchnorrKeyPair::keygen();
	redeemKeys[myindex] = SchnorrKeyPair::keygen();
	revokeKeys[myindex] = SchnorrKeyPair::keygen();

	std::cerr << "[init] Start message sending thread" << std::endl;
	if(sendMessageThread.joinable())
		sendMessageThread.join();
	sendMessageThread = std::thread([=]{sendMessageFunc();});
	std::cerr << "[init] Start message receiving thread" << std::endl;
	if(receiveMessageThread.joinable())
		receiveMessageThread.join();
	receiveMessageThread = std::thread([=]{receiveMessageFunc();});

	// Agrees on random seed
	std::cerr << "[init] Negotiating seed" << std::endl;
	seed.randomize();
	uint256 oseed;
	if(myindex) {
		sendCommit("seedcmt",seed.commit());
		oseed = receiveUint256("seed");
		sendUint256("seed",seed);
	} else {
		auto seedcommit = receiveCommit("seedcmt");
		sendUint256("seed",seed);
		oseed = receiveUint256("seed");
	}
	seed ^= oseed;
	std::cerr << "[init] Seed agreed on" << std::endl;

	std::cerr << "[init] Sending local public keys" << std::endl;
	// Send each other the locally generated private keys
	sendPubkey(dkgSeq,fundKeys[myindex]);
	sendPubkey(dkgSeq+1,closeKeys[myindex]);
	sendPubkey(dkgSeq+2,redeemKeys[myindex]);
	sendPubkey(dkgSeq+3,revokeKeys[myindex]);
	std::cerr << "[init] Local public keys sent" << std::endl;
	std::cerr << "[init] Receiving remote public keys" << std::endl;
	fundKeys[otherindex]   = receivePubkey(dkgSeq);
	closeKeys[otherindex]  = receivePubkey(dkgSeq+1);
	redeemKeys[otherindex] = receivePubkey(dkgSeq+2);
	revokeKeys[otherindex] = receivePubkey(dkgSeq+3);
	std::cerr << "[init] Remote public keys received" << std::endl;

	// Distributed generation of keys
	std::cerr << "[init] Distributed key generation of share key" << std::endl;
	distKeygen(shareKey);
	std::cerr << "[init] Distributed key generation of close key" << std::endl;
	distKeygen(closeKey);
	std::cerr << "[init] Distributed key generations done" << std::endl;

	state = State::INITIALIZED;
	std::cerr << "[init] Initialization done" << std::endl;
}

void ZChannel::establish() {
	assert(state == State::INITIALIZED);

	std::cerr << "[establish] Computing share note" << std::endl;
	shareNote.reset(new Note(getShareNote()));
	std::cerr << "[establish] Signing share note" << std::endl;
	shareNoteSigs[myindex] =
		fundKeys[myindex].sign(DigestType(shareNote->getDigest()));
	std::cerr << "[establish] Sending share note signature" << std::endl;
	sendSignature("share",shareNoteSigs[myindex]);
	std::cerr << "[establish] Receiving share note signature" << std::endl;
	shareNoteSigs[otherindex] = receiveSignature("share");
	std::cerr << "[establish] Share note signatures complete" << std::endl;

	signCloseRedeemNotes(0);
	publish(getFundCoin(myindex));
	publish(*shareNote);

	state = State::WAIT_FOR_CONFIRM_SHARE;

	waitForMessage("share:confirmed");
	state = State::ESTABLISHED;
}

void ZChannel::update(ValuePair v) {
	assert(state == State::ESTABLISHED);
	values.push_back(v);
	signCloseRedeemNotes(closeNotes.size());
}

void ZChannel::close(bool active) {
	assert(state == State::ESTABLISHED);
	if(active) publish(closeNotes.back());
	waitForMessage("close:"+std::to_string(closeSeq)+":confirmed");
	state = State::WAIT_FOR_CONFIRM_REDEEM;
	waitForMessage("redeem:"+std::to_string(myindex)+":confirmed");
	state = State::UNINITIALIZED;
}

ZChannel::SignatureType ZChannel::distSigGen(const DigestType& md,
		DKGType& dkg, bool forme) {
	if(forme) {
		auto aux = dkg.signPubkeyForMe(md);
		auto cm = receiveCommitAux(dkgSigSeq);
		dkg.receiveAux(cm);
		sendPubkey(dkgSigSeq,aux.asPubkey());
		auto oaux = receivePubkeyAux(dkgSigSeq);
		dkg.receiveAux(oaux);
		auto ssig = receiveSigShare(dkgSigSeq);
		auto sig = dkg.receiveSig(ssig);
		dkgSigSeq++;
		return sig;
	} else {
		auto aux = dkg.signPubkeyForOther(md);
		sendCommitAux(dkgSigSeq,aux.asCommit());
		auto oaux = receivePubkey(dkgSigSeq);
		sendPubkey(dkgSigSeq,dkg.auxkey());
		auto ssig = dkg.receiveAux(oaux);
		sendSigShare(dkgSigSeq,ssig.getSignature());
		dkgSigSeq++;
		return ZChannel::SignatureType();
	}
}

void ZChannel::distKeygen(DKGType& dkg) {
	auto pkeycm = dkg.keyGen(myindex?SEND_COMMIT:SEND_PUBKEY);
	SchnorrKeyPair pkey;
	if(pkeycm.isPubkey()) {
		auto cm = receiveCommit(dkgSeq);
		dkg.receive(cm);
		sendPubkeyShare(dkgSeq,pkeycm.asPubkey());
		pkey = receivePubkeyShare(dkgSeq);
	} else {
		sendCommit(dkgSeq,pkeycm.asCommit());
		pkey = receivePubkeyShare(dkgSeq);
		sendPubkeyShare(dkgSeq,dkg.pubkey());
	}
	dkg.receive(PubkeyOrCommitment(pkey));

	dkgSeq++;
}


/**
 * Message: only consider [0-9][A-Z][a-z],':', '-' and ';', and ignore everything * else
 * Format: <label>-<content>;
 * Label: [0-9A-Za-z:]+
 * Content: [0-9A-Fa-f]
 */
void ZChannel::sendMessageFunc() {
	ACE_SOCK_Acceptor acceptor;
	ACE_SOCK_Stream peer;
	ACE_INET_Addr addr;
	ACE_INET_Addr remote_addr;

	if(addr.set(lport) == -1) {
		std::cerr << "  [Send Messge Thread] Failed to set port" << std::endl;
		return;
	}
	if(acceptor.open(addr) == -1) {
		std::cerr << "  [Send Message Thread] Failed to bind to address" << std::endl;
		return;
	}
#ifdef THREAD_MESSAGE
	std::cerr << "  [Send Messge Thread] Listening to port " << lport << std::endl;
#endif

	while(true) {
		if(acceptor.accept(peer,&remote_addr) == -1) {
			std::cerr << "  [Send Message Thread] Failed to accept" << std::endl;
			return;
		}
#ifdef THREAD_MESSAGE
		std::cerr << "  [Send Message Thread] Accepted peer: " << remote_addr.get_host_name() << ":" << remote_addr.get_port_number() << std::endl;
#endif
		
		peer.disable(ACE_NONBLOCK);

		while(true) {
			std::lock_guard<std::mutex> guard(sendMessagePoolMutex);
			if(!sendMessagePool.empty()) {
				for(size_t i = 0; i < sendMessagePool.size(); i++) {
					std::string label = sendMessagePool[i].getLabel();
					std::string content = sendMessagePool[i].getContent();
					std::string message = label+"-"+content+";";
					if(peer.send_n(message.c_str(),message.size()) == -1) {
						std::cout << "  [Send Message Thread] Failed to send message!" << std::endl;
						return;
					}
#ifdef THREAD_MESSAGE
					std::cout << "  [Send Message Thread] Message sent: " << message << std::endl;
#endif
				}
				sendMessagePool.clear();
			}
		}
	}
}

void ZChannel::receiveMessageFunc() {
	ACE_SOCK_Connector connector;
	ACE_SOCK_Stream peer;
	ACE_INET_Addr peer_addr;
	// ACE_Time_Value timeout(60); // One minute to connect

	char buf[1024]; // Enough space to receive
	int n;

	if(peer_addr.set(rport,ip.c_str()) == -1) {
		std::cerr << "  [Receive Message Thread] Failed to set remote address" << std::endl;
		return;
	}
#ifdef THREAD_MESSAGE
	std::cerr << "  [Receive Message Thread] Trying to connect to peer: "
		<< peer_addr.get_host_name() << ":"
		<< peer_addr.get_port_number() << std::endl;
#endif

	while(true) {
		if(connector.connect(peer,peer_addr) == -1) {
			// std::cerr << "  [Receive Message Thread] Failed to connect to peer" << std::endl;
			// ACE_ERROR((LM_ERROR,"%p\n","  [Receive Message Thread] connect()"));
			// return;
		} else break;
	}
#ifdef THREAD_MESSAGE
	std::cerr << "  [Receive Message Thread] Connected to peer." << std::endl;
#endif

	std::ostringstream oslabel;
	std::ostringstream oscontent;
	bool islabel = true;
	while((n = peer.recv(buf, sizeof buf)) > 0) {
		for(size_t i = 0; i < n; i++) {
			for(i = 0; i < n; i++) {
				char c = buf[i];
				if(islabel) {
					if((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == ':')
						oslabel << c;
					else if(c == '-')
						islabel = false;
				} else {
					if((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
						oscontent << c;
					else if(c == ';') {
						std::string label = oslabel.str();
						std::string content = oscontent.str();
#ifdef THREAD_MESSAGE
						std::cerr << "  [Receive Message Thread] Received message: " << label << " " << content << std::endl;
#endif
						std::lock_guard<std::mutex> guard(receiveMessagePoolMutex);
						insertReceiveMessage(label,content);
#ifdef THREAD_MESSAGE
						std::cerr << "  [Receive Message Thread] Now message pool is of size: " << receiveMessagePool.size() << std::endl;
#endif
						oslabel.str("");
						oslabel.clear();
						oscontent.str("");
						oscontent.clear();
						islabel = true;
					}
				}
			}
		}
	}
}

