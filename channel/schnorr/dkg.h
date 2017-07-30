#ifndef __DKG_H_
#define __DKG_H_

#include <array>
#include <cassert>

#include "schnorr.h"
#include "digest.h"

class SharedSignature {
	SchnorrSignature signature;
public:
	SharedSignature(){}
	SharedSignature(const SchnorrSignature& sig):signature(sig){}
	SharedSignature(const SharedSignature& sig):signature(sig.signature){}
	inline void setSignature(const SchnorrSignature& sig){signature=sig;}
	inline SchnorrSignature getSignature(){return signature;}
	inline SchnorrSignature operator+(const SharedSignature& rh) const {
		return signature+rh.signature;
	}
};

class SharedKeyPair {
	SchnorrKeyPair keypair;
	SchnorrKeyPair sharedPubkey;
public:
	SharedKeyPair(){}
	SharedKeyPair(const SchnorrKeyPair &keypair):keypair(keypair){}
	SharedKeyPair(const SchnorrKeyPair &keypair, const SchnorrKeyPair &sharedPubkey):keypair(keypair),sharedPubkey(sharedPubkey){}
	SharedKeyPair(const SharedKeyPair &skeypair):SharedKeyPair(skeypair.keypair,skeypair.sharedPubkey){}

	inline void setShared(const SchnorrKeyPair &shared) {
		sharedPubkey = shared;
	}

	inline void setRemote(const SchnorrKeyPair &remote) {
		sharedPubkey = keypair + remote;
	}

	inline SchnorrKeyPair getKeypair() {
		return keypair;
	}

	inline SchnorrKeyPair getSharedPubkey() {
		return sharedPubkey;
	}

	template<size_t n>
	SharedSignature sign(const Digest<n> &md, const SharedKeyPair &aux) const;
};

class PubkeyOrCommitment {
	SchnorrKeyPair keypair;
	Commitment commit;
	bool iscommit;
public:
	PubkeyOrCommitment() = delete;
	PubkeyOrCommitment(SchnorrKeyPair keypair):keypair(keypair),iscommit(false){}
	PubkeyOrCommitment(Commitment commit):commit(commit),iscommit(true){}
	inline bool isCommit() {return iscommit;}
	inline bool isPubkey() {return !iscommit;}
	inline SchnorrKeyPair & asPubkey() {
		assert(!iscommit);
		return keypair;
	}
	inline Commitment & asCommit() {
		assert(iscommit);
		return commit;
	}
};

/**
 * START: KeyGen(SEND_COMMIT) --> WAIT_PUBKEY
 * START: KeyGen(SEND_PUBKEY) --> WAIT_PUBKEY_COMMIT
 * WAIT_PUBKEY_COMMIT: Receive(pubkeyCommit) --> READY
 * WAIT_PUBKEY: Receive(pubkey) --> READY
 * READY: Sign(digest,FOR_?,SEND_COMMIT) --> WAIT_AUX
 * READY: Sign(digest,FOR_?,SEND_PUBKEY) --> WAIT_AUX_COMMIT
 * WAIT_AUX: ReceiveAux(auxPubkey) --> forme? WAIT_SIG_SHARE: READY
 * WAIT_AUX_COMMIT: ReceiveAux(auxPubkey) --> forme? WAIT_SIG_SHARE: READY
 *
 */
class SchnorrDKG {
	std::array<unsigned char,32> digest;
	SharedKeyPair keypair;
	static const int START = 0;
	static const int WAIT_PUBKEY = 1;
	static const int WAIT_PUBKEY_COMMIT = 2;
	static const int READY = 3;
	static const int WAIT_AUX = 4;
	static const int WAIT_AUX_COMMIT = 5;
	static const int WAIT_SIG_SHARE = 6;
	static const int SEND_COMMIT = 0;
	static const int SEND_PUBKEY = 1;
	static const int FOR_ME = 1;
	static const int FOR_OTHER = 2;
	bool forme;
	bool forother;
	int state;
public:
	SchnorrDKG():state(START){}
	PubkeyOrCommitment KeyGen(int sendWhat);
};

#endif
