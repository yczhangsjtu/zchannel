#ifndef __DKG_H_
#define __DKG_H_

#include <array>
#include <cassert>

#include "schnorr.h"

class SharedKeyPair {
	SchnorrKeyPair keypair;
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
