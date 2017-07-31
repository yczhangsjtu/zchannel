#ifndef __DKG_H_
#define __DKG_H_

#include <array>
#include <iostream>
#include <cassert>
#include <string>

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
	inline std::string toHex() {
		return signature.toHex();
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

	inline SchnorrKeyPair getKeypair() const {
		return keypair;
	}

	inline SchnorrKeyPair getSharedPubkey() const {
		return sharedPubkey;
	}

	inline SchnorrKeyPair getAuxKeypair() const {
		SchnorrKeyPair auxKeypair(keypair);
		auxKeypair.setPub(sharedPubkey);
		return auxKeypair;
	}

	template<typename DigestType>
	inline SharedSignature sign(const DigestType &md, const SharedKeyPair &aux) const {
		return keypair.signWithAux(md,aux.getAuxKeypair());
	}

	template<typename DigestType>
	inline bool verify(const DigestType &md, const SchnorrSignature& sig) const {
		return sharedPubkey.verify(md,sig);
	}

	inline void print(int offset=0) {
		std::cout << std::string(" ",offset) << "private key: " << std::endl;
		keypair.print(offset+2);
		std::cout << std::string(" ",offset) << "shared pub key: " << std::endl;
		sharedPubkey.print(offset+2);
	}
};

class PubkeyOrCommitment {
	SchnorrKeyPair keypair;
	Commitment commit;
	bool iscommit;
public:
	PubkeyOrCommitment() = delete;
	PubkeyOrCommitment(SchnorrKeyPair keypair):keypair(keypair),iscommit(false){}
	PubkeyOrCommitment(Commitment commit):commit(commit),iscommit(true){}
	PubkeyOrCommitment(const PubkeyOrCommitment& rh):keypair(rh.keypair),commit(rh.commit),iscommit(rh.iscommit){}
	inline bool isCommit() const {return iscommit;}
	inline bool isPubkey() const {return !iscommit;}
	inline SchnorrKeyPair & asPubkey() {
		assert(!iscommit);
		return keypair;
	}
	inline const SchnorrKeyPair & asConstPubkey() const {
		assert(!iscommit);
		return keypair;
	}
	inline Commitment & asCommit() {
		assert(iscommit);
		return commit;
	}
	inline const Commitment & asConstCommit() const {
		assert(iscommit);
		return commit;
	}
};

/**
 * START: keyGen(SEND_COMMIT) --> WAIT_PUBKEY
 * START: keyGen(SEND_PUBKEY) --> WAIT_PUBKEY_COMMIT
 * WAIT_PUBKEY_COMMIT: Receive(pubkeyCommit) --> WAIT_PUBKEY
 * WAIT_PUBKEY: Receive(pubkey) --> READY
 * READY: Sign(digest,FOR_?,SEND_COMMIT) --> WAIT_AUX
 * READY: Sign(digest,FOR_?,SEND_PUBKEY) --> WAIT_AUX_COMMIT
 * WAIT_AUX: ReceiveAux(auxPubkey) --> forme? WAIT_SIG_SHARE: READY
 * WAIT_AUX_COMMIT: ReceiveAux(auxPubkeyCommit) --> WAIT_AUX
 * WAIT_SIG_SHARE: ReceiveSig(sharedSig) --> READY
 *
 */
template<typename DigestType>
class SchnorrDKG {
	DigestType digest;
	SharedKeyPair keypair;
	SharedKeyPair auxKeypair;
	SharedSignature signature;
	Commitment pubkeyCommit;
	static const int START = 0;
	static const int WAIT_PUBKEY = 1;
	static const int WAIT_PUBKEY_COMMIT = 2;
	static const int READY = 3;
	static const int WAIT_AUX = 4;
	static const int WAIT_AUX_COMMIT = 5;
	static const int WAIT_SIG_SHARE = 6;
	bool forme;
	bool forother;
	int state;
public:
	static const int SEND_COMMIT = 0;
	static const int SEND_PUBKEY = 1;
	static const int FOR_ME = 1;
	static const int FOR_OTHER = 2;
	SchnorrDKG():state(START){}
	PubkeyOrCommitment keyGen(int sendWhat);
	inline SchnorrKeyPair pubkey() const {return keypair.getKeypair().pubkey();}
	inline SchnorrKeyPair sharePubkey() const {return keypair.getSharedPubkey().pubkey();}
	inline SchnorrKeyPair auxkey() const {return auxKeypair.getKeypair().pubkey();}
	inline PubkeyOrCommitment keyGenCommit(){return keyGen(SEND_COMMIT);}
	inline PubkeyOrCommitment keyGenPubkey(){return keyGen(SEND_PUBKEY);}
	void receive(const PubkeyOrCommitment &pubkeycommit);
	PubkeyOrCommitment sign(const DigestType &md, int sendWhat, int forWho);
	inline PubkeyOrCommitment signCommitForMe(const DigestType &md){return sign(md,SEND_COMMIT,FOR_ME);}
	inline PubkeyOrCommitment signCommitForOther(const DigestType &md){return sign(md,SEND_COMMIT,FOR_OTHER);}
	inline PubkeyOrCommitment signPubkeyForMe(const DigestType &md){return sign(md,SEND_PUBKEY,FOR_ME);}
	inline PubkeyOrCommitment signPubkeyForOther(const DigestType &md){return sign(md,SEND_PUBKEY,FOR_OTHER);}
	SharedSignature receiveAux(const PubkeyOrCommitment &pubkeycommit);
	SchnorrSignature receiveSig(const SharedSignature &sig);
};

#include "dkg.tcc"

#endif
