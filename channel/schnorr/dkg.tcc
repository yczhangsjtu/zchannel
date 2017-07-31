template<typename DigestType>
PubkeyOrCommitment SchnorrDKG<DigestType>::keyGen(int sendWhat) {
	assert(state == START);
	keypair = SharedKeyPair(SchnorrKeyPair::keygen());
	if(sendWhat == SEND_COMMIT) {
		PubkeyOrCommitment pubkeycommit(keypair.getKeypair().commit());
		state = WAIT_PUBKEY;
		return pubkeycommit;
	} else {
		assert(sendWhat == SEND_PUBKEY);
		PubkeyOrCommitment pubkeycommit(keypair.getKeypair().pubkey());
		state = WAIT_PUBKEY_COMMIT;
		return pubkeycommit;
	}
}

template<typename DigestType>
void SchnorrDKG<DigestType>::receive(const PubkeyOrCommitment &pubkeycommit) {
	if(state == WAIT_PUBKEY) {
		assert(pubkeycommit.isPubkey());
		keypair.setRemote(pubkeycommit.asConstPubkey());
		state = READY;
	} else if(state == WAIT_PUBKEY_COMMIT) {
		assert(pubkeycommit.isCommit());
		pubkeyCommit = pubkeycommit.asConstCommit();
		state = WAIT_PUBKEY;
	} else {
		assert(0);
	}
}

template<typename DigestType>
PubkeyOrCommitment SchnorrDKG<DigestType>::sign(const DigestType &md, int sendWhat, int forWho) {
	assert(state == READY);
	digest = md;
	auxKeypair = SharedKeyPair(SchnorrKeyPair::keygen());
	forme = forWho == FOR_ME;
	if(sendWhat == SEND_COMMIT) {
		PubkeyOrCommitment pubkeycommit(auxKeypair.getKeypair().commit());
		state = WAIT_AUX;
		return pubkeycommit;
	} else {
		assert(sendWhat == SEND_PUBKEY);
		PubkeyOrCommitment pubkeycommit(auxKeypair.getKeypair().pubkey());
		state = WAIT_AUX_COMMIT;
		return pubkeycommit;
	}
}

template<typename DigestType>
SharedSignature SchnorrDKG<DigestType>::receiveAux(const PubkeyOrCommitment &pubkeycommit) {
	if(state == WAIT_AUX) {
		assert(pubkeycommit.isPubkey());
		auxKeypair.setRemote(pubkeycommit.asConstPubkey());
		signature = keypair.sign(digest,auxKeypair);
		if(forme) {
			state = WAIT_SIG_SHARE;
			return SharedSignature();
		} else {
			state = READY;
			return signature;
		}
	} else if(state == WAIT_AUX_COMMIT) {
		assert(pubkeycommit.isCommit());
		pubkeyCommit = pubkeycommit.asConstCommit();
		state = WAIT_AUX;
		return SharedSignature();
	} else {
		assert(0);
	}
}

template<typename DigestType>
SchnorrSignature SchnorrDKG<DigestType>::receiveSig(const SharedSignature &sig) {
	assert(state == WAIT_SIG_SHARE);
	auto finalSig = signature + sig;
	assert(keypair.verify(digest,finalSig));
	return finalSig;
}
