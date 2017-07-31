template<typename DigestType>
PubkeyOrCommitment SchnorrDKG<DigestType>::keyGen(Spec sendWhat) {
	assert(state == State::START);
	keypair = SharedKeyPair(SchnorrKeyPair::keygen());
	if(sendWhat == Spec::SEND_COMMIT) {
		PubkeyOrCommitment pubkeycommit(keypair.getKeypair().commit());
		state = State::WAIT_PUBKEY;
		return pubkeycommit;
	} else {
		assert(sendWhat == Spec::SEND_PUBKEY);
		PubkeyOrCommitment pubkeycommit(keypair.getKeypair().pubkey());
		state = State::WAIT_PUBKEY_COMMIT;
		return pubkeycommit;
	}
}

template<typename DigestType>
void SchnorrDKG<DigestType>::receive(const PubkeyOrCommitment &pubkeycommit) {
	if(state == State::WAIT_PUBKEY) {
		assert(pubkeycommit.isPubkey());
		keypair.setRemote(pubkeycommit.asConstPubkey());
		state = State::READY;
	} else if(state == State::WAIT_PUBKEY_COMMIT) {
		assert(pubkeycommit.isCommit());
		pubkeyCommit = pubkeycommit.asConstCommit();
		state = State::WAIT_PUBKEY;
	} else {
		assert(0);
	}
}

template<typename DigestType>
PubkeyOrCommitment SchnorrDKG<DigestType>::sign(const DigestType &md, Spec sendWhat, int forWho) {
	assert(state == State::READY);
	digest = md;
	auxKeypair = SharedKeyPair(SchnorrKeyPair::keygen());
	forme    = forWho & FOR_ME;
	forother = forWho & FOR_OTHER;
	if(sendWhat == Spec::SEND_COMMIT) {
		PubkeyOrCommitment pubkeycommit(auxKeypair.getKeypair().commit());
		state = State::WAIT_AUX;
		return pubkeycommit;
	} else {
		assert(sendWhat == Spec::SEND_PUBKEY);
		PubkeyOrCommitment pubkeycommit(auxKeypair.getKeypair().pubkey());
		state = State::WAIT_AUX_COMMIT;
		return pubkeycommit;
	}
}

template<typename DigestType>
SharedSignature SchnorrDKG<DigestType>::receiveAux(const PubkeyOrCommitment &pubkeycommit) {
	if(state == State::WAIT_AUX) {
		assert(pubkeycommit.isPubkey());
		auxKeypair.setRemote(pubkeycommit.asConstPubkey());
		signature = keypair.sign(digest,auxKeypair);
		if(forme) state = State::WAIT_SIG_SHARE;
		else state = State::READY;
		if(!forother) return SharedSignature();
		else return signature;
	} else if(state == State::WAIT_AUX_COMMIT) {
		assert(pubkeycommit.isCommit());
		pubkeyCommit = pubkeycommit.asConstCommit();
		state = State::WAIT_AUX;
		if(!forother) return SharedSignature();
		else return signature;
	} else {
		assert(0);
	}
}

template<typename DigestType>
SchnorrSignature SchnorrDKG<DigestType>::receiveSig(const SharedSignature &sig) {
	assert(state == State::WAIT_SIG_SHARE);
	auto finalSig = signature + sig;
	assert(keypair.verify(digest,finalSig));
	state = State::READY;
	return finalSig;
}
