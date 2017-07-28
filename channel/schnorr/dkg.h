#ifndef __DKG_H_
#define __DKG_H_

class SharedKeyPair {
	SchnorrKeyPair keypair;
};

/**
 * START: Start(digest,send_commit/send_pubkey)
 *
 */
class SchnorrDKG {
	unsigned char digest[32];
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
public:
	SchnorrDKG(){}
};

#endif
