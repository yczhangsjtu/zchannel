#include <iostream>
#include "dkg.h"

using namespace std;

int main() {
	// Test normal schnorr signature
	cout << "Testing normal use of schnorr signature ..." << endl;
	auto keyAlice = SchnorrKeyPair::keygen();
	auto auxKeyAlice = SchnorrKeyPair::keygen();
	SHA256Digest md("message");
	SchnorrSignature sig = keyAlice.sign(md);
	cout << "Alice Sig:" << sig.toHex() << endl;
	if(keyAlice.pubkey().verify(md,sig))
		cout << "    Verified!" << endl;
	else
		cout << "    Invalid signature!" << endl;
	sig = keyAlice.signWithAux(md,auxKeyAlice);
	cout << "Alice Sig:" << sig.toHex() << endl;
	if(keyAlice.pubkey().verify(md,sig))
		cout << "    Verified!" << endl;
	else
		cout << "    Invalid signature!" << endl;

	// Test shared schnorr signature
	auto keyBob = SchnorrKeyPair::keygen();

	SharedKeyPair keyShareAlice(keyAlice);
	SharedKeyPair keyShareBob(keyBob);
	keyShareAlice.setRemote(keyBob.pubkey());
	keyShareBob.setRemote(keyAlice.pubkey());

	cout << "Alice's shared key: " << endl;
	keyShareAlice.print(2);
	cout << "Bob's shared key: " << endl;
	keyShareBob.print(2);

	auto auxKeyBob = SchnorrKeyPair::keygen();
	SharedKeyPair auxKeyShareAlice(auxKeyAlice);
	SharedKeyPair auxKeyShareBob(auxKeyBob);
	auxKeyShareAlice.setRemote(auxKeyBob.pubkey());
	auxKeyShareBob.setRemote(auxKeyAlice.pubkey());

	cout << "Alice's aux shared key: " << endl;
	auxKeyShareAlice.print(2);
	cout << "Bob's aux shared key: " << endl;
	auxKeyShareBob.print(2);

	auto sigAlice = keyShareAlice.sign(md,auxKeyShareAlice);
	auto sigBob = keyShareBob.sign(md,auxKeyShareBob);
	auto sigShare = sigAlice + sigBob;
	cout << "Alice's share of sig: " << sigAlice.toHex() << endl;
	cout << "Bob's share of sig:   " << sigBob.toHex() << endl;
	cout << "Final signature:      " << sigShare.toHex() << endl;

	if(keyShareAlice.verify(md,sigShare))
		cout << "    Verified!" << endl;
	else
		cout << "    Invalid signature!" << endl;

	/*
	auto sharedKeyPair = keyShareAlice.getSharedPubkey();
	auto auxSharedKeyPair = auxKeyShareAlice.getSharedPubkey();
	auto compareSig = sharedKeyPair.signWithAux(md,auxSharedKeyPair);
	cout << "Compare signature:      " << compareSig.toHex() << endl;
	if(sharedKeyPair.verify(md,compareSig))
		cout << "    Verified!" << endl;
	else
		cout << "    Invalid signature!" << endl;
		*/
	cout << "Testing distributed generation of schnorr signature" << endl;
	SchnorrDKG<SHA256Digest> dkgAlice, dkgBob;

	// Key Agreement
	auto keyGenAlice = dkgAlice.keyGenPubkey();
	auto keyGenBob = dkgBob.keyGenCommit();
	dkgAlice.receive(keyGenBob);
	dkgBob.receive(keyGenAlice);
	dkgAlice.receive(dkgBob.pubkey());
	
	// Distributed Sign (for Alice)
	auto auxAlice = dkgAlice.signPubkeyForMe(md);
	auto auxBob = dkgBob.signCommitForOther(md);
	dkgAlice.receiveAux(auxBob);
	auto sigShareBob = dkgBob.receiveAux(auxAlice);
	dkgAlice.receiveAux(dkgBob.auxkey());
	auto sigFinalAlice = dkgAlice.receiveSig(sigShareBob);

	cout << "Distributed Generated Key" << endl;
	dkgAlice.sharePubkey().print();
	cout << "Distributed Generated Signature" << endl;
	cout << sigFinalAlice.toHex() << endl;
	if(dkgAlice.sharePubkey().verify(md,sigFinalAlice)) {
		cout << "Verified!" << endl;
	} else {
		cout << "Invalid signature!" << endl;
	}
	return 0;
}
