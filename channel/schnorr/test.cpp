#include <iostream>
#include "dkg.h"

int main() {
	// Test normal schnorr signature
	auto keyAlice = SchnorrKeyPair::keygen();
	auto auxKeyAlice = SchnorrKeyPair::keygen();
	SHA256Digest md("message");
	SchnorrSignature sig = keyAlice.sign(md);
	std::cout << "Alice Sig:" << sig.toHex() << std::endl;
	if(keyAlice.pubkey().verify(md,sig))
		std::cout << "    Verified!" << std::endl;
	else
		std::cout << "    Invalid signature!" << std::endl;
	sig = keyAlice.signWithAux(md,auxKeyAlice);
	std::cout << "Alice Sig:" << sig.toHex() << std::endl;
	if(keyAlice.pubkey().verify(md,sig))
		std::cout << "    Verified!" << std::endl;
	else
		std::cout << "    Invalid signature!" << std::endl;

	// Test shared schnorr signature
	auto keyBob = SchnorrKeyPair::keygen();

	SharedKeyPair keyShareAlice(keyAlice);
	SharedKeyPair keyShareBob(keyBob);
	keyShareAlice.setRemote(keyBob);
	keyShareBob.setRemote(keyAlice);

	std::cout << "Alice's shared key: " << std::endl;
	keyShareAlice.print(2);
	std::cout << "Bob's shared key: " << std::endl;
	keyShareBob.print(2);

	auto auxKeyBob = SchnorrKeyPair::keygen();
	SharedKeyPair auxKeyShareAlice(auxKeyAlice);
	SharedKeyPair auxKeyShareBob(auxKeyBob);
	auxKeyShareAlice.setRemote(auxKeyBob);
	auxKeyShareBob.setRemote(auxKeyAlice);

	std::cout << "Alice's aux shared key: " << std::endl;
	auxKeyShareAlice.print(2);
	std::cout << "Bob's aux shared key: " << std::endl;
	auxKeyShareBob.print(2);

	auto sigAlice = keyShareAlice.sign(md,auxKeyShareAlice);
	auto sigBob = keyShareBob.sign(md,auxKeyShareBob);
	auto sigShare = sigAlice + sigBob;
	std::cout << "Alice's share of sig: " << sigAlice.toHex() << std::endl;
	std::cout << "Bob's share of sig:   " << sigBob.toHex() << std::endl;
	std::cout << "Final signature:      " << sigShare.toHex() << std::endl;

	if(keyShareAlice.verify(md,sigShare))
		std::cout << "    Verified!" << std::endl;
	else
		std::cout << "    Invalid signature!" << std::endl;

	auto sharedKeyPair = keyShareAlice.getSharedPubkey();
	auto auxSharedKeyPair = auxKeyShareAlice.getSharedPubkey();
	auto compareSig = sharedKeyPair.signWithAux(md,auxSharedKeyPair);
	std::cout << "Compare signature:      " << compareSig.toHex() << std::endl;
	if(sharedKeyPair.verify(md,compareSig))
		std::cout << "    Verified!" << std::endl;
	else
		std::cout << "    Invalid signature!" << std::endl;
	return 0;
}
