#include <iostream>
#include <chrono>
#include <ctime>
#include "dkg.h"

using namespace std;

int main() {
	SHA256Digest md("message");
	std::chrono::time_point<std::chrono::system_clock> start, end;
	std::chrono::duration<double> elapsed_seconds;
	std::time_t end_time;

	int TIME = 1000;

	cout << "Benchmarking normal use of schnorr signature ..." << endl;
	start = std::chrono::system_clock::now();
	for(int i = 0; i < TIME; i++)
	{
		// Test normal schnorr signature
		auto keyAlice = SchnorrKeyPair::keygen();
		auto auxKeyAlice = SchnorrKeyPair::keygen();
		SchnorrSignature sig = keyAlice.sign(md);
		// cout << "Alice Sig:" << sig.toHex() << endl;
		assert(keyAlice.pubkey().verify(md,sig));
		sig = keyAlice.signWithAux(md,auxKeyAlice);
		// cout << "Alice Sig:" << sig.toHex() << endl;
		assert(keyAlice.pubkey().verify(md,sig));

		// Test shared schnorr signature
		auto keyBob = SchnorrKeyPair::keygen();

		SharedKeyPair keyShareAlice(keyAlice);
		SharedKeyPair keyShareBob(keyBob);
		keyShareAlice.setRemote(keyBob.pubkey());
		keyShareBob.setRemote(keyAlice.pubkey());

		// cout << "Alice's shared key: " << endl;
		// keyShareAlice.print(2);
		// cout << "Bob's shared key: " << endl;
		// keyShareBob.print(2);

		auto auxKeyBob = SchnorrKeyPair::keygen();
		SharedKeyPair auxKeyShareAlice(auxKeyAlice);
		SharedKeyPair auxKeyShareBob(auxKeyBob);
		auxKeyShareAlice.setRemote(auxKeyBob.pubkey());
		auxKeyShareBob.setRemote(auxKeyAlice.pubkey());

		// cout << "Alice's aux shared key: " << endl;
		// auxKeyShareAlice.print(2);
		// cout << "Bob's aux shared key: " << endl;
		// auxKeyShareBob.print(2);

		auto sigAlice = keyShareAlice.sign(md,auxKeyShareAlice);
		auto sigBob = keyShareBob.sign(md,auxKeyShareBob);
		auto sigShare = sigAlice + sigBob;
		// cout << "Alice's share of sig: " << sigAlice.toHex() << endl;
		// cout << "Bob's share of sig:   " << sigBob.toHex() << endl;
		// cout << "Final signature:      " << sigShare.toHex() << endl;

		assert(keyShareAlice.verify(md,sigShare));
	}
	end = std::chrono::system_clock::now();
	elapsed_seconds = end-start;
	end_time = std::chrono::system_clock::to_time_t(end);
	std::cout << "finished computation at " << std::ctime(&end_time)
						<< "elapsed time (" << TIME <<" times): " << elapsed_seconds.count() << "s\n";

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
	cout << "Benchmarking distributed generation of schnorr signature" << endl;
	SchnorrDKG<SHA256Digest> dkgAlice, dkgBob;

	start = std::chrono::system_clock::now();
	// Key Agreement
	auto keyGenAlice = dkgAlice.keyGenPubkey();
	auto keyGenBob = dkgBob.keyGenCommit();
	dkgAlice.receive(keyGenBob);
	dkgBob.receive(keyGenAlice);
	dkgAlice.receive(dkgBob.pubkey());
	end = std::chrono::system_clock::now();
	elapsed_seconds = end-start;
	end_time = std::chrono::system_clock::to_time_t(end);
	std::cout << "finished computation at " << std::ctime(&end_time)
						<< "elapsed time: " << elapsed_seconds.count() << "s\n";
	
	start = std::chrono::system_clock::now();
	for(int i = 0; i < TIME; i++)
	{
		// Distributed Sign (for Alice only)
		auto auxAlice = dkgAlice.signPubkeyForMe(md);
		auto auxBob = dkgBob.signCommitForOther(md);
		dkgAlice.receiveAux(auxBob);
		auto sigShareBob = dkgBob.receiveAux(auxAlice);
		dkgAlice.receiveAux(dkgBob.auxkey());
		auto sigFinalAlice = dkgAlice.receiveSig(sigShareBob);

		// cout << "Distributed Generated Key" << endl;
		// dkgAlice.sharePubkey().print();
		// cout << "Distributed Generated Signature" << endl;
		// cout << sigFinalAlice.toHex() << endl;
		assert(dkgAlice.sharePubkey().verify(md,sigFinalAlice));
	}
	end = std::chrono::system_clock::now();
	elapsed_seconds = end-start;
	end_time = std::chrono::system_clock::to_time_t(end);
	std::cout << "finished computation at " << std::ctime(&end_time)
						<< "elapsed time (" << TIME <<" times): " << elapsed_seconds.count() << "s\n";

	start = std::chrono::system_clock::now();
	for(int i = 0; i < TIME; i++)
	{
		// Distributed Sign (for Both)
		auto auxAlice = dkgAlice.signPubkeyForBoth(md);
		auto auxBob = dkgBob.signCommitForBoth(md);
		dkgAlice.receiveAux(auxBob);
		auto sigShareBob = dkgBob.receiveAux(auxAlice);
		auto sigShareAlice = dkgAlice.receiveAux(dkgBob.auxkey());
		auto sigFinalBob = dkgBob.receiveSig(sigShareAlice);
		auto sigFinalAlice = dkgAlice.receiveSig(sigShareBob);

		// cout << "Distributed Generated Key (of Alice)" << endl;
		// dkgAlice.sharePubkey().print();
		// cout << "Distributed Generated Signature" << endl;
		// cout << sigFinalAlice.toHex() << endl;

		// cout << "Distributed Generated Key (of Bob)" << endl;
		// dkgBob.sharePubkey().print();
		// cout << "Distributed Generated Signature" << endl;
		// cout << sigFinalBob.toHex() << endl;

		assert(dkgAlice.sharePubkey().verify(md,sigFinalAlice));
	}
	end = std::chrono::system_clock::now();
	elapsed_seconds = end-start;
	end_time = std::chrono::system_clock::to_time_t(end);
	std::cout << "finished computation at " << std::ctime(&end_time)
						<< "elapsed time (" << TIME <<" times): " << elapsed_seconds.count() << "s\n";
	return 0;
}
