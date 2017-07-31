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

	cout << "Benchmarking normal keygen..." << endl;
	start = std::chrono::system_clock::now();
	for(int i = 0; i < TIME; i++)
	{
		// Test normal schnorr signature
		SchnorrKeyPair::keygen();
	}
	end = std::chrono::system_clock::now();
	elapsed_seconds = end-start;
	end_time = std::chrono::system_clock::to_time_t(end);
	std::cout << "finished computation at " << std::ctime(&end_time)
						<< "elapsed time (" << TIME <<" times): " << elapsed_seconds.count() << "s\n\n";

	auto key = SchnorrKeyPair::keygen();
	auto auxKey = SchnorrKeyPair::keygen();
	SchnorrSignature sig;

	cout << "Benchmarking normal sign..." << endl;
	start = std::chrono::system_clock::now();
	for(int i = 0; i < TIME; i++)
		sig = key.sign(md);
	end = std::chrono::system_clock::now();
	elapsed_seconds = end-start;
	end_time = std::chrono::system_clock::to_time_t(end);
	std::cout << "finished computation at " << std::ctime(&end_time)
						<< "elapsed time (" << TIME <<" times): " << elapsed_seconds.count() << "s\n\n";

	cout << "Benchmarking normal verify..." << endl;
	start = std::chrono::system_clock::now();
	for(int i = 0; i < TIME; i++)
		assert(key.pubkey().verify(md,sig));
	end = std::chrono::system_clock::now();
	elapsed_seconds = end-start;
	end_time = std::chrono::system_clock::to_time_t(end);
	std::cout << "finished computation at " << std::ctime(&end_time)
						<< "elapsed time (" << TIME <<" times): " << elapsed_seconds.count() << "s\n\n";

	cout << "Benchmarking sign with auxiliary key..." << endl;
	start = std::chrono::system_clock::now();
	for(int i = 0; i < TIME; i++)
	{
		sig = key.signWithAux(md,auxKey);
		// cout << "Alice Sig:" << sig.toHex() << endl;
		assert(key.pubkey().verify(md,sig));
	}
	end = std::chrono::system_clock::now();
	elapsed_seconds = end-start;
	end_time = std::chrono::system_clock::to_time_t(end);
	std::cout << "finished computation at " << std::ctime(&end_time)
						<< "elapsed time (" << TIME <<" times): " << elapsed_seconds.count() << "s\n\n";

	SchnorrKeyPair keyAlice;
	SchnorrKeyPair keyBob;
	SharedKeyPair keyShareAlice;
	SharedKeyPair keyShareBob;
	// Benchmark shared schnorr signature
	cout << "Benchmarking shared generation of schnorr key..." << endl;
	start = std::chrono::system_clock::now();
	for(int i = 0; i < TIME; i++)
	{
		keyAlice = SchnorrKeyPair::keygen();
		keyBob = SchnorrKeyPair::keygen();
		keyShareAlice = SharedKeyPair(keyAlice);
		keyShareBob = SharedKeyPair(keyBob);
		keyShareAlice.setRemote(keyBob.pubkey());
		keyShareBob.setRemote(keyAlice.pubkey());
	}
	end = std::chrono::system_clock::now();
	elapsed_seconds = end-start;
	end_time = std::chrono::system_clock::to_time_t(end);
	std::cout << "finished computation at " << std::ctime(&end_time)
						<< "elapsed time (" << TIME <<" times): " << elapsed_seconds.count() << "s\n\n";

	SchnorrKeyPair auxKeyBob;
	SchnorrKeyPair auxKeyAlice;
	cout << "Benchmarking shared generation of schnorr signature..." << endl;
	for(int i = 0; i < TIME; i++)
	{
		auxKeyAlice = SchnorrKeyPair::keygen();
		auxKeyBob = SchnorrKeyPair::keygen();
		SharedKeyPair auxKeyShareAlice(auxKeyAlice);
		SharedKeyPair auxKeyShareBob(auxKeyBob);
		auxKeyShareAlice.setRemote(auxKeyBob.pubkey());
		auxKeyShareBob.setRemote(auxKeyAlice.pubkey());

		auto sigAlice = keyShareAlice.sign(md,auxKeyShareAlice);
		auto sigBob = keyShareBob.sign(md,auxKeyShareBob);
		auto sigShare = sigAlice + sigBob;
		assert(keyShareAlice.verify(md,sigShare));
	}
	end = std::chrono::system_clock::now();
	elapsed_seconds = end-start;
	end_time = std::chrono::system_clock::to_time_t(end);
	std::cout << "finished computation at " << std::ctime(&end_time)
						<< "elapsed time (" << TIME <<" times): " << elapsed_seconds.count() << "s\n\n";

	SchnorrDKG<SHA256Digest> dkgAlice, dkgBob;

	cout << "Benchmarking distributed generation of schnorr key" << endl;
	start = std::chrono::system_clock::now();
	PubkeyOrCommitment keyGenAlice = Commitment();
	PubkeyOrCommitment keyGenBob = Commitment();
	for(int i = 0; i < TIME; i++)
	{
		dkgAlice = SchnorrDKG<SHA256Digest>();
		dkgBob = SchnorrDKG<SHA256Digest>();
		// Key Agreement
		keyGenAlice = dkgAlice.keyGenPubkey();
		keyGenBob = dkgBob.keyGenCommit();
		dkgAlice.receive(keyGenBob);
		dkgBob.receive(keyGenAlice);
		dkgAlice.receive(dkgBob.pubkey());
	}
	end = std::chrono::system_clock::now();
	elapsed_seconds = end-start;
	end_time = std::chrono::system_clock::to_time_t(end);
	std::cout << "finished computation at " << std::ctime(&end_time)
						<< "elapsed time: " << elapsed_seconds.count() << "s\n\n";
	
	cout << "Benchmarking distributed generation of schnorr signature (for one party)" << endl;
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
						<< "elapsed time (" << TIME <<" times): " << elapsed_seconds.count() << "s\n\n";

	cout << "Benchmarking distributed generation of schnorr signature (for both party)" << endl;
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
						<< "elapsed time (" << TIME <<" times): " << elapsed_seconds.count() << "s\n\n";
	return 0;
}
