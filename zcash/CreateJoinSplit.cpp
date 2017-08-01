// Copyright (c) 2016 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chrono>
#include <ctime>

#include "zcashutil.h"
#include "primitives/transaction.h"
#include "JoinSplit.hpp"
#include "common/profiling.hpp"

using namespace libzcash;

int main(int argc, char **argv)
{
    libsnark::start_profiling();

    if(argc != 3) {
        std::cerr << "Usage: " << argv[0] << " provingKeyFileName verificationKeyFileName" << std::endl;
        return 1;
    }
    std::string pkFile = argv[1];
    std::string vkFile = argv[2];

    auto p = ZCJoinSplit::Unopened();
    p->loadVerifyingKey(vkFile);
    p->setProvingKeyPath(pkFile);
    p->loadProvingKey();

    // construct a proof.

    // for (int i = 0; i < 15; i++) {
			uint256 anchor = ZCIncrementalMerkleTree().root();
			uint256 pubKeyHash;
			BHeight BH1=0,BH2=0,MBH=1000;
			bool ovd1,ovd2;
			auto verifier = ProofVerifier::Strict();

			JSDescription jsdesc(*p,
													 pubKeyHash,
													 MBH,
													 {BH1,BH2},
													 {ovd1,ovd2},
													 {anchor, anchor},
													 {JSInput(), JSInput()},
													 {JSOutput(), JSOutput()},
													 0,
													 0);

			std::chrono::time_point<std::chrono::system_clock> start,end;
			std::chrono::duration<double> elapsed_seconds;

			start = std::chrono::system_clock::now();
			for(int i = 0; i < 1000; i++)
				jsdesc.Verify(*p, verifier, pubKeyHash);
			end = std::chrono::system_clock::now();
			elapsed_seconds = end-start;
			std::cout << "Elapsed time (1000 verifications): " << elapsed_seconds.count() << "s\n\n";
    // }
}
