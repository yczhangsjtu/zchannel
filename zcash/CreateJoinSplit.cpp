// Copyright (c) 2016 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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

    // for (int i = 0; i < 5; i++) {
		uint256 anchor = ZCIncrementalMerkleTree().root();
		uint256 pubKeyHash;

		JSDescription jsdesc(*p,
												 pubKeyHash,
												 {anchor, anchor},
												 {JSInput(), JSInput()},
												 {JSOutput(), JSOutput()},
												 0,
												 0);
    // }
}
