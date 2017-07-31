#include "schnorr/schnorr.h"
#include "schnorr/dkg.h"
#include "schnorr/digest.h"
#include "schnorr/schnorr.h"
#include "channel.h"

Commitment uint256::commit() const {
	SHA256Digest digest(data(),32);
	return digest.getArray();
}

Commitment uint256::commit(const uint256 &trapdoor) const {
	SHA256Digest digest(trapdoor.data(),32,data(),32);
	return digest.getArray();
}
