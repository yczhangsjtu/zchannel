#include "schnorr.h"
#include "dkg.h"
#include "digest.h"

template<size_t n>
SharedSignature SharedKeyPair::sign(const Digest<n> &md, const SharedKeyPair &aux) const {
}

PubkeyOrCommitment SchnorrDKG::KeyGen(int sendWhat) {
}

