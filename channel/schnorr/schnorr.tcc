template<typename DigestType>
SchnorrSignature SchnorrKeyPair::signWithAux(const DigestType &md, const SchnorrKeyPair& aux) const {
	std::call_once(initflag,SchnorrSignature::initSchnorr);

	assert(a);
	assert(aux.a);
	assert(aux.p);

	int res = 0;
	BIGNUM *e = NULL;
	BIGNUM *s = NULL;
	BIGNUM *x0 = NULL;
	BIGNUM *y0 = NULL;
	unsigned char x0bin[33];
	size_t x0len;

	DigestType digest;

	// Initialize all structures -----------------------
	e = BN_new();
	if(!e) {
		fprintf(stderr,"%s: Failedto create e\n",__func__);
		goto error;
	}
	s = BN_new();
	if(!s) {
		fprintf(stderr,"%s: Failedto create s\n",__func__);
		goto error;
	}
	x0 = BN_new();
	if(!x0) {
		fprintf(stderr,"%s: Failedto create x0\n",__func__);
		goto error;
	}
	y0 = BN_new();
	if(!y0) {
		fprintf(stderr,"%s: Failedto create y0\n",__func__);
		goto error;
	}

	// Start the algorithm -----------------------------
	//
	EC_POINT_get_affine_coordinates_GFp(group,aux.p,x0,y0,ctx);
	x0len = BN_num_bytes(x0);
	BN_bn2bin(x0,x0bin);
	digest = DigestType(x0bin,x0len,md.data(),md.size());
	BN_bin2bn(digest.data(),digest.size(),e);
	BN_mod_mul(s,a,e,order,ctx);
	BN_mod_sub(s,aux.a,s,order,ctx);

	res = 1;

error:
	if(!res) {
		fprintf(stderr,"Error in schnorr sign with aux!\n");
	}
	SchnorrSignature sig;
	if(res == 1) {
		sig = SchnorrSignature(e,s);
	}
	if(e) BN_free(e);
	if(s) BN_free(s);
	if(x0) BN_free(x0);
	if(y0) BN_free(y0);
	return sig;
}

template<typename DigestType>
SchnorrSignature SchnorrKeyPair::sign(const DigestType &md) const {
	SchnorrKeyPair aux = SchnorrKeyPair::keygen();
	SchnorrSignature sig = signWithAux(md,aux);
	return sig;
}

template<typename DigestType>
bool SchnorrKeyPair::verify(const DigestType &md, const SchnorrSignature &sig) const {
	int res = 0;
	bool ret;
	BIGNUM *ev = NULL;
	BIGNUM *x0 = NULL;
	BIGNUM *y0 = NULL;
	EC_POINT *kG = NULL;
	unsigned char x0bin[33];
	size_t x0len;

	DigestType digest;

	ev = BN_new();
	if(!ev) {
		fprintf(stderr,"%s: Failedto create ev\n",__func__);
		goto error;
	}
	x0 = BN_new();
	if(!x0) {
		fprintf(stderr,"%s: Failedto create x0\n",__func__);
		goto error;
	}
	y0 = BN_new();
	if(!y0) {
		fprintf(stderr,"%s: Failedto create y0\n",__func__);
		goto error;
	}
	kG = EC_POINT_new(group);
	if(!kG) {
		fprintf(stderr,"%s: Failed to create kG\n",__func__);
		goto error;
	}

	// Start verification
	EC_POINT_mul(group,kG,sig.s,p,sig.e,ctx);
	EC_POINT_get_affine_coordinates_GFp(group,kG,x0,y0,ctx);
	x0len = BN_num_bytes(x0);
	BN_bn2bin(x0,x0bin);

	digest = DigestType(x0bin,x0len,md.data(),md.size());

	BN_bin2bn(digest.data(),digest.size(),ev);
	ret = BN_cmp(sig.e,ev) == 0;
	res = 1;
error:
	if(!res) {
		fprintf(stderr,"Error in schnorr verify!\n");
	}
	if(ev) BN_free(ev);
	if(x0) BN_free(x0);
	if(y0) BN_free(y0);
	if(kG) EC_POINT_free(kG);
	return ret;
}

