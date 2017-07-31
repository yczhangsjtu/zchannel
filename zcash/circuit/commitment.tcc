template<typename FieldT>
class note_commitment_gadget : gadget<FieldT> {
private:
    std::shared_ptr<block_variable<FieldT>> cm_block1;
    std::shared_ptr<block_variable<FieldT>> cm_block2;
    std::shared_ptr<block_variable<FieldT>> cm_block3;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> cm_hasher1;
    std::shared_ptr<digest_variable<FieldT>> cm_intermediate_hash1;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> cm_hasher2;
    std::shared_ptr<digest_variable<FieldT>> cm_intermediate_hash2;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> cm_hasher3;

public: note_commitment_gadget(
        protoboard<FieldT> &pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& a_pk, // 256 bit
        pb_variable_array<FieldT>& v, // 64 bit
        pb_variable_array<FieldT>& rho, // 256 bit
        pb_variable_array<FieldT>& r, // 256 bit
        pb_variable_array<FieldT>& pkcm, // 256 bit
        pb_variable_array<FieldT>& tlock, // 64 bit
        std::shared_ptr<digest_variable<FieldT>> result,
				const std::string& annotation
    ) : gadget<FieldT>(pb,annotation) {
					{
						pb_variable_array<FieldT> leading_byte =
							from_bits({1, 0, 1, 1, 0, 0, 0, 0}, ZERO);

						pb_variable_array<FieldT> first_of_rho(rho.begin(), rho.begin()+184);
						pb_variable_array<FieldT> last_of_rho(rho.begin()+184, rho.end());

						pb_variable_array<FieldT> first_of_pkcm(pkcm.begin(), pkcm.begin()+184);
						pb_variable_array<FieldT> last_of_pkcm(pkcm.begin()+184, pkcm.end());

						cm_intermediate_hash1.reset(new digest_variable<FieldT>(pb, 256, annotation+" cm_inter_hash1"));
						cm_intermediate_hash2.reset(new digest_variable<FieldT>(pb, 256, annotation+" cm_inter_hash2"));

						// final padding
						pb_variable_array<FieldT> length_padding =
							from_bits({
									// padding (39 bytes)
									1,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,

									// length of message (1160 bits)
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,0,0,0,
									0,0,0,0,0,1,0,0,
									1,0,0,0,1,0,0,0
							}, ZERO);

						cm_block1.reset(new block_variable<FieldT>(pb, {
									leading_byte,
									a_pk,
									v,
									first_of_rho
									}, annotation+" note_cm_block1"));
						assert(leading_byte.size() + a_pk.size() + v.size() + first_of_rho.size() == 512);

						cm_block2.reset(new block_variable<FieldT>(pb, {
									last_of_rho,
									r,
									first_of_pkcm
									}, annotation+" note_cm_block2"));
						assert(last_of_rho.size()+r.size()+first_of_pkcm.size() == 512);

						cm_block3.reset(new block_variable<FieldT>(pb, {
									last_of_pkcm,
									tlock,
									length_padding	
									}, annotation+" note_cm_block3"));

						assert(last_of_pkcm.size()+tlock.size()+length_padding.size()==512);

						pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

						cm_hasher1.reset(new sha256_compression_function_gadget<FieldT>(
									pb,
									IV,
									cm_block1->bits,
									*cm_intermediate_hash1,
									annotation+" note_cm_hasher1"));

						pb_linear_combination_array<FieldT> IV2(cm_intermediate_hash1->bits);

						cm_hasher2.reset(new sha256_compression_function_gadget<FieldT>(
									pb,
									IV2,
									cm_block2->bits,
									*cm_intermediate_hash2,
									annotation+" note_cm_hasher2"));
						pb_linear_combination_array<FieldT> IV3(cm_intermediate_hash2->bits);

						cm_hasher3.reset(new sha256_compression_function_gadget<FieldT>(
									pb,
									IV3,
									cm_block3->bits,
									*result,
									annotation+" note_cm_hasher3"));
					}
    }

    void generate_r1cs_constraints() {
        cm_hasher1->generate_r1cs_constraints();
        cm_hasher2->generate_r1cs_constraints();
        cm_hasher3->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        cm_hasher1->generate_r1cs_witness();
        cm_hasher2->generate_r1cs_witness();
        cm_hasher3->generate_r1cs_witness();
    }
};

template<typename FieldT>
class input_note_commitment_gadget : gadget<FieldT> {
private:
    std::shared_ptr<digest_variable<FieldT>> pkcm;
    std::shared_ptr<block_variable<FieldT>> pkcm_block1;
    std::shared_ptr<block_variable<FieldT>> pkcm_block2;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> pkcm_hasher1;
    std::shared_ptr<digest_variable<FieldT>> pkcm_intermediate_hash1;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> pkcm_hasher2;
    std::shared_ptr<note_commitment_gadget<FieldT>> note_gadget;
public:
		input_note_commitment_gadget(
        protoboard<FieldT> &pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& a_pk, // 256 bit
        pb_variable_array<FieldT>& a_sk, // 252 bit
        pb_variable_array<FieldT>& v, // 64 bit
        pb_variable_array<FieldT>& rho, // 256 bit
        pb_variable_array<FieldT>& r, // 256 bit
        pb_variable_array<FieldT>& pkh, // 256 bit
        pb_variable_array<FieldT>& tlock, // 64 bit
        std::shared_ptr<digest_variable<FieldT>> result,
				const std::string& annotation
				) : gadget<FieldT>(pb,annotation) {
			pb_variable_array<FieldT> leading_byte =
				from_bits({0, 0, 0, 0}, ZERO);

			pkcm_intermediate_hash1.reset(new digest_variable<FieldT>(pb, 256, annotation+" inputnote_pkcm_interhash1"));
			pkcm.reset(new digest_variable<FieldT>(pb,256,annotation+" inputnote_pkcm"));

			// final padding
			pb_variable_array<FieldT> length_padding =
				from_bits({
						// padding (56 bytes)
						1,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,

						// length of message (512 bits)
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,0,0,
						0,0,0,0,0,0,1,0,
						0,0,0,0,0,0,0,0
				}, ZERO);

			pkcm_block1.reset(new block_variable<FieldT>(pb, {
						leading_byte,
						a_sk,
						pkh
						}, annotation+" pkcm_block1"));

			pkcm_block2.reset(new block_variable<FieldT>(pb, {
						length_padding
						}, annotation+" pkcm_block2"));

			pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

			pkcm_hasher1.reset(new sha256_compression_function_gadget<FieldT>(
						pb,
						IV,
						pkcm_block1->bits,
						*pkcm_intermediate_hash1,
						annotation+" pkcm_hasher1"));

			pb_linear_combination_array<FieldT> IV2(pkcm_intermediate_hash1->bits);

			pkcm_hasher2.reset(new sha256_compression_function_gadget<FieldT>(
						pb,
						IV2,
						pkcm_block2->bits,
						*pkcm,
						annotation+" pkcm_hasher2"));

			note_gadget.reset(new note_commitment_gadget<FieldT>(
						pb,
						ZERO,
						a_pk, // 256 bit
						v, // 64 bit
						rho, // 256 bit
						r, // 256 bit
						pkcm->bits, // 256 bit
						tlock, // 64 bit
						result,
						annotation+" note_gadget_note_commitment"));

		}
    void generate_r1cs_constraints() {
        pkcm_hasher1->generate_r1cs_constraints();
        pkcm_hasher2->generate_r1cs_constraints();
        note_gadget->generate_r1cs_constraints();
		}
    void generate_r1cs_witness() {
        pkcm_hasher1->generate_r1cs_witness();
        pkcm_hasher2->generate_r1cs_witness();
        note_gadget->generate_r1cs_witness();
		}
};
