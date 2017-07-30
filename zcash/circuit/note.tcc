template<typename FieldT>
class note_gadget : public gadget<FieldT> {
		std::string annotation;
public:
    pb_variable_array<FieldT> value;
    std::shared_ptr<digest_variable<FieldT>> r;

    note_gadget(protoboard<FieldT> &pb,const std::string& annotation) : gadget<FieldT>(pb,annotation), annotation(annotation) {
        value.allocate(pb, 64, annotation+" note_gadget_value");
        r.reset(new digest_variable<FieldT>(pb, 256, annotation+" note_gadget_r"));
    }

    void generate_r1cs_constraints() {
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>(
                this->pb,
                value[i],
                annotation+" boolean_value"
            );
        }

        r->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(const Note& note) {
        r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note.r));
        value.fill_with_bits(this->pb, uint64_to_bool_vector(note.value));
    }
};

template<typename FieldT>
class input_note_gadget : public note_gadget<FieldT> {
private:
    std::shared_ptr<digest_variable<FieldT>> a_pk;
    std::shared_ptr<digest_variable<FieldT>> rho;

    std::shared_ptr<digest_variable<FieldT>> commitment;
    std::shared_ptr<input_note_commitment_gadget<FieldT>> commit_to_inputs;

    pb_variable<FieldT> value_enforce;
    std::shared_ptr<merkle_tree_gadget<FieldT>> witness_input;

    std::shared_ptr<PRF_addr_a_pk_gadget<FieldT>> spend_authority;
    std::shared_ptr<PRF_nf_gadget<FieldT>> expose_nullifiers;

		std::string annotation;
public:
    std::shared_ptr<digest_variable<FieldT>> a_sk;

    input_note_gadget(
        protoboard<FieldT>& pb,
        pb_variable<FieldT>& ZERO,
        std::shared_ptr<digest_variable<FieldT>> nullifier,
        std::shared_ptr<digest_variable<FieldT>> pkh,
				pb_variable_array<FieldT>& tlock,
        digest_variable<FieldT> rt,
				const std::string &annotation
    ) : note_gadget<FieldT>(pb,annotation), annotation(annotation) {
        a_sk.reset(new digest_variable<FieldT>(pb, 252, annotation+" input_a_sk"));
        a_pk.reset(new digest_variable<FieldT>(pb, 256, annotation+" input_a_pk"));
        rho.reset(new digest_variable<FieldT>(pb, 256, annotation+" input_rho"));
        commitment.reset(new digest_variable<FieldT>(pb, 256, annotation+" input_commit"));

        spend_authority.reset(new PRF_addr_a_pk_gadget<FieldT>(
            pb,
            ZERO,
            a_sk->bits,
            a_pk,
						annotation+" spend_authority"
        ));

        expose_nullifiers.reset(new PRF_nf_gadget<FieldT>(
            pb,
            ZERO,
            a_sk->bits,
            rho->bits,
            nullifier,
						annotation+" expose_nullifier"
        ));

        commit_to_inputs.reset(new input_note_commitment_gadget<FieldT>(
            pb,
            ZERO,
            a_pk->bits,
            this->a_sk->bits,
            this->value,
            rho->bits,
            this->r->bits,
						pkh->bits,
						tlock,
            commitment,
						annotation+" commit_to_inputs"
        ));

        value_enforce.allocate(pb,annotation+" input_note_value_enforce");

        witness_input.reset(new merkle_tree_gadget<FieldT>(
            pb,
            *commitment,
            rt,
            value_enforce,
						annotation+" witness_input"
        ));
    }

    void generate_r1cs_constraints() {
        note_gadget<FieldT>::generate_r1cs_constraints();

        a_sk->generate_r1cs_constraints();
        rho->generate_r1cs_constraints();

        spend_authority->generate_r1cs_constraints();
        expose_nullifiers->generate_r1cs_constraints();

        commit_to_inputs->generate_r1cs_constraints();

        // value * (1 - enforce) = 0
        // Given `enforce` is boolean constrained:
        // If `value` is zero, `enforce` _can_ be zero.
        // If `value` is nonzero, `enforce` _must_ be one.
        generate_boolean_r1cs_constraint<FieldT>(this->pb, value_enforce,annotation+" input_note_value_enforce");

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
            packed_addition(this->value),
            (1 - value_enforce),
            0
        ), annotation+" input_value_enforce");

        witness_input->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(
        const MerklePath& path,
        const SpendingKey& key,
        const Note& note
    ) {
        note_gadget<FieldT>::generate_r1cs_witness(note);

        // Witness a_sk for the input
        a_sk->bits.fill_with_bits(
            this->pb,
            uint252_to_bool_vector(key)
        );

        // Witness a_pk for a_sk with PRF_addr
        spend_authority->generate_r1cs_witness();

        // [SANITY CHECK] Witness a_pk with note information
        a_pk->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.a_pk)
        );

        // Witness rho for the input note
        rho->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.rho)
        );

        // Witness the nullifier for the input note
        expose_nullifiers->generate_r1cs_witness();

        // Witness the commitment of the input note
        commit_to_inputs->generate_r1cs_witness();

        // [SANITY CHECK] Ensure the commitment is
        // valid.
        commitment->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.cm())
        );

        // Set enforce flag for nonzero input value
        this->pb.val(value_enforce) = (note.value != 0) ? FieldT::one() : FieldT::zero();

        // Witness merkle tree authentication path
        witness_input->generate_r1cs_witness(path);
    }
};

template<typename FieldT>
class output_note_gadget : public note_gadget<FieldT> {
private:
    std::shared_ptr<digest_variable<FieldT>> rho;
    std::shared_ptr<digest_variable<FieldT>> a_pk;
    std::shared_ptr<digest_variable<FieldT>> pkcm;

    std::shared_ptr<PRF_rho_gadget<FieldT>> prevent_faerie_gold;
    std::shared_ptr<note_commitment_gadget<FieldT>> commit_to_outputs;
		pb_variable_array<FieldT> tlock;

public:
    output_note_gadget(
        protoboard<FieldT>& pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& phi,
        pb_variable_array<FieldT>& h_sig,
        bool nonce,
        std::shared_ptr<digest_variable<FieldT>> commitment,
				const std::string& annotation
    ) : note_gadget<FieldT>(pb,annotation) {
        rho.reset(new digest_variable<FieldT>(pb, 256, annotation+" output_rho"));
        a_pk.reset(new digest_variable<FieldT>(pb, 256, annotation+" output_a_pk"));
				pkcm.reset(new digest_variable<FieldT>(pb, 256, annotation+" output_pkcm"));
				tlock.allocate(pb,64,annotation+" output_tlock");

        // Do not allow the caller to choose the same "rho"
        // for any two valid notes in a given view of the
        // blockchain. See protocol specification for more
        // details.
        prevent_faerie_gold.reset(new PRF_rho_gadget<FieldT>(
            pb,
            ZERO,
            phi,
            h_sig,
            nonce,
            rho,
						annotation+" prevent_faerie"
        ));

        // Commit to the output notes publicly without
        // disclosing them.
        commit_to_outputs.reset(new note_commitment_gadget<FieldT>(
            pb,
            ZERO,
            a_pk->bits,
            this->value,
            rho->bits,
            this->r->bits,
						this->pkcm->bits,
						this->tlock,
            commitment,
						annotation+" commit_to_outputs"
        ));
    }

    void generate_r1cs_constraints() {
        note_gadget<FieldT>::generate_r1cs_constraints();

        a_pk->generate_r1cs_constraints();

        prevent_faerie_gold->generate_r1cs_constraints();

        commit_to_outputs->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(const Note& note) {
        note_gadget<FieldT>::generate_r1cs_witness(note);

        prevent_faerie_gold->generate_r1cs_witness();

        // [SANITY CHECK] Witness rho ourselves with the
        // note information.
        rho->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.rho)
        );

        a_pk->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.a_pk)
        );

				pkcm->bits.fill_with_bits(
						this->pb,
						uint256_to_bool_vector(note.pkcm)
				);

				tlock.fill_with_bits(
						this->pb,
						uint64_to_bool_vector(note.tlock)
				);

        commit_to_outputs->generate_r1cs_witness();
    }
};
