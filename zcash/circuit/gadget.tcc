#include "zcash/circuit/utils.tcc"
#include "zcash/circuit/prfs.tcc"
#include "zcash/circuit/commitment.tcc"
#include "zcash/circuit/merkle.tcc"
#include "zcash/circuit/note.tcc"

template<typename FieldT, size_t NumInputs, size_t NumOutputs>
class joinsplit_gadget : gadget<FieldT> {
	private:
		// Verifier inputs
		pb_variable_array<FieldT> zk_packed_inputs;
		pb_variable_array<FieldT> zk_unpacked_inputs;
		std::shared_ptr<multipacking_gadget<FieldT>> unpacker;

		boost::array<std::shared_ptr<digest_variable<FieldT>>, NumInputs> zk_merkle_root;
		std::shared_ptr<digest_variable<FieldT>> zk_h_sig;
		boost::array<std::shared_ptr<digest_variable<FieldT>>, NumInputs> zk_input_nullifiers;
		boost::array<std::shared_ptr<digest_variable<FieldT>>, NumInputs> zk_input_macs;
		boost::array<std::shared_ptr<digest_variable<FieldT>>, NumOutputs> zk_output_commitments;
		pb_variable_array<FieldT> zk_vpub_old;
		pb_variable_array<FieldT> zk_vpub_new;

		// Verifier inputs for zchannel
		boost::array<std::shared_ptr<digest_variable<FieldT>>, NumInputs> zk_pkh;
		boost::array<pb_variable_array<FieldT>, NumInputs> bh64;
		boost::array<pb_variable_array<FieldT>, NumInputs> ovd64;
		pb_variable_array<FieldT> mbh64;

		// Aux inputs
		pb_variable<FieldT> ZERO;
		std::shared_ptr<digest_variable<FieldT>> zk_phi;
		pb_variable_array<FieldT> zk_total_uint64;

		// Aux inputs for zchannel
		boost::array<pb_variable_array<FieldT>, NumInputs> tlock64;
		boost::array<pb_variable_array<FieldT>, NumInputs> ladd64;
		boost::array<pb_variable_array<FieldT>, NumInputs> radd64;

		// Input note gadgets
		boost::array<std::shared_ptr<input_note_gadget<FieldT>>, NumInputs> zk_input_notes;
		boost::array<std::shared_ptr<PRF_pk_gadget<FieldT>>, NumInputs> zk_mac_authentication;

		// Output note gadgets
		boost::array<std::shared_ptr<output_note_gadget<FieldT>>, NumOutputs> zk_output_notes;

	public:
		// PRF_pk only has a 1-bit domain separation "nonce"
		// for different macs.
		BOOST_STATIC_ASSERT(NumInputs <= 2);

		// PRF_rho only has a 1-bit domain separation "nonce"
		// for different output `rho`.
		BOOST_STATIC_ASSERT(NumOutputs <= 2);

		joinsplit_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
			// Verification
			{
				// The verification inputs are all bit-strings of various
				// lengths (256-bit digests and 64-bit integers) and so we
				// pack them into as few field elements as possible. (The
				// more verification inputs you have, the more expensive
				// verification is.)
				zk_packed_inputs.allocate(pb, verifying_field_element_size());
				pb.set_input_sizes(verifying_field_element_size());

				alloc_uint256(zk_unpacked_inputs, zk_h_sig);

				for (size_t i = 0; i < NumInputs; i++) {
					alloc_uint256(zk_unpacked_inputs, zk_merkle_root[i]);
					alloc_uint256(zk_unpacked_inputs, zk_input_nullifiers[i]);
					alloc_uint256(zk_unpacked_inputs, zk_input_macs[i]);

					// ZChannel part
					alloc_uint256(zk_unpacked_inputs, zk_pkh[i]);
					alloc_uint64(zk_unpacked_inputs, bh64[i]);
					alloc_uint64(zk_unpacked_inputs, ovd64[i]);
				}

				for (size_t i = 0; i < NumOutputs; i++) {
					alloc_uint256(zk_unpacked_inputs, zk_output_commitments[i]);
				}

				alloc_uint64(zk_unpacked_inputs, zk_vpub_old);
				alloc_uint64(zk_unpacked_inputs, zk_vpub_new);

				// ZChannel part
				alloc_uint64(zk_unpacked_inputs, mbh64);

				assert(zk_unpacked_inputs.size() == verifying_input_bit_size());

				// This gadget will ensure that all of the inputs we provide are
				// boolean constrained.
				unpacker.reset(new multipacking_gadget<FieldT>(
							pb,
							zk_unpacked_inputs,
							zk_packed_inputs,
							FieldT::capacity(),
							"unpacker"
							));
			}

			// We need a constant "zero" variable in some contexts. In theory
			// it should never be necessary, but libsnark does not synthesize
			// optimal circuits.
			// 
			// The first variable of our constraint system is constrained
			// to be one automatically for us, and is known as `ONE`.
			ZERO.allocate(pb);

			zk_phi.reset(new digest_variable<FieldT>(pb, 252, ""));

			zk_total_uint64.allocate(pb, 64);

			for (size_t i = 0; i < NumInputs; i++) {
				// Input note gadget for commitments, macs, nullifiers,
				// and spend authority.
				zk_input_notes[i].reset(new input_note_gadget<FieldT>(
							pb,
							ZERO,
							zk_input_nullifiers[i],
							zk_pkh[i],
							tlock64[i],
							*zk_merkle_root[i]
							));

				// The input keys authenticate h_sig to prevent
				// malleability.
				zk_mac_authentication[i].reset(new PRF_pk_gadget<FieldT>(
							pb,
							ZERO,
							zk_input_notes[i]->a_sk->bits,
							zk_h_sig->bits,
							i ? true : false,
							zk_input_macs[i]
							));

				// For ZChannel
				tlock64[i].allocate(pb,64);
				ladd64[i].allocate(pb,64);
				radd64[i].allocate(pb,64);

			}
			// mbh.allocate(pb);

			for (size_t i = 0; i < NumOutputs; i++) {
				zk_output_notes[i].reset(new output_note_gadget<FieldT>(
							pb,
							ZERO,
							zk_phi->bits,
							zk_h_sig->bits,
							i ? true : false,
							zk_output_commitments[i]
							));
			}
		}

		void generate_r1cs_constraints() {
			// The true passed here ensures all the inputs
			// are boolean constrained.
			unpacker->generate_r1cs_constraints(true);

			// Constrain `ZERO`
			generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");

			// Constrain bitness of phi
			zk_phi->generate_r1cs_constraints();

			for (size_t i = 0; i < NumInputs; i++) {
				// Constrain the JoinSplit input constraints.
				zk_input_notes[i]->generate_r1cs_constraints();

				// Authenticate h_sig with a_sk
				zk_mac_authentication[i]->generate_r1cs_constraints();
			}

			for (size_t i = 0; i < NumOutputs; i++) {
				// Constrain the JoinSplit output constraints.
				zk_output_notes[i]->generate_r1cs_constraints();
			}

			// Value balance
			{
				linear_combination<FieldT> left_side = packed_addition(zk_vpub_old);
				for (size_t i = 0; i < NumInputs; i++) {
					left_side = left_side + packed_addition(zk_input_notes[i]->value);
				}

				linear_combination<FieldT> right_side = packed_addition(zk_vpub_new);
				for (size_t i = 0; i < NumOutputs; i++) {
					right_side = right_side + packed_addition(zk_output_notes[i]->value);
				}

				// Ensure that both sides are equal
				this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
							1,
							left_side,
							right_side
							));

				// #854: Ensure that left_side is a 64-bit integer.
				for (size_t i = 0; i < 64; i++) {
					generate_boolean_r1cs_constraint<FieldT>(
							this->pb,
							zk_total_uint64[i],
							""
							);
				}

				this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
							1,
							left_side,
							packed_addition(zk_total_uint64)
							));
			}

			// Time Lock
			{
				// MSB is stored at position 56 (because bytes are stored in little endian,
				// but in each byte the bits are stored in big endian!!)
				// Likewise, LSB is stored at position 7
				const size_t MSB_POS = 56;
				const size_t LSB_POS = 7;
				// MSB is constrained to 0: mbh < 2^63
				generate_r1cs_equals_const_constraint<FieldT>(this->pb, mbh64[MSB_POS], FieldT::zero(), "ZERO");
				for (size_t i = 0; i < 64; i++) {
					generate_boolean_r1cs_constraint<FieldT>(
							this->pb,
							mbh64[i],
							""
							);
				}
				for (size_t i = 0; i < NumInputs; i++) {
					// OVD is contrained to 0 or 1
					generate_boolean_r1cs_constraint<FieldT>(this->pb, ovd64[i][LSB_POS], "ZERO");
					for (size_t j = 0; j < 64; j++) {
						if(j != LSB_POS) {
							generate_r1cs_equals_const_constraint<FieldT>(
									this->pb,
									ovd64[i][j], FieldT::zero(),
									""
									);
						}
					}
					// bh < 2^63
					generate_r1cs_equals_const_constraint<FieldT>(this->pb, bh64[i][MSB_POS], FieldT::zero(), "ZERO");
					for (size_t j = 0; j < 64; j++) {
						generate_boolean_r1cs_constraint<FieldT>(
								this->pb,
								bh64[i][j],
								""
								);
					}
					// tlock < 2^63
					generate_r1cs_equals_const_constraint<FieldT>(this->pb, tlock64[i][MSB_POS], FieldT::zero(), "ZERO");
					for (size_t j = 0; j < 64; j++) {
						generate_boolean_r1cs_constraint<FieldT>(
								this->pb,
								tlock64[i][j],
								""
								);
					}
					// ladd < 2^63
					generate_r1cs_equals_const_constraint<FieldT>(this->pb, ladd64[i][MSB_POS], FieldT::zero(), "ZERO");
					for (size_t j = 0; j < 64; j++) {
						generate_boolean_r1cs_constraint<FieldT>(
								this->pb,
								ladd64[i][j],
								""
								);
					}
					// ladd < 2^63
					generate_r1cs_equals_const_constraint<FieldT>(this->pb, radd64[i][MSB_POS], FieldT::zero(), "ZERO");
					for (size_t j = 0; j < 64; j++) {
						generate_boolean_r1cs_constraint<FieldT>(
								this->pb,
								radd64[i][j],
								""
								);
					}
					linear_combination<FieldT> left_side = packed_addition(bh64[i]);
					left_side = left_side + packed_addition(tlock64[i]);

					linear_combination<FieldT> right_side = packed_addition(mbh64);
					right_side = right_side + packed_addition(radd64[i]);

					// Ensure that both sides are equal
					this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
								1,
								left_side,
								right_side
								));

					// Ensure that either ovd = 0 or radd = 0
					this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
								packed_addition(ovd64[i]),
								packed_addition(radd64[i]),
								0 * ONE
								));
				}
			}
		}

		void generate_r1cs_witness(
				const uint252& phi,
				const boost::array<uint256, NumInputs>& rt,
				uint64_t mbh,
				const boost::array<uint64_t, NumInputs>& bh,
				const boost::array<bool, NumInputs>& ovd,
				const uint256& h_sig,
				const boost::array<JSInput, NumInputs>& inputs,
				const boost::array<Note, NumOutputs>& outputs,
				uint64_t vpub_old,
				uint64_t vpub_new
				) {
			// Witness `zero`
			this->pb.val(ZERO) = FieldT::zero();

			// Witness rt. This is not a sanity check.
			//
			// This ensures the read gadget constrains
			// the intended root in the event that
			// both inputs are zero-valued.
			for(size_t i = 0; i < NumInputs; i++) {
				zk_merkle_root[i]->bits.fill_with_bits(
						this->pb,
						uint256_to_bool_vector(rt[i])
						);
			}

			// Witness public balance values
			zk_vpub_old.fill_with_bits(
					this->pb,
					uint64_to_bool_vector(vpub_old)
					);
			zk_vpub_new.fill_with_bits(
					this->pb,
					uint64_to_bool_vector(vpub_new)
					);

			{
				// Witness total_uint64 bits
				uint64_t left_side_acc = vpub_old;
				for (size_t i = 0; i < NumInputs; i++) {
					left_side_acc += inputs[i].note.value;
				}

				zk_total_uint64.fill_with_bits(
						this->pb,
						uint64_to_bool_vector(left_side_acc)
						);
			}

			// Witness phi
			zk_phi->bits.fill_with_bits(
					this->pb,
					uint252_to_bool_vector(phi)
					);

			// Witness h_sig
			zk_h_sig->bits.fill_with_bits(
					this->pb,
					uint256_to_bool_vector(h_sig)
					);

			for (size_t i = 0; i < NumInputs; i++) {
				// Witness pkh
				zk_pkh[i]->bits.fill_with_bits(
						this->pb,
						uint256_to_bool_vector(inputs[i].note.pkh)
						);
				// Witness the input information.
				auto merkle_path = inputs[i].witness.path();
				zk_input_notes[i]->generate_r1cs_witness(
						merkle_path,
						inputs[i].key,
						inputs[i].note
						);

				// Witness macs
				zk_mac_authentication[i]->generate_r1cs_witness();
			}

			for (size_t i = 0; i < NumOutputs; i++) {
				// Witness the output information.
				zk_output_notes[i]->generate_r1cs_witness(outputs[i]);
			}

			// [SANITY CHECK] Ensure that the intended root
			// was witnessed by the inputs, even if the read
			// gadget overwrote it. This allows the prover to
			// fail instead of the verifier, in the event that
			// the roots of the inputs do not match the
			// treestate provided to the proving API.
			for (size_t i = 0; i < NumInputs; i++) {
				zk_merkle_root[i]->bits.fill_with_bits(
						this->pb,
						uint256_to_bool_vector(rt[i])
						);
			}

			// Witness time lock
			for (size_t i = 0; i < NumInputs; i++) {
				ovd64[i].fill_with_bits(
						this->pb,
						uint64_to_bool_vector(ovd[i]?0:1)
						);
				bh64[i].fill_with_bits(
						this->pb,
						uint64_to_bool_vector(bh[i])
						);
				tlock64[i].fill_with_bits(
						this->pb,
						uint64_to_bool_vector(inputs[i].note.tlock)
						);
			}
			mbh64.fill_with_bits(
					this->pb,
					uint64_to_bool_vector(mbh)
					);

			// This happens last, because only by now are all the
			// verifier inputs resolved.
			unpacker->generate_r1cs_witness_from_bits();
		}

		static r1cs_primary_input<FieldT> witness_map(
				const boost::array<uint256, NumInputs>& rt,
				const uint256& h_sig,
				const boost::array<uint256, NumInputs>& macs,
				const boost::array<uint256, NumInputs>& nullifiers,
        const boost::array<uint256, NumInputs>& pkh, // to be handled
				const boost::array<uint256, NumOutputs>& commitments,
				uint64_t vpub_old,
				uint64_t vpub_new,
				uint64_t mbh, // to be handled
				const boost::array<uint64_t, ZC_NUM_JS_INPUTS>& bh, // to be handled
				const boost::array<bool, ZC_NUM_JS_INPUTS>& ovd // to be handled
				) {
			std::vector<bool> verify_inputs;

			insert_uint256(verify_inputs, h_sig);

			for (size_t i = 0; i < NumInputs; i++) {
				insert_uint256(verify_inputs, rt[i]);
				insert_uint256(verify_inputs, nullifiers[i]);
				insert_uint256(verify_inputs, macs[i]);
				// ZChannel
				insert_uint256(verify_inputs, pkh[i]);
				insert_uint64(verify_inputs, bh[i]);
				insert_uint64(verify_inputs, ovd[i]?0:1);
			}

			for (size_t i = 0; i < NumOutputs; i++) {
				insert_uint256(verify_inputs, commitments[i]);
			}

			insert_uint64(verify_inputs, vpub_old);
			insert_uint64(verify_inputs, vpub_new);
			// ZChannel
			insert_uint64(verify_inputs, mbh);

			assert(verify_inputs.size() == verifying_input_bit_size());
			auto verify_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(verify_inputs);
			assert(verify_field_elements.size() == verifying_field_element_size());
			return verify_field_elements;
		}

		static size_t verifying_input_bit_size() {
			size_t acc = 0;

			acc += 256; // h_sig
			for (size_t i = 0; i < NumInputs; i++) {
				acc += 256; // the merkle root (anchor)
				acc += 256; // nullifier
				acc += 256; // pkh
				acc += 256; // mac
				acc += 64; // block height
				acc += 64; // ovd flag
			}
			for (size_t i = 0; i < NumOutputs; i++) {
				acc += 256; // new commitment
			}
			acc += 64; // vpub_old
			acc += 64; // vpub_new

			acc += 64; // minimum block height

			return acc;
		}

		static size_t verifying_field_element_size() {
			return div_ceil(verifying_input_bit_size(), FieldT::capacity());
		}

		void alloc_uint256(
				pb_variable_array<FieldT>& packed_into,
				std::shared_ptr<digest_variable<FieldT>>& var
				) {
			var.reset(new digest_variable<FieldT>(this->pb, 256, ""));
			packed_into.insert(packed_into.end(), var->bits.begin(), var->bits.end());
		}

		void alloc_uint64(
				pb_variable_array<FieldT>& packed_into,
				pb_variable_array<FieldT>& integer
				) {
			integer.allocate(this->pb, 64, "");
			packed_into.insert(packed_into.end(), integer.begin(), integer.end());
		}
};
