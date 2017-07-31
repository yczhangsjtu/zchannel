#include <iostream>
#include <boost/array.hpp>
#include <boost/foreach.hpp>
#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "gadgetlib1/protoboard.hpp"
#include "gadgetlib1/gadget.hpp"
#include "gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "crypto/sha256.h"
#include "crypto/common.h"
#include "uint256.h"
#include "util.h"

using namespace libsnark;

#include "circuit/utils.tcc"
#include "circuit/commitment.tcc"

using namespace std;

template<typename FieldT>
bool test_note_commitment_gadget()
{
	protoboard<FieldT> pb;
	pb_variable<FieldT> ZERO;
	pb_variable_array<FieldT> a_pk; // 256 bit
	pb_variable_array<FieldT> v; // 64 bit
	pb_variable_array<FieldT> rho; // 256 bit
	pb_variable_array<FieldT> r; // 256 bit
	pb_variable_array<FieldT> pkcm; // 256 bit
	pb_variable_array<FieldT> tlock; // 64 bit
	std::shared_ptr<digest_variable<FieldT>> result;
	
	result.reset(new digest_variable<FieldT>(pb,256,"result"));

	ZERO.allocate(pb,"ZERO");
	a_pk.allocate(pb,256,"apk");
	v.allocate(pb,64,"v");
	rho.allocate(pb,256,"rho");
	r.allocate(pb,256,"r");
	pkcm.allocate(pb,256,"pkcm");
	tlock.allocate(pb,64,"tlock");

	note_commitment_gadget<FieldT> ncmgadget(pb,ZERO,a_pk,v,rho,r,pkcm,tlock,result,"note_cm");

	ncmgadget.generate_r1cs_constraints();
	generate_r1cs_equals_const_constraint<FieldT>(pb,ZERO,FieldT::zero(),"ZERO=0");

	uint256 apk_data = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
	uint256 rho_data = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
	uint256 r_data   = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
	uint256 pkc_data = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
	uint256 result_data;
	uint64_t v_data = 0;
	uint64_t t_data = 0;

	pb.val(ZERO) = FieldT::zero();
	a_pk.fill_with_bits  (pb,uint256_to_bool_vector(apk_data));
	rho.fill_with_bits   (pb,uint256_to_bool_vector(rho_data));
	r.fill_with_bits     (pb,uint256_to_bool_vector(r_data));
	pkcm.fill_with_bits  (pb,uint256_to_bool_vector(pkc_data));
	v.fill_with_bits     (pb,uint64_to_bool_vector(v_data));
	tlock.fill_with_bits (pb,uint64_to_bool_vector(t_data));

	CSHA256 sha256;
	auto value_vec = convertIntToVectorLE(v_data);
	unsigned char leading_byte = 0xb0;
	sha256.Write(&leading_byte,1);
	sha256.Write(apk_data.begin(),32);
	sha256.Write(&value_vec[0],value_vec.size());
	sha256.Write(rho_data.begin(),32);
	sha256.Write(r_data.begin(),32);
	sha256.Write(pkc_data.begin(),32);
	sha256.Write((unsigned char*)&t_data,8);
	sha256.Finalize(result_data.begin());

	ncmgadget.generate_r1cs_witness();
	result->bits.fill_with_bits(pb,uint256_to_bool_vector(result_data));

	/*
	std::vector<FieldT> primary_input = pb.primary_input();
	std::vector<FieldT> aux_input = pb.auxiliary_input();
	pb.constraint_system.swap_AB_if_beneficial();
	r1cs_ppzksnark_prover<ppzksnark_ppT>(*pk,primary_input,aux_input,pb.constraint_system);
	*/

	return pb.is_satisfied();
}

template<typename FieldT>
bool test_input_note_commitment_gadget()
{
	protoboard<FieldT> pb;
	pb_variable<FieldT> ZERO;
	pb_variable_array<FieldT> a_pk; // 256 bit
	pb_variable_array<FieldT> a_sk; // 252 bit
	pb_variable_array<FieldT> v; // 64 bit
	pb_variable_array<FieldT> rho; // 256 bit
	pb_variable_array<FieldT> r; // 256 bit
	pb_variable_array<FieldT> pkh; // 256 bit
	pb_variable_array<FieldT> tlock; // 64 bit
	std::shared_ptr<digest_variable<FieldT>> result;
	
	result.reset(new digest_variable<FieldT>(pb,256,"result"));

	ZERO.allocate(pb,"ZERO");
	a_pk.allocate(pb,256,"apk");
	a_sk.allocate(pb,252,"ask");
	v.allocate(pb,64,"v");
	rho.allocate(pb,256,"rho");
	r.allocate(pb,256,"r");
	pkh.allocate(pb,256,"pkh");
	tlock.allocate(pb,64,"tlock");

	input_note_commitment_gadget<FieldT> incmgadget(pb,ZERO,a_pk,a_sk,v,rho,r,pkh,tlock,result,"note_cm");

	incmgadget.generate_r1cs_constraints();
	generate_r1cs_equals_const_constraint<FieldT>(pb,ZERO,FieldT::zero(),"ZERO=0");

	uint256 apk_data = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
	uint256 ask_data = uint256S("00000000000000000000000000000000000000000000000000000000000000F0");
	uint256 rho_data = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
	uint256 r_data   = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
	uint256 pkh_data = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
	uint256 result_data;
	uint256 pkcm_data;

	uint64_t v_data = 0;
	uint64_t t_data = 0;

	pb.val(ZERO) = FieldT::zero();
	a_pk.fill_with_bits (pb,uint256_to_bool_vector(apk_data));
	a_sk.fill_with_bits (pb,trailing252(uint256_to_bool_vector(ask_data)));
	rho.fill_with_bits  (pb,uint256_to_bool_vector(rho_data));
	r.fill_with_bits    (pb,uint256_to_bool_vector(r_data));
	pkh.fill_with_bits  (pb,uint256_to_bool_vector(pkh_data));
	v.fill_with_bits    (pb,uint64_to_bool_vector(v_data));
	tlock.fill_with_bits(pb,uint64_to_bool_vector(t_data));

	CSHA256 sha256;
	sha256.Write(ask_data.begin(),32);
	sha256.Write(pkh_data.begin(),32);
	sha256.Finalize(pkcm_data.begin());

	sha256.Reset();
	auto value_vec = convertIntToVectorLE(v_data);
	unsigned char leading_byte = 0xb0;
	sha256.Write(&leading_byte,1);
	sha256.Write(apk_data.begin(),32);
	sha256.Write(&value_vec[0],value_vec.size());
	sha256.Write(rho_data.begin(),32);
	sha256.Write(r_data.begin(),32);
	sha256.Write(pkcm_data.begin(),32);
	sha256.Write((unsigned char*)&t_data,8);
	sha256.Finalize(result_data.begin());

	incmgadget.generate_r1cs_witness();
	result->bits.fill_with_bits(pb,uint256_to_bool_vector(result_data));

	/*
	std::vector<FieldT> primary_input = pb.primary_input();
	std::vector<FieldT> aux_input = pb.auxiliary_input();
	pb.constraint_system.swap_AB_if_beneficial();
	r1cs_ppzksnark_prover<ppzksnark_ppT>(*pk,primary_input,aux_input,pb.constraint_system);
	*/

	return pb.is_satisfied();
}

int main() {
	typedef default_r1cs_ppzksnark_pp ppzksnark_ppT;
	typedef Fr<ppzksnark_ppT> FieldT;
	ppzksnark_ppT::init_public_params();
	if (init_and_check_sodium() == -1) {
		return 1;
	}
	if(test_note_commitment_gadget<FieldT>())
		cout << "note_commitment is okay!" << endl;
	else
		cout << "note_commitment test fails!" << endl;
	if(test_input_note_commitment_gadget<FieldT>())
		cout << "input_note_commitment is okay!" << endl;
	else
		cout << "input_note_commitment test fails!" << endl;
	return 0;
}
