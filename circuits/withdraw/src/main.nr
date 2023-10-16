/* Note: Exponential ElGamal only supports plaintexts constrained to 40 bits, 
because solving the Discrete Log is needed during decryption
It is the responsiblity of the smart contract developer to ensure 
that all plaintexts are in the u40 range before encryption
*/
use dep::std::ec::tecurve::affine::Curve as AffineCurve;
use dep::std::ec::tecurve::affine::Point as Gaffine;
use dep::std::collections::vec::Vec;
use dep::std;
use dep::noir_bigint::BigUint56;
use dep::bjj;

// Code of the circuit used once at construction of the token to prove the correctness of encryption of the minted total supply.
// In this particular case, we are using a zkSNARK only for its succintness property, not the zk property, because total supply is publicly known.
// The alternative would have been to reimplement Baby JubJub encryption in the EVM onchain which is very gas-expensive and complex.
fn main(private_key: Field, 
        randomness: Field, 
        /* Balance_old_me_clear is the clear (i.e decrypted) balance of sender 
        this is computed offchain by solving the DLP with babygiant algorithm, 
        after calling bjj_exp_elgamal_decrypt with his private key */
        balance_old_clear: Field,

        // Public Inputs
        nonce: pub Field,
        public_key: pub Gaffine, 
        value: pub Field, 
        relay_fee: pub Field,
        balance_old_encrypted_1: pub Gaffine, 
        balance_old_encrypted_2: pub Gaffine,
        balance_new_encrypted_1: pub Gaffine, 
        balance_new_encrypted_2: pub Gaffine)
    { 
    let bjj_affine: AffineCurve = AffineCurve::new(bjj_a, bjj_d, Gaffine::new(bjj_generator_x, bjj_generator_y));
    let base_pt: Gaffine = Gaffine::new(bjj_basept_x, bjj_basept_y);
    let embedded_balance_old_me_clear = bjj_affine.mul(balance_old_clear as Field, base_pt);
    let decoded_value = bjj::exp_elgamal_decrypt(private_key, (balance_old_encrypted_1,balance_old_encrypted_2));
    // check that unencrypted balance of withdrawer really corresponds to his encrypted balance
    assert((decoded_value.x == embedded_balance_old_me_clear.x) & (decoded_value.y == embedded_balance_old_me_clear.y)); 
    // we encrypt the minted value with the minter's public key
    let new_balance_encrypted_computed = bjj::exp_elgamal_encrypt(public_key, balance_old_clear - value - relay_fee, randomness);
    assert((new_balance_encrypted_computed.0.x == balance_new_encrypted_1.x) & 
            (new_balance_encrypted_computed.0.y == balance_new_encrypted_1.y) & 
            (new_balance_encrypted_computed.1.x == balance_new_encrypted_2.x) & 
            (new_balance_encrypted_computed.1.y == balance_new_encrypted_2.y)); 
}

#[test]
fn test_main() {
    // private values
    // let private_key: Field = 2291123624948246627368989940774052753470489062495018070576418670157516550852; // see debug notebook for an example on how to compute those
    // let randomness: Field = 168986485046885582825082387270879151100288537211746581237924789162159767775; // see debug notebook for an example on how to compute those
    // let balance_old_me_clear : u40 = 100;

    // // public values
    // let public_key: Gaffine = bjj_priv_to_pub_key(private_key);
    // let value: Field = 1000000000000; // the message being encrypted, should be a u40

    // main(private_key, randomness, balance_old_me_clear, public_key,value,balance_old_encrypted_1,balance_old_encrypted_2, balance_new_encrypted_computed.0, balance_new_encrypted_computed.1);  // checks that public_key is derived from private_key and returns encrypted value and most importantly that the encrpyted value, i.e (C1,C2), is correct
}