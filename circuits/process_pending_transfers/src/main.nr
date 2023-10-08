/* Note: Exponential ElGamal only supports plaintexts constrained to 40 bits, 
because solving the Discrete Log is needed during decryption
It is the responsiblity of the smart contract developer to ensure 
that all plaintexts are in the u40 range before encryption
*/
use dep::std::ec::tecurve::affine::Curve as AffineCurve;
use dep::std::ec::tecurve::affine::Point as Gaffine;
use dep::std::collections::vec::Vec;
use dep::std;

global bjj_a = 168700;
global bjj_d = 168696;
global bjj_generator_x = 995203441582195749578291179787384436505546430278305826713579947235728471134;
global bjj_generator_y = 5472060717959818805561601436314318772137091100104008585924551046643952123905;
global bjj_basept_x = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
global bjj_basept_y = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

/* Code of the circuit used at each transfer of the token to prove the validity of transfer (sender 
has enough balance) and correctness of encrypted new balances of sender and receiver.
To be sure this is not vulnerable, we added a check in the smart contract to make sure that sender
is different from receiver (a nonce variable is not needed in our case because transfers are 
initiated by from=msg.sender in the contract, so replay attack is impossible)
*/
fn main(// All Public inputs, this can be executed by anyone
        balance_old_to_encrypted_1: pub Gaffine, 
        balance_old_to_encrypted_2: pub Gaffine,
        balance_new_to_encrypted_1: pub Gaffine, 
        balance_new_to_encrypted_2: pub Gaffine,
        encrypted_values: pub [Gaffine; 8],
    ) { 

    // check that new balance = the balance_old_me_clear - fee

    let bjj_affine: AffineCurve = AffineCurve::new(bjj_a, bjj_d, Gaffine::new(bjj_generator_x, bjj_generator_y));
    
    let mut encrypted_value_sum = (encrypted_values[0], encrypted_values[1]);

    for i in 1..3 {
        let mut s = i*2;
        if(encrypted_values[s].x as Field != 0){
            encrypted_value_sum = (bjj_affine.add(encrypted_value_sum.0, encrypted_values[s]),bjj_affine.add(encrypted_value_sum.1, encrypted_values[s+1]));
        }
    }

    // addition of the points on Baby Jubjub : this operation is additevely homomorphic for Exponential ElGamal
    let balance_new_to_encrypted_computed = 
        (bjj_affine.add(balance_old_to_encrypted_1, encrypted_value_sum.0),bjj_affine.add(balance_old_to_encrypted_2, encrypted_value_sum.1)); 
    // checks that the new encrypted balance of receiver is correct
    assert((balance_new_to_encrypted_computed.0.x==balance_new_to_encrypted_1.x) & 
            (balance_new_to_encrypted_computed.0.y==balance_new_to_encrypted_1.y) & 
            (balance_new_to_encrypted_computed.1.x==balance_new_to_encrypted_2.x) & 
            (balance_new_to_encrypted_computed.1.y==balance_new_to_encrypted_2.y)); 
}

// Because of a bug in Noir 10.3, this test will cause a stack overflow error, but you can check that it passes via `nargo prove` instead of `nargo test`: the values inside Prover.toml are strictly equivalent to this test
#[test]
fn test_main() {
   
    // public values
    // let public_key_me: Gaffine = bjj_priv_to_pub_key(private_key);
    // let public_key_to: Gaffine = bjj_priv_to_pub_key(2397698694665525209403000085013646741088197704326090841842743616643093564368); // bjj_priv_to_pub_key(private_key_to)
    // let balance_old_me_encrypted : (Gaffine,Gaffine) = bjj_exp_elgamal_encrypt(public_key_me, balance_old_me_clear, 1223911427385630814994881905088740515414339792865684838215099796087690786721);
    // let balance_old_to_encrypted : (Gaffine,Gaffine) = bjj_exp_elgamal_encrypt(public_key_to, 42, 1391605116707840153256607813912547565986654451413670922768018807428594876790);
    // let balance_new_me_encrypted : (Gaffine,Gaffine) = bjj_exp_elgamal_encrypt(public_key_me, 9900, randomness1);
    // let balance_new_to_encrypted : (Gaffine,Gaffine) = bjj_exp_elgamal_encrypt(public_key_to, 142, 1391605116707840153256607813912547565986654451413670922768018807428594876790+randomness2);

    // main( public_key_to, balance_old_me_encrypted.0, balance_old_me_encrypted.1, balance_old_to_encrypted.0,
    //  balance_old_to_encrypted.1, balance_new_me_encrypted.0, balance_new_me_encrypted.1, balance_new_to_encrypted.0,  balance_new_to_encrypted.1);
}

fn bjj_priv_to_pub_key(private_key: Field) -> Gaffine
{
 // Define Baby Jubjub (ERC-2494) parameters in affine representation
 let bjj_affine: AffineCurve = AffineCurve::new(bjj_a, bjj_d, Gaffine::new(bjj_generator_x, bjj_generator_y));
 let base_pt: Gaffine = Gaffine::new(bjj_basept_x, bjj_basept_y);
 bjj_affine.mul(private_key, base_pt)
}

fn bjj_exp_elgamal_encrypt(public_key: Gaffine, plaintext: u40, randomness: Field) -> (Gaffine,Gaffine) // same notations as in https://en.wikipedia.org/wiki/ElGamal_encryption 
{
 let bjj_affine: AffineCurve = AffineCurve::new(bjj_a, bjj_d, Gaffine::new(bjj_generator_x, bjj_generator_y));
 let base_pt: Gaffine = Gaffine::new(bjj_basept_x, bjj_basept_y);
 let C1: Gaffine = bjj_affine.mul(randomness, base_pt);
 let plain_embedded: Gaffine = bjj_affine.mul(plaintext as Field, base_pt);
 let shared_secret: Gaffine = bjj_affine.mul(randomness, public_key);
 let C2: Gaffine = bjj_affine.add(shared_secret, plain_embedded);
 (C1,C2)
}

fn bjj_exp_elgamal_decrypt(private_key : Field, ciphertext: (Gaffine,Gaffine)) -> Gaffine
{
 let bjj_affine: AffineCurve = AffineCurve::new(bjj_a, bjj_d, Gaffine::new(bjj_generator_x,bjj_generator_y));
 let shared_secret = bjj_affine.mul(private_key,ciphertext.0);
 let plain_embedded = bjj_affine.subtract(ciphertext.1,shared_secret);
 plain_embedded
}