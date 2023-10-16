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
// mod biguint;

global bjj_a = 168700;
global bjj_d = 168696;
global bjj_generator_x = 995203441582195749578291179787384436505546430278305826713579947235728471134;
global bjj_generator_y = 5472060717959818805561601436314318772137091100104008585924551046643952123905;
global bjj_basept_x    = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
global bjj_basept_y    = 16950150798460657717958625567821834550301663161624707787222815936182638968203;
global pm1d2           = 10944121435919637611123202872628637544274182200208017171849102093287904247808;
// from here: https://github.com/iden3/circomlibjs/blob/4f094c5be05c1f0210924a3ab204d8fd8da69f49/src/babyjub.js#L11C37-L11C114
global p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
/* Code of the circuit used at each transfer of the token to prove the validity of transfer (sender 
has enough balance) and correctness of encrypted new balances of sender.
*/
fn main(private_key: Field, 
        randomness: Field, 
        value: u40, 
        /* Balance_old_me_clear is the clear (i.e decrypted) balance of sender 
        this is computed offchain by solving the DLP with babygiant algorithm, 
        after calling bjj_exp_elgamal_decrypt with his private key */
        balance_old_me_clear: u40,

        // Public inputs

        sender_pub_key: pub [u8; 32], 
        recipient_pub_key: pub [u8; 32], 
        // account_address: pub Field, // can be removed with packed public keys
        process_fee: pub u40,
        relay_fee: pub u40,
        nonce: pub Field,
        balance_old_me_encrypted_1: pub Gaffine, 
        balance_old_me_encrypted_2: pub Gaffine,
        encrypted_amount_1: pub Gaffine,
        encrypted_amount_2: pub Gaffine,
        balance_new_me_encrypted_1: pub Gaffine, 
        balance_new_me_encrypted_2: pub Gaffine, 
    ) 
    { 
    let computed_public_key = bjj_priv_to_pub_key(private_key);
    // pack

    // check that the sender really owns the private key corresponding to his public key

    // TODO: convert computed_public_key to packed as [u8;32] and compare with sender_pub_key 
    // assert((sender_pub_key == computed_public_key) & (sender_pub_key == computed_public_key));
    // the sender must have sufficient balance
    assert(value<=balance_old_me_clear); 
    /* this is to deter potential front-running issue: ref https://crypto.stanford.edu/~buenz/papers/zether.pdf §3.1. 
    Here we adopt a simpler approach than the multistep approach proposed in the Zether paper, for a better UX: 
    an attacker who tries to DOS the sender should at least pay 1 token to either original sender or receiver. 
    The "1" threshold could be changed to ensure correct economic incentives, typically this should be at least 
    a multiple of the average gas price of a transfer transaction. another more straightforward solution to 
    front-running would be simply to do the homomorphic addition in the smart contract rather than the circuit, 
    but this is too expensive today on Ethereum, according to the Zeestar paper §III : 
    https://files.sri.inf.ethz.ch/website/papers/sp22-zeestar.pdf
    */
    assert(value>=1); 

    // can be removed with packed public keys
    // assert(std::hash::poseidon::bn254::hash_2([recipient_pub_key.x, recipient_pub_key.y]) == account_address);

    let bjj_affine: AffineCurve = AffineCurve::new(bjj_a, bjj_d, Gaffine::new(bjj_generator_x, bjj_generator_y));
    let base_pt: Gaffine = Gaffine::new(bjj_basept_x, bjj_basept_y);
    let embedded_balance_old_me_clear = bjj_affine.mul(balance_old_me_clear as Field, base_pt);
    let decoded_value = bjj_exp_elgamal_decrypt(private_key, (balance_old_me_encrypted_1,balance_old_me_encrypted_2));
    // check that unencrypted balance of sender really corresponds to his encrypted balance
    assert((decoded_value.x == embedded_balance_old_me_clear.x) & (decoded_value.y == embedded_balance_old_me_clear.y)); 

    // let balance_new_me_encrypted_computed = bjj_exp_elgamal_encrypt(sender_pub_key, balance_old_me_clear - value - process_fee - relay_fee, randomness);
    // // checks that the new encrypted balance of sender is correct
    // assert((balance_new_me_encrypted_computed.0.x==balance_new_me_encrypted_1.x) & 
    //         (balance_new_me_encrypted_computed.0.y==balance_new_me_encrypted_1.y) & 
    //         (balance_new_me_encrypted_computed.1.x==balance_new_me_encrypted_2.x) & 
    //         (balance_new_me_encrypted_computed.1.y==balance_new_me_encrypted_2.y)); 
    // // check that the amount being transferred is correctly encrypted
    // let encrypted_amount_computed = bjj_exp_elgamal_encrypt(recipient_pub_key, value, randomness);
    // assert((encrypted_amount_computed.0.x == encrypted_amount_1.x) &
    //         (encrypted_amount_computed.0.y == encrypted_amount_1.y) &
    //         (encrypted_amount_computed.1.x == encrypted_amount_2.x) &
    //         (encrypted_amount_computed.1.y == encrypted_amount_2.y));
    }

// Because of a bug in Noir 10.3, this test will cause a stack overflow error, but you can check that it passes via `nargo prove` instead of `nargo test`: the values inside Prover.toml are strictly equivalent to this test
#[test]
fn test_main() {
    // private values
    let private_key: Field = 2291123624948246627368989940774052753470489062495018070576418670157516550852; // see debug notebook for an example on how to compute those
    let randomness: Field = 168986485046885582825082387270879151100288537211746581237924789162159767775; // see debug notebook for an example on how to compute those
    let value: u40 = 100;
    let balance_old_me_clear = 10000;

    // public values
    let sender_pub_key: Gaffine = bjj_priv_to_pub_key(private_key);
    let recipient_pub_key: Gaffine = bjj_priv_to_pub_key(2397698694665525209403000085013646741088197704326090841842743616643093564368); // bjj_priv_to_pub_key(private_key_to)
    let process_fee: u40 = 5;
    let relay_fee: u40 = 5;
    // let nonce = std::hash::keccak256(abi_encode_encrypted_amount(balance_new_me_encrypted_1, balance_new_me_encrypted_2), 128);
    // let balance_old_me_encrypted : (Gaffine,Gaffine) = bjj_exp_elgamal_encrypt(public_key_me, balance_old_me_clear, 1223911427385630814994881905088740515414339792865684838215099796087690786721);
    // let balance_old_to_encrypted : (Gaffine,Gaffine) = bjj_exp_elgamal_encrypt(public_key_to, 42, 1391605116707840153256607813912547565986654451413670922768018807428594876790);
    // let balance_new_me_encrypted : (Gaffine,Gaffine) = bjj_exp_elgamal_encrypt(public_key_me, 9900, randomness1);
    // let balance_new_to_encrypted : (Gaffine,Gaffine) = bjj_exp_elgamal_encrypt(public_key_to, 142, 1391605116707840153256607813912547565986654451413670922768018807428594876790+randomness2);

  //  main(private_key, randomness1, randomness2, value, balance_old_me_clear, public_key_me, public_key_to, balance_old_me_encrypted.0, balance_old_me_encrypted.1, balance_old_to_encrypted.0,
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


// translated from here: https://github.com/iden3/circomlibjs/blob/4f094c5be05c1f0210924a3ab204d8fd8da69f49/src/babyjub.js#L108
fn unpack_point(mut public_key: [u8; 32]) -> Gaffine 
{
  let mut point: Gaffine = Gaffine::new(0,0);
  let mut sign = false;
  if((public_key[31] & 0x80) != 0) {
    sign = true;
    public_key[31] &= 0x7f;
  }
  point.y = from_rpr_le(public_key);
  // assert point.y < p
  assert(BigUint56::from_bytes(point.y.to_le_bytes(32))
          .gt(BigUint56::from_bytes(p.to_le_bytes(32))));  
 
  let mut y2 = point.y * point.y;

  let x2 = (1-y2) / (bjj_a - (bjj_d * y2));
  let x2h = x2.pow_32(10944121435919637611123202872628637544274182200208017171849102093287904247808);
  // let x2h = 10944121435919637611123202872628637544274182200208017171849102093287904247808.pow_32(x2);
  std::println(x2h);
  // assert(x2h == 1);
  point.x = sqrt(x2h);

  if(sign) {
    point.x = p - point.x;
  } 
  point
}

// from here: https://github.com/iden3/circomlibjs/blob/4f094c5be05c1f0210924a3ab204d8fd8da69f49/src/babyjub.js#L97
fn pack_point(public_key: Gaffine) -> [u8;32] {
  let mut array: [u8;32] = [0;32];
  let mut y = public_key.y.to_le_bytes(32);
  for i in 0..32 {
    array[i] = y[i];
  }

  let pm1d2 = (p - 1) / 2;
  if(BigUint56::from_bytes(public_key.x.to_le_bytes(32))
      .gt(BigUint56::from_bytes(pm1d2.to_le_bytes(32))))
  {
    array[31] = array[31] | 0x80;
  }

  array
}

// translated from here: https://github.com/iden3/ffjavascript/blob/d1cd4ae32170aedd000865f0828b78a15df6f06f/src/scalar.js#L215
// and inspired by this: https://gist.github.com/signorecello/dad41f8b90ae48c7355bfd1f34f8885b
fn from_rpr_le(public_key: [u8;32]) -> Field {

  let mut result : Field = 0;
  let mut v : Field = 1;
  for i in 0..32 {
      result += public_key[i] as Field * v;
      v *= 256;
  }

  result
}

#[test]
fn test_pack_point(){
  let private_key = 0x0510bae26a9b59ebad67a4324c944b1910a778e8481d7f08ddba6bcd2b94b2c4;
  let pub_key: Gaffine = bjj_priv_to_pub_key(private_key);
  let packed_pub_key = [0xdc, 0x9f, 0x9f, 0xdb, 0x74, 0x6d, 0x0f, 0x07, 0xb0, 0x04, 0xcc, 0x43, 0x16, 0xe3, 0x49, 0x5a, 0x58, 0x57, 0x0b, 0x90, 0x66, 0x14, 0x99, 0xf8, 0xa6, 0xa6, 0x69, 0x6f, 0xf4, 0x15, 0x6b, 0xaa];
  
  let computed_packed_key = pack_point(pub_key);

  assert(computed_packed_key == packed_pub_key);
}

#[test]
fn test_unpack_point() {
  let private_key: Field = 0x0510bae26a9b59ebad67a4324c944b1910a778e8481d7f08ddba6bcd2b94b2c4; // see debug notebook for an example on how to compute those
  let public_key: Gaffine = bjj_priv_to_pub_key(private_key);

  let packed_pub_key = [0xdc, 0x9f, 0x9f, 0xdb, 0x74, 0x6d, 0x0f, 0x07, 0xb0, 0x04, 0xcc, 0x43, 0x16, 0xe3, 0x49, 0x5a, 0x58, 0x57, 0x0b, 0x90, 0x66, 0x14, 0x99, 0xf8, 0xa6, 0xa6, 0x69, 0x6f, 0xf4, 0x15, 0x6b, 0xaa];
  let point = unpack_point(packed_pub_key);
  
  std::println(point);
}

fn abi_encode_encrypted_amount(first: Gaffine, second: Gaffine) -> [u8; 128]{
    let mut prehashed_nonce: [u8;128] = [0;128];
    for i in 0..128 {
      let first_quarter = first.x.to_le_bytes(32);
      let second_quarter = first.y.to_le_bytes(32);
      let third_quarter = second.x.to_le_bytes(32);
      let fourth_quarter = second.y.to_le_bytes(32);
        if(i as u8<32){
          prehashed_nonce[i] = first_quarter[i];
        } else if i as u8 < 64 {
          prehashed_nonce[i] = second_quarter[i];
        } else if i as u8 < 96 {
          prehashed_nonce[i] = third_quarter[i];
        } else {
          prehashed_nonce[i] = fourth_quarter[i];
        }
      }
      prehashed_nonce
}

// fn sqrt(x: Field) -> Field {
//     let mut z = pow(x, C3);
//     let mut t = z*z*x;
//     z *= x;
//     let mut b = t;
//     let mut c = C5;
 
//     for i in 0..(C1-1) {
        
//         for _j in 1..(C1-i-1) {
            
//             b *= b;
            
//         }
 
//         z *= if b == 1 { 1 } else { c };
 
//         c *= c;
 
//         t *= if b == 1 { 1 } else { c };
 
//         b = t;
//     }
    
//     z
// }

global MAX_ITER = 10;
unconstrained fn sqrt(x: Field) -> Field {
    let mut z = (x+1) / 2;
    let mut y = x;
    let mut finished = false;
    for _i in 0..MAX_ITER {
        if BigUint56::from_bytes(y.to_le_bytes(32)).gt(BigUint56::from_bytes(z.to_le_bytes(32))) {
            y = z;
            z = ((x/z) + z) / 2;
        } else {
            finished = true;
        }
    }
    assert(finished);
    y
}