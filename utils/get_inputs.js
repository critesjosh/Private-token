import * as babyjubjubUtils from './babyjubjub_utils.js';

async function main() {

    const priv_key = "0x0510bae26a9b59ebad67a4324c944b1910a778e8481d7f08ddba6bcd2b94b2c4"
    const pub_key = babyjubjubUtils.privateToPublicKey(priv_key);
    const initial_balance = 100;
    const amount = 10;

    console.log('private key', priv_key)
    console.log('pub_key x', pub_key.x.toString(16))
    console.log('pub_key y', pub_key.y.toString(16))

    const initial_balance_enc = babyjubjubUtils.exp_elgamal_encrypt(pub_key, initial_balance);

    console.log("[balance_old_encrypted_1]")
    console.log(`x = "0x${initial_balance_enc.C1.x.toString(16)}"`)
    console.log(`y = "0x${initial_balance_enc.C1.y.toString(16)}"\n`)
    console.log("[balance_old_encrypted_2]")
    console.log(`x = "0x${initial_balance_enc.C2.x.toString(16)}"`)
    console.log(`y = "0x${initial_balance_enc.C2.y.toString(16)}"\n`)
    console.log('randomness1 = ', `"0x${initial_balance_enc.randomness.toString(16)}"\n`)

    // const amount_enc = babyjubjubUtils.exp_elgamal_encrypt(pub_key, 10);

    // console.log("[balance_old_encrypted_1]")
    // console.log(`x = "0x${initial_balance_enc.C1.x.toString(16)}"`)
    // console.log(`y = "0x${initial_balance_enc.C1.y.toString(16)}"\n`)
    // console.log("[balance_old_encrypted_2]")
    // console.log(`x = "0x${initial_balance_enc.C2.x.toString(16)}"`)
    // console.log(`y = "0x${initial_balance_enc.C2.y.toString(16)}"\n`)
    // console.log('randomness1 = ', `"0x${initial_balance_enc.randomness.toString(16)}"\n`)

    const new_balance_enc = babyjubjubUtils.exp_elgamal_encrypt(pub_key, 90);

    console.log("[balance_new_encrypted_1]")
    console.log(`x = "0x${new_balance_enc.C1.x.toString(16)}"`)
    console.log(`y = "0x${new_balance_enc.C1.y.toString(16)}"\n`)
    console.log("[balance_new_encrypted_2]")
    console.log(`x = "0x${new_balance_enc.C2.x.toString(16)}"`)
    console.log(`y = "0x${new_balance_enc.C2.y.toString(16)}"\n`)
    console.log('randomness1 = ', `"0x${new_balance_enc.randomness.toString(16)}"`)
}

main();