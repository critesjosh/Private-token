# Private-token
Token with private balances using zkSNARKs and Homomorphic Encryption, inspired by [Zeestar](https://files.sri.inf.ethz.ch/website/papers/sp22-zeestar.pdf) and [Zether](https://crypto.stanford.edu/~buenz/papers/zether.pdf), implemented in [Noir](https://noir-lang.org/) (and Rust).

You can read the slides presenting the final project [here](https://docs.google.com/presentation/d/1SDTOthvK1xCXcoKlILIKCobktrDf_ibPUbHtykAQfpc/edit?usp=sharing).

# Quick description

This project is an implementation of a token on Ethereum with private balances, i.e all the balances are publicly stored on the Ethereum blockchain in an encrypted format, but only the owner of an Ethereum account is able to decrypt their own balance. This is possible thanks to the improved expressiveness allowed by homomorphic encryption on top of zkSNARKs, allowing a party **A** to compute over encrypted data owned by *another* party **B** i.e **A** can add encrpyted balances owned by **B** without needing any knowledge of those balances.

The current model is the following : 

this is optional now. First a Public Key Infrastructure (PKI) contract is deployed, this contract will contain the mapping between Ethereum addresses and Public Keys (points on the Baby Jubjub curve).

After the deployment of the new Private Token, transfers between users can occur. 

The Baby Jubjub private key, which corresponds to the public key, should be safeguarded diligently by each registered user. If lost, the user will no longer have access to their funds. anyone else with the private key can spend funds.

# Requirements
* `nargo` version 0.10.5 **Important**
* `node` version 18 or later
* `cargo` v1.73.0-nightly
* `hardhat` v2.17.2
* `just 1.14.0` (install it via `cargo install just`)

# To run the tests : 

Clone the repo, install the requirements, and then just run : 
```
just test
```

# To deploy the front-end locally : 

Clone the repo, install the requirements, and then create 2 `.env` files in the `hardhat/` and `frontend` directories. Fill them with the same keys as in the corresponding `.env.example`files placed in the corresponding directories. `CHAINNAME`should be set to `sepolia`in `hardhat/.env`and a valid Sepolia RPC URL given for `SEPOLIA_RPC_URL`. Then run the following commands in this order : 
```
just wp
```
```
just ds
```
```
just release
```

# Warning
Do not use in production, this was not audited and done as a final project for the [zkCamp Noir bootcamp](https://www.zkcamp.xyz/aztec).