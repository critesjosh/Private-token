// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// import "./PublicKeyInfrastructure.sol";
import {MintUltraVerifier} from "./mint_plonk_vk.sol";
import {MintToNewUltraVerifier} from "./mint_to_new_plonk_vk.sol";
import {TransferUltraVerifier} from "./transfer_plonk_vk.sol";
import {TransferToNewUltraVerifier} from "./transfer_to_new_plonk_vk.sol";
import {IERC20} from "./IERC20.sol";

/**
 * @dev Implementation of PrivateToken.
 * total supply is set at construction by the deployer and cannot exceed type(uint40).max = 1099511627775 because during Exponential ElGamal decryption we must solve the DLP quickly
 * Balances are encrypted to each owner's public key, according to the registered keys inside the PublicKeyInfrastructure.
 * Because we use Exponential ElGamal encryption, each EncryptedAmount is a pair of points on Baby Jubjub (C1,C2) = ((C1x,C1y),(C2x,C2y)).
 */
contract PrivateToken {
    struct EncryptedAmount {
        // #TODO : We could pack those in 2 uints instead of 4 to save storage costs (for e.g using circomlibjs library to pack points on BabyJubjub)
        uint256 C1x;
        uint256 C1y;
        uint256 C2x;
        uint256 C2y;
    }

    // breaking up deposits/transfer into two steps allow all of them to succeed.
    // without this, te people trying to send the same person money in the same block would fail
    // because they would both be trying to update the same ecrypted state
    // debiting the senders account in the first tx and doing the addtion in another allows
    // the send to always succeed. at worst the claim of the token would fail if multiple people
    // try to update simultaneously, but at the tx doesn't fail
    struct PendingTransaction {
        EncryptedAmount amount;
        bytes32 pubEncryptionKeyHash;
        // add a fee to incentivize someone to process the pending tx
        // otherwise leave as 0 and the recipient can process the tx themselves at cost
        uint256 fee;
    }

    struct PublicKey {
        // #TODO : We could pack those in a single uint256 to save storage costs (for e.g using circomlibjs library to pack points on BabyJubjub)
        uint256 X;
        uint256 Y;
    } // The Public Key should be a point on Baby JubJub elliptic curve : checks must be done offchain before registering to ensure that X<p and Y<p and (X,Y) is on the curve
    // p = 21888242871839275222246405745257275088548364400416034343698204186575808495617 < 2**254

    // optional PKI contract to register public keys
    PublicKeyInfrastructure public immutable PKI;

    MintUltraVerifier public immutable MintVerifier;
    TransferUltraVerifier public immutable TransferVerifier;
    TransferToNewUltraVerifier public immutable TransferToNewVerifier;
    uint40 public immutable totalSupply;

    IERC20 token;
    uint8 public immutable decimals = 2;

    // hash of public key => encrypted balance
    mapping(bytes32 => EncryptedAmount) public balances;

    mapping(bytes32 => pendingTransactions[]) public pendingTransactions;

    // This prevents replay attacks in the transfer fn
    mapping(bytes32 => uint256) public nonce;

    /*
        A PendingTransaction is added to this array when transfer is called.
        The transfer fn debits the senders balance by the amount sent.
        The sender encrypts the amount with the receivers public key

        The processPendingPendingTransactions fn takes a batch of PendingTransactions, and 
        does computes the updates for the homonorphic addition of the encrypted 
        amounts to the receivers and updates the recievers encrypted balances.

    */
    PendingTransaction[] public pendingTransactions;

    event PrivateTransfer(bytes32 indexed to, address indexed from);

    constructor(
        address MintVerifierAddress,
        address MintToNewVerifierAddress,
        address TransferVerifierAddress,
        address TransferToNewVerifierAddress,
        address _token
    ) {
        MintVerifier = MintUltraVerifier(MintVerifierAddress);
        MintToNewVerifier = MintToNewUltraVerifier(MintToNewVerifierAddress);
        TransferVerifier = TransferUltraVerifier(TransferVerifierAddress);
        TransferToNewVerifier = TransferToNewUltraVerifier(TransferToNewVerifierAddress);
        token = IERC20(_token);
    }

    // TODO: add transferWithRelay and withdrawWithRelay functions and write circuits
    // the idea is to be able to incentivize other people to submit txs for your from their
    // ETH accounts, so you dont doxx yourself by sending txs from your ETH account

    function deposit(
        address _from,
        uint256 _amount,
        PublicKey _to_key,
        bytes32 _to_address,
        bytes proof_mint,
        EncryptedAmount _newBalance,
        uint256 fee
    ) public {
        // convert to decimals places. any decimals following 2 are lost
        // max value is u40 - 1, so 1099511627775. with 2 decimals
        // that gives us a max supply of ~11 billion erc20 tokens
        uint40 amount = _amount / 10 ** (token.decimals() - decimals);
        require(totalSupply + amount < type(uint40).max, "Amount is too big");
        token.transferFrom(_from, this.address, uint256(_amount));
        // keep the fee - users can add a fee to incentivize processPendingTransfers
        amount = amount - fee;
        if (balances[_to_address] == 0) {
            mintToNew(_to_address, _amount, proof_mint, _to_key, _newBalance);
        } else {
            mint(_to_address, _amount, proof_mint, _to_key, _newBalance);
        }
    }

    function mintToNew(
        bytes32 _to, // poseidon hash of pub_key. pass as input to save gas
        uint40 amount,
        bytes memory proof_mint,
        PublicKey memory pub_key,
        EncryptedAmount memory newEncryptedAmount
    ) internal {
        // #TODO : implement this function
        bytes32[] memory publicInputs = new bytes32[](7);
        publicInputs[0] = bytes32(pub_key.X);
        publicInputs[1] = bytes32(pub_key.Y);
        publicInputs[2] = bytes32(uint256(amount));
        publicInputs[3] = bytes32(newEncryptedAmount.C1x);
        publicInputs[4] = bytes32(newEncryptedAmount.C1y);
        publicInputs[5] = bytes32(newEncryptedAmount.C2x);
        publicInputs[6] = bytes32(newEncryptedAmount.C2y);
        require(MintToNewVerifier.verify(proof_mint, publicInputs), "Mint proof is invalid"); // checks that the initial balance of the deployer is a correct encryption of the initial supply (and the deployer owns the private key corresponding to his registered public key)
        // calculate the new total encrypted supply offchain, replace existing value (not an increment)
        balances[_to] = newEncryptedAmount;
        totalSupply += amount;
    }

    function _mint(
        bytes32 _to, // poseidon hash of pub_key. pass as input to save gas
        uint40 amount,
        bytes memory proof_mint,
        PublicKey memory pub_key,
        EncryptedAmount memory newEncryptedAmount
    ) internal {
        EncryptedAmount memory oldEncryptedAmount = balances[_to];
        bytes32[] memory publicInputs = new bytes32[](7);
        publicInputs[0] = bytes32(pub_key.X);
        publicInputs[1] = bytes32(pub_key.Y);
        publicInputs[2] = bytes32(uint256(amount));
        publicInputs[3] = bytes32(oldEncryptedAmount.C1x);
        publicInputs[4] = bytes32(oldEncryptedAmount.C1y);
        publicInputs[5] = bytes32(oldEncryptedAmount.C2x);
        publicInputs[6] = bytes32(oldEncryptedAmount.C2y);
        publicInputs[7] = bytes32(newEncryptedAmount.C1x);
        publicInputs[8] = bytes32(newEncryptedAmount.C1y);
        publicInputs[9] = bytes32(newEncryptedAmount.C2x);
        publicInputs[10] = bytes32(newEncryptedAmount.C2y);
        require(MintVerifier.verify(proof_mint, publicInputs), "Mint proof is invalid"); // checks that the initial balance of the deployer is a correct encryption of the initial supply (and the deployer owns the private key corresponding to his registered public key)
        // calculate the new total encrypted supply offchain, replace existing value (not an increment)
        balances[minter] = newEncryptedAmount;
        totalSupply += amount;
    }

    function withdraw(
        bytes32 _from,
        address _to,
        u40 _amount,
        bytes memory _withdraw_proof,
        PublicKey memory _pub_key,
        EncryptedAmount _newEncryptedAmount
    ) public {
        EncryptedAmount memory oldEncryptedAmount = balances[_from];
        bytes32[] memory publicInputs = new bytes32[](7);
        publicInputs[0] = bytes32(pub_key.X);
        publicInputs[1] = bytes32(pub_key.Y);
        publicInputs[2] = bytes32(uint256(_amount));
        publicInputs[3] = bytes32(oldEncryptedAmount.C1x);
        publicInputs[4] = bytes32(oldEncryptedAmount.C1y);
        publicInputs[5] = bytes32(oldEncryptedAmount.C2x);
        publicInputs[6] = bytes32(oldEncryptedAmount.C2y);
        publicInputs[7] = bytes32(_newEncryptedAmount.C1x);
        publicInputs[8] = bytes32(_newEncryptedAmount.C1y);
        publicInputs[9] = bytes32(_newEncryptedAmount.C2x);
        publicInputs[10] = bytes32(_newEncryptedAmount.C2y);
        require(MintVerifier.verify(_withdraw_proof, publicInputs), "Withdraw proof is invalid");
        // calculate the new total encrypted supply offchain, replace existing value (not an increment)
        balances[_from] = newEncryptedAmount;
        totalSupply -= _amount;
        token.transferFrom(this.address, _to, uint256(_amount * 10 ** (token.decimals() - decimals)));
    }

    function transfer(
        bytes32 _to,
        bytes32 _from,
        // TODO: get these from the contract
        // EncryptedAmount calldata EncryptedAmountOldMe,
        // EncryptedAmount calldata EncryptedAmountOldTo,
        EncryptedAmount calldata EncryptedAmountNewMe,
        // EncryptedAmount calldata EncryptedAmountNewTo,
        bytes memory proof_transfer,
        EnrcyptedAmount calldata _amountToSend,
        uint256 _fee
    ) public {
        EncryptedAmount memory EncryptedAmountOldMeNow = balances[_from];

        pendingTransactions[_to].push({amount: _amountToSend, pubEncryptionKeyHash: _to, fee: _fee});
        pendingendingTransactionPot += _fee;

        require(
            EncryptedAmountOldToNow.C1x == EncryptedAmountOldTo.C1x
                && EncryptedAmountOldToNow.C1y == EncryptedAmountOldTo.C1y
                && EncryptedAmountOldToNow.C2x == EncryptedAmountOldTo.C2x
                && EncryptedAmountOldToNow.C2y == EncryptedAmountOldTo.C2y
                && EncryptedAmountOldMeNow.C1x == EncryptedAmountOldMe.C1x
                && EncryptedAmountOldMeNow.C1y == EncryptedAmountOldMe.C1y
                && EncryptedAmountOldMeNow.C2x == EncryptedAmountOldMe.C2x
                && EncryptedAmountOldMeNow.C2y == EncryptedAmountOldMe.C2y
        ); // this require is at the top of the transfer function, in order to limit gas spent in case of accidental front-running - front-running attack issue is already deterred thanks to the assert(value>=1) constraint inside the circuits (see comments in transfer/src/main.nr)
        // require(msg.sender != to, "Cannot transfer to self");
        // PublicKey memory registeredKeyMe = PKI.getRegistredKey(msg.sender);
        // PublicKey memory registeredKeyTo = PKI.getRegistredKey(to);
        // require(registeredKeyMe.X + registeredKeyMe.Y != 0, "Sender has not registered a Public Key yet");
        // require(registeredKeyTo.X + registeredKeyTo.Y != 0, "Receiver has not registered a Public Key yet");
        // require(
        //     EncryptedAmountOldMe.C1x + EncryptedAmountOldMe.C1y + EncryptedAmountOldMe.C1y
        //         + EncryptedAmountOldMe.C2y != 0,
        //     "Sender has not received tokens yet"
        // ); // this should never overflow because 4*p<type(uint256).max

        bool receiverAlreadyReceived = (
            EncryptedAmountOldTo.C1x + EncryptedAmountOldTo.C1y + EncryptedAmountOldTo.C1y + EncryptedAmountOldTo.C2y
                != 0
        ); // this should never overflow because 4*p<type(uint256).max

        if (receiverAlreadyReceived) {
            // TODO: add nonce

            bytes32[] memory publicInputs = new bytes32[](20);
            publicInputs[0] = bytes32(registeredKeyMe.X);
            publicInputs[1] = bytes32(registeredKeyMe.Y);

            publicInputs[2] = bytes32(registeredKeyTo.X);
            publicInputs[3] = bytes32(registeredKeyTo.Y);

            publicInputs[4] = bytes32(EncryptedAmountOldMeNow.C1x);
            publicInputs[5] = bytes32(EncryptedAmountOldMeNow.C1y);
            publicInputs[6] = bytes32(EncryptedAmountOldMeNow.C2x);
            publicInputs[7] = bytes32(EncryptedAmountOldMeNow.C2y);
            publicInputs[8] = bytes32(_to);
            publicInputs[9] = bytes32(_fee);
            publicInputs[10] = bytes32(_amountToSend.C1x);
            publicInputs[11] = bytes32(_amountToSend.C1y);
            publicInputs[12] = bytes32(_amountToSend.C2x);
            publicInputs[13] = bytes32(_amountToSend.C2y);

            publicInputs[14] = bytes32(EncryptedAmountNewMe.C1x);
            publicInputs[15] = bytes32(EncryptedAmountNewMe.C1y);
            publicInputs[16] = bytes32(EncryptedAmountNewMe.C2x);
            publicInputs[17] = bytes32(EncryptedAmountNewMe.C2y);

            // publicInputs[16] = bytes32(EncryptedAmountNewTo.C1x);
            // publicInputs[17] = bytes32(EncryptedAmountNewTo.C1y);
            // publicInputs[18] = bytes32(EncryptedAmountNewTo.C2x);
            // publicInputs[19] = bytes32(EncryptedAmountNewTo.C2y);

            require(TransferVerifier.verify(proof_transfer, publicInputs), "Transfer proof is invalid");
        } else {
            // TODO: add nonce

            bytes32[] memory publicInputs = new bytes32[](16);
            publicInputs[0] = bytes32(registeredKeyMe.X);
            publicInputs[1] = bytes32(registeredKeyMe.Y);

            publicInputs[2] = bytes32(registeredKeyTo.X);
            publicInputs[3] = bytes32(registeredKeyTo.Y);

            publicInputs[4] = bytes32(EncryptedAmountOldMeNow.C1x);
            publicInputs[5] = bytes32(EncryptedAmountOldMeNow.C1y);
            publicInputs[6] = bytes32(EncryptedAmountOldMeNow.C2x);
            publicInputs[7] = bytes32(EncryptedAmountOldMeNow.C2y);

            publicInputs[8] = bytes32(EncryptedAmountNewMe.C1x);
            publicInputs[9] = bytes32(EncryptedAmountNewMe.C1y);
            publicInputs[10] = bytes32(EncryptedAmountNewMe.C2x);
            publicInputs[11] = bytes32(EncryptedAmountNewMe.C2y);

            publicInputs[12] = bytes32(_to);
            publicInputs[13] = bytes32(_fee);

            require(
                TransferToNewVerifier.verify(proof_transfer, publicInputs), "Transfer to new address proof is invalid"
            );
        }
        balances[_from] = EncryptedAmountNewMe;
        balances[_to] = EncryptedAmountNewTo;
        emit PrivateTransfer(_from, _to);
    }

    function processPendingPendingTransaction(
        // the number of proofs passed is the number of PendingTransactions to process
        // the index of the proof in the array is the index of the PendingTransaction to process
        // from pendingTransactions
        bytes32[] memory _proofs,
        address _feeRecipient,
        byres32 _recipient,
        PublicKey memory _publicKey,
        EncryptedAmount calldata EncryptedAmountNewTo
    ) {
        for (i = 0; i++; proofs.length) {
            PendingTransaction memory pendingTransaction = sPopCheap(pendingTransactions, i); // pendingTransactions[recipient][i];
            uint256 fee = pendingTransaction.fee;
            EncryptedAmount oldBalance = balances[pendingTransaction.pubEncryptionKeyHash];

            bytes32[] memory publicInputs = new bytes32[](15);
            publicInputs[0] = bytes32(publicKey.X);
            publicInputs[1] = bytes32(publicKey.Y);
            publicInputs[2] = bytes32(pendingTransaction.pubEncryptionKeyHash);
            publicInputs[3] = bytes32(pendingTransaction.amount.C1x);
            publicInputs[4] = bytes32(pendingTransaction.amount.C1y);
            publicInputs[5] = bytes32(pendingTransaction.amount.C2x);
            publicInputs[6] = bytes32(pendingTransaction.amount.C2y);
            publicInputs[7] = bytes32(oldBalance.C1x);
            publicInputs[8] = bytes32(oldBalance.C1y);
            publicInputs[9] = bytes32(oldBalance.C2x);
            publicInputs[10] = bytes32(oldBalance.C2y);
            publicInputs[11] = bytes32(EncryptedAmountNewTo.C1x);
            publicInputs[12] = bytes32(EncryptedAmountNewTo.C1y);
            publicInputs[13] = bytes32(EncryptedAmountNewTo.C2x);
            publicInputs[14] = bytes32(EncryptedAmountNewTo.C2y);
            ProcessPendingVerifier(proofs[i], publicInputs);
            EncryptedAmount memory EncryptedAmountOldTo = balances[pendingTransaction.pubEncryptionKeyHash];
            EncryptedAmount memory EncryptedAmountNewTo = EncryptedAmountOldTo;
            balances[pendingTransaction.pubEncryptionKeyHash] = EncryptedAmountNewTo;
        }
        token.transfer(_feeRecipient, fee);
    }
}

// from here: https://github.com/cryptofinlabs/cryptofin-solidity/blob/master/contracts/array-utils/AddressArrayUtils.sol
function sPopCheap(PendingTransaction[] storage pendingTransaction, uint256 index)
    internal
    returns (PendingTransaction)
{
    uint256 length = A.length;
    if (index >= length) {
        revert("Error: index out of bounds");
    }
    PendingTransaction entry = A[index];
    if (index != length - 1) {
        A[index] = A[length - 1];
        delete A[length - 1];
    }
    A.length--;
    return entry;
}
