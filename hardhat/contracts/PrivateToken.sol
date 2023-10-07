// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// import "./PublicKeyInfrastructure.sol";
import {TransferUltraVerifier} from "./transfer_plonk_vk.sol";
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
    struct PendingTransfer {
        EncryptedAmount amount;
        // add a fee to incentivize someone to process the pending tx
        // otherwise leave as 0 and the recipient can process the tx themselves at cost
        uint256 fee;
    }

    struct PendingDeposit {
        uint256 amount;
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

    ProcessDepositVerifier public immutable PROCESS_DEPOSIT_VERIFIER;
    ProcessTransferVerifier public immutable PROCESS_TRANSFER_VERIFIER;
    TransferVerifier public immutable TRANSFER_VERIFIER;
    WithdrawVerifier public immutable WITHDRAW_VERIFIER;
    uint40 public immutable totalSupply;

    IERC20 token;
    uint8 public immutable decimals = 2;

    // hash of public key => encrypted balance
    mapping(bytes32 => EncryptedAmount) public balances;
    mapping(bytes32 => PendingTransfer[]) public pendingTransfers;
    mapping(bytes32 => PendingDeposit[]) public pendingDeposits;

    // This prevents replay attacks in the transfer fn
    mapping(bytes32 => uint256) public nonce;

    /*
        A PendingTransaction is added to this array when transfer is called.
        The transfer fn debits the senders balance by the amount sent.
        The sender encrypts the amount with the receivers public key

        The processPendingTransfer fn takes a batch of PendingTransfers, and 
        does computes the updates for the homonorphic addition of the encrypted 
        amounts to the receivers and updates the recievers encrypted balances.

    */

    event PrivateTransfer(bytes32 indexed to, address indexed from);

    /**
     * @notice
     * @dev
     * @param TransferVerifierAddress
     * @param _token
     */
    constructor(
        address processDepositVerifier,
        address rocessTransferVerifier,
        address transferVerifierAddress,
        address withdrawVerifier,
        address _token
    ) {
        TransferVerifier = TransferUltraVerifier(TransferVerifierAddress);
        token = IERC20(_token);
    }

    // TODO: add transferWithRelay and withdrawWithRelay functions and write circuits
    // the idea is to be able to incentivize other people to submit txs for your from their
    // ETH accounts, so you dont doxx yourself by sending txs from your ETH account
    // relayFee can be public, recipient can be ETH address
    // need to update circuits
    // potentially mitigate DDoS attacks against relayers with RLNs

    /**
     * @notice
     * @dev
     * @param TransferToNewVerifierAddress - ddd
     */

    function deposit(address _from, uint256 _amount, bytes32 _to, uint256 fee) public {
        // convert to decimals places. any decimals following 2 are lost
        // max value is u40 - 1, so 1099511627775. with 2 decimals
        // that gives us a max supply of ~11 billion erc20 tokens
        uint40 amount = _amount / 10 ** (token.decimals() - decimals);
        require(totalSupply + amount < type(uint40).max, "Amount is too big");
        token.transferFrom(_from, this.address, uint256(_amount));
        // keep the fee - users can add a fee to incentivize processPendingDeposits
        amount = amount - fee;
        pendingDeposits[_to].push({amount: amount, fee: fee});
    }

    /**
     * @notice This functions transfers an encrypted amount of tokens to the recipient (_to).
     *  If the sender is sending to an account with a 0 balance, they can omit the fee, as the funds
     *  will be directly added to their account. Otherwise a fee can be specified to incentivize
     *  processing of the tx by an unknown third party (see processPendingTranfer). This is required
     *  two account cannot simultaneously update the encrypted balance of the recipient. Having a pending
     *  transfer queue allows the sender to always succeed in debiting their account, and the recipient
     *  receiving the funds.
     * @dev
     * @param _to - recipient of the tokens
     * @param _from - sender of the tokens
     * @param _fee - (optional, can be 0) amount to pay the processor of the tx (when processPendingTransfers is called)
     *  if there is no fee supplied, the recipient can process it themselves
     * @param _recipient_pub_key - public key of the recipient in the system
     * @param _sender_pub_key - public key of the sender in the system
     * @param _amountToSend - amount to send, encrypted with the recipients public key
     * @param _senderNewBalance - sender's new balance, minus the amount sent and the fee
     * @param _proof_transfer - proof
     */

    function transfer(
        bytes32 _to,
        bytes32 _from,
        uint256 _fee,
        PublicKey memory _recipient_pub_key,
        PublicKey memory _sender_pub_key,
        EnrcyptedAmount calldata _amountToSend,
        EncryptedAmount calldata _senderNewBalance,
        bytes memory _proof_transfer
    ) public {
        EncryptedAmount memory oldBalance = balances[_from];
        EncryptedAmount memory receiverBalance = balances[_to];

        bool zeroBalance =
            receiverBalance.Cx1 == 0 && receiverBalance.Cx2 == 0 && receiverBalance.Cy1 == 0 && receiverBalance.Cy2 == 0;

        if (zeroBalance) {
            // no fee required if a new account
            _fee == 0;
            balances[_to] = _amountToSend;
        } else {
            pendingTransactions[_to].push({amount: _amountToSend, fee: _fee});
        }

        bytes32[] memory publicInputs = new bytes32[](19);
        publicInputs[0] = bytes32(_sender_pub_key.X);
        publicInputs[1] = bytes32(_sender_pub_key.Y);
        publicInputs[2] = bytes32(_recipient_pub_key.X);
        publicInputs[3] = bytes32(_recipient_pub_key.Y);
        publicInputs[4] = bytes32(_to);
        publicInputs[5] = bytes32(_fee);
        publicInputs[6] = bytes32(nonce[_from]);
        publicInputs[7] = bytes32(oldBalance.C1x);
        publicInputs[8] = bytes32(oldBalance.C1y);
        publicInputs[9] = bytes32(oldBalance.C2x);
        publicInputs[10] = bytes32(oldBalance.C2y);
        publicInputs[11] = bytes32(_amountToSend.C1x);
        publicInputs[12] = bytes32(_amountToSend.C1y);
        publicInputs[13] = bytes32(_amountToSend.C2x);
        publicInputs[14] = bytes32(_amountToSend.C2y);
        publicInputs[15] = bytes32(_senderNewBalance.C1x);
        publicInputs[16] = bytes32(_senderNewBalance.C1y);
        publicInputs[17] = bytes32(_senderNewBalance.C2x);
        publicInputs[18] = bytes32(_senderNewBalance.C2y);
        require(TransferVerifier.verify(proof_transfer, publicInputs), "Transfer proof is invalid");

        balances[_from] = _myNewBalance;
        emit PrivateTransfer(_from, _to);
        nonce[_from]++;
    }

    /**
     * @notice TODO
     * @dev
     * @param
     */

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

    /**
     * @notice the circuit processing this takes in a fixes number of pending transactions.
     *  It will take up to 4 at a time (TODO: research how big this num should this be?).
     *  The circuit checks that the publicKey and recipient match. it encrypts the totalAmount
     *  and adds it to the recipients encrypted balance. It checks that the provided encrypted
     *  balance and the calculated encrypted balances match.
     * @dev
     * @param _proof - proof to verify with the ProcessPendingTransfers circuit
     * @param _txsToProcess - an array indexes of pendingDeposits to process; max length 4
     * @param _feeRecipient - the recipient of the fees (typically the processor of these txs)
     * @param _recipient - the recipient of the pending transfers within the system
     * @param _publicKey - the public key of the recipient in the system
     * @param _newBalance - the new balance of the recipient after processing the pending transfers
     */

    function processPendingDeposit(
        bytes32 memory _proof,
        uint8[] memory _txsToProcess,
        address _feeRecipient,
        bytes32 _recipient,
        PublicKey memory _publicKey,
        EncryptedAmount calldata _newBalance
    ) public {
        uint8 numTxsToProcess = _txsToProcess.length;
        require(numTxsToProcess <= 4, "Too many txs to process");
        uint256 totalFees;
        uint256 totalAmount;
        EncryptedAmount oldBalance = balances[_recipient];
        for (i = 0; i++; _numTxsToProcess) {
            PendingDeposit memory pendingDeposit = sPopCheap(pendingDeposits, i);
            totalAmount += pendingDeposit.amount;
            totalFees += pendingDeposit.fee;
        }

        bytes32[] memory publicInputs = new bytes32[](12);
        publicInputs[0] = bytes32(publicKey.X);
        publicInputs[1] = bytes32(publicKey.Y);
        publicInputs[2] = bytes32(_recipient);
        publicInputs[3] = bytes32(totalAmount);
        publicInputs[4] = bytes32(oldBalance.C1x);
        publicInputs[5] = bytes32(oldBalance.C1y);
        publicInputs[6] = bytes32(oldBalance.C2x);
        publicInputs[7] = bytes32(oldBalance.C2y);
        publicInputs[8] = bytes32(newBalance.C1x);
        publicInputs[9] = bytes32(newBalance.C1y);
        publicInputs[10] = bytes32(newBalance.C2x);
        publicInputs[11] = bytes32(newBalance.C2y);

        require(ProcessPendingDepositVerifier(_proof, publicInputs), "Process pending proof is invalid");
        balances[_recipient] = _newBalance;
        token.transfer(_feeRecipient, totalFees);
    }

    /**
     * @notice the circuit processing this takes in a fixes number of pending transactions.
     *  It will take up to 4 at a time (TODO: research how big this num should this be?). The circuit adds all of the encrypted amounts sent
     *  and then checks that the _newBalance is the sum of the old balance and the sum of the
     *  amounts to add. All of the fees are summed and sent to the _feeRecipient
     * @dev
     * @param _proof - proof to verify with the ProcessPendingTransfers circuit
     * @param _txsToProcess - the indexs of the pendingTransfers to process; max length 4
     * @param _feeRecipient - the recipient of the fees (typically the processor of these txs)
     * @param _recipient - the recipient of the pending transfers within the system
     * @param _publicKey - the public key of the recipient in the system
     * @param _newBalance - the new balance of the recipient after processing the pending transfers
     */

    function processPendingTransfer(
        bytes32 memory _proof,
        uint8[] memory _txsToProcess,
        address _feeRecipient,
        bytes32 _recipient,
        PublicKey memory _publicKey,
        EncryptedAmount calldata _newBalance
    ) public {
        uint8 numTxsToProcess = _txsToProcess.length;
        require(_txsToProcess.length <= 4, "Too many txs to process");
        uint256 totalFees;
        EncryptedAmount oldBalance = balances[_recipient];
        EncryptedAmount[] encryptedAmounts = new EncryptedAmount[](numTxsToProcess);

        bytes32[] memory publicInputs = new bytes32[](35);
        publicInputs[0] = bytes32(publicKey.X);
        publicInputs[1] = bytes32(publicKey.Y);
        publicInputs[2] = bytes32(_recipient);
        publicInputs[3] = bytes32(encryptedAmounts.amount.C1x);
        publicInputs[4] = bytes32(oldBalance.C1x);
        publicInputs[5] = bytes32(oldBalance.C1y);
        publicInputs[6] = bytes32(oldBalance.C2x);
        publicInputs[7] = bytes32(oldBalance.C2y);
        publicInputs[8] = bytes32(newBalance.C1x);
        publicInputs[9] = bytes32(newBalance.C1y);
        publicInputs[10] = bytes32(newBalance.C2x);
        publicInputs[11] = bytes32(newBalance.C2y);

        for (i = 0; i++; numTxsToProcess) {
            // note that the sPopCheap changes the order of the array,
            // so _txsToProcess[i] should take that into account when choosing indexes
            PendingTransfer memory pendingTransfer = sPopCheap(pendingTransfers, _txsToProcess[i]);
            publicInputs.push(pendingTransfer.amount.C1x);
            publicInputs.push(pendingTransfer.amount.C1y);
            publicInputs.push(pendingTransfer.amount.C2x);
            publicInputs.push(pendingTransfer.amount.C2x);
            totalFees += pendingTransaction.fee;
        }

        require(ProcessPendingVerifier(proofs[i], publicInputs), "Process pending proof is invalid");
        balances[_recipient] = newBalance;
        token.transfer(_feeRecipient, totalFees);
    }

    /**
     * @notice
     * @dev
     * @param
     */
    // from here: https://github.com/cryptofinlabs/cryptofin-solidity/blob/master/contracts/array-utils/AddressArrayUtils.sol

    function sPopCheap(PendingTransfer[] storage pendingTransfers, uint256 index) internal returns (PendingTransfer) {
        uint256 length = A.length;
        if (index >= length) {
            revert("Error: index out of bounds");
        }
        PendingTransfer entry = A[index];
        if (index != length - 1) {
            A[index] = A[length - 1];
            delete A[length - 1];
        }
        A.length--;
        return entry;
    }

    function sPopCheap(PendingDeposit[] storage pendingDeposits, uint256 index) internal returns (PendingDeposit) {
        uint256 length = A.length;
        if (index >= length) {
            revert("Error: index out of bounds");
        }
        PendingDeposit entry = A[index];
        if (index != length - 1) {
            A[index] = A[length - 1];
            delete A[length - 1];
        }
        A.length--;
        return entry;
    }
}
