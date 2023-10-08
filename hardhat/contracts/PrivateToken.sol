// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {UltraVerifier as ProcessDepositVerifier} from "./process_pending_deposits/plonk_vk.sol";
import {UltraVerifier as ProcessTransferVerifier} from "./process_pending_transfers/plonk_vk.sol";
import {UltraVerifier as TransferVerifier} from "./transfer/plonk_vk.sol";
import {UltraVerifier as WithdrawVerifier} from "./withdraw/plonk_vk.sol";

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
        uint256 time;
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
    uint40 public totalSupply;

    IERC20 token;
    uint256 public immutable SOURCE_TOKEN_DECIMALS;
    uint8 public immutable decimals = 2;

    // hash of public key => encrypted balance
    mapping(bytes32 => EncryptedAmount) public balances;

    // hash of public key => the key for the allPendingTransfersMapping
    mapping(bytes32 => uint256) public pendingTransferNonces;
    mapping(bytes32 => uint256) public pendingDepositNonces;
    mapping(bytes32 => mapping(uint256 => PendingTransfer)) public allPendingTransfersMapping;
    mapping(bytes32 => mapping(uint256 => PendingDeposit)) public allPendingDepositsMapping;

    // This prevents replay attacks in the transfer fn
    // TODO: update how nonces are calculated, use a hash or something
    mapping(bytes32 => bytes32) public nonce;

    /*
        A PendingTransaction is added to this array when transfer is called.
        The transfer fn debits the senders balance by the amount sent.
        The sender encrypts the amount with the receivers public key

        The processPendingTransfer fn takes a batch of PendingTransfers, and 
        does computes the updates for the homonorphic addition of the encrypted 
        amounts to the receivers and updates the recievers encrypted balances.

    */

    event Transfer(bytes32 indexed to, address indexed from);
    event TransferProcessed(bytes32 to, uint256 fee, address feeRecipient);
    event Deposit(address from, bytes32 to, uint256 amount, uint256 fee);
    event DepositProcessed(bytes32 to, uint256 amount, uint256 fee, address feeRecipient);
    event Withdraw(bytes32 from, address to, uint256 amount);

    /**
     * @notice Constructor - setup up verifiers and link to token
     * @dev
     * @param _processDepositVerifier address of the processDepositVerifier contract
     * @param _processTransferVerifier address of the processTransferVerifier contract
     * @param _transferVerifier address of the transferVerifier contract
     * @param _withdrawVerifier address of the withdrawVerifier contract
     * @param _token - ERC20 token address
     */
    constructor(
        address _processDepositVerifier,
        address _processTransferVerifier,
        address _transferVerifier,
        address _withdrawVerifier,
        address _token,
        uint256 _decimals
    ) {
        PROCESS_DEPOSIT_VERIFIER = ProcessDepositVerifier(_processDepositVerifier);
        PROCESS_TRANSFER_VERIFIER = ProcessTransferVerifier(_processTransferVerifier);
        TRANSFER_VERIFIER = TransferVerifier(_transferVerifier);
        WITHDRAW_VERIFIER = WithdrawVerifier(_withdrawVerifier);
        token = IERC20(_token);
        try token.decimals() returns (uint256 returnedDecimals) {
            SOURCE_TOKEN_DECIMALS = returnedDecimals;
        } catch {
            SOURCE_TOKEN_DECIMALS = _decimals;
        }
    }

    // TODO: add transferWithRelay and withdrawWithRelay functions and write circuits
    // the idea is to be able to incentivize other people to submit txs for your from their
    // ETH accounts, so you dont doxx yourself by sending txs from your ETH account
    // relayFee can be public, recipient can be ETH address
    // need to update circuits
    // potentially mitigate DDoS attacks against relayers with RLNs

    /**
     * @notice Deposits the assocated token into the contract to be used privately.
     *  The deposited amount is pushed to the recepients PendingDeposits queue. The fee
     *  is the amount that will be paid to the processor of the tx (when processPendingDeposits
     *  is called)
     *  This function converts the token to 2 decimal places, the remainder is lost
     * @dev
     * @param _from - sender of the tokens, an ETH address
     *  @param _amount - amount to deposit
     *  @param _to - recipient of the tokens, a public key in the system
     *  @param _fee - (optional, can be 0) amount to pay the processor of the tx (when processPendingDeposits is called)
     */

    function deposit(address _from, uint256 _amount, bytes32 _to, uint40 _fee) public {
        // convert to decimals places. any decimals following 2 are lost
        // max value is u40 - 1, so 1099511627775. with 2 decimals
        // that gives us a max supply of ~11 billion erc20 tokens
        uint40 amount = uint40(_amount / 10 ** (SOURCE_TOKEN_DECIMALS - decimals));
        require(totalSupply + amount < type(uint40).max, "Amount is too big");
        token.transferFrom(_from, address(this), uint256(_amount));
        // keep the fee - users can add a fee to incentivize processPendingDeposits
        amount = amount - _fee;
        allPendingDepositsMapping[_to].push(PendingDeposit(amount, _fee));
        totalSupply += amount;
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
        EncryptedAmount calldata _amountToSend,
        EncryptedAmount calldata _senderNewBalance,
        bytes memory _proof_transfer
    ) public {
        EncryptedAmount memory oldBalance = balances[_from];
        EncryptedAmount memory receiverBalance = balances[_to];

        bool zeroBalance = (
            receiverBalance.C1x == 0 && receiverBalance.C2x == 0 && receiverBalance.C1y == 0 && receiverBalance.C2y == 0
        );
        if (zeroBalance) {
            // no fee required if a new account
            _fee = 0;
            balances[_to] = _amountToSend;
        } else {
            allPendingTransfersMapping[_to].push(PendingTransfer(_amountToSend, _fee, block.timestamp));
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
        require(TRANSFER_VERIFIER.verify(_proof_transfer, publicInputs), "Transfer proof is invalid");

        balances[_from] = _senderNewBalance;
        emit Transfer(_from, _to);
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
        uint40 _amount,
        bytes memory _withdraw_proof,
        PublicKey memory _pub_key,
        EncryptedAmount memory _newEncryptedAmount
    ) public {
        // TODO: add nonce
        EncryptedAmount memory oldEncryptedAmount = balances[_from];
        bytes32[] memory publicInputs = new bytes32[](7);
        publicInputs[0] = bytes32(_pub_key.X);
        publicInputs[1] = bytes32(_pub_key.Y);
        publicInputs[2] = bytes32(uint256(_amount));
        publicInputs[3] = bytes32(oldEncryptedAmount.C1x);
        publicInputs[4] = bytes32(oldEncryptedAmount.C1y);
        publicInputs[5] = bytes32(oldEncryptedAmount.C2x);
        publicInputs[6] = bytes32(oldEncryptedAmount.C2y);
        publicInputs[7] = bytes32(_newEncryptedAmount.C1x);
        publicInputs[8] = bytes32(_newEncryptedAmount.C1y);
        publicInputs[9] = bytes32(_newEncryptedAmount.C2x);
        publicInputs[10] = bytes32(_newEncryptedAmount.C2y);
        require(WITHDRAW_VERIFIER.verify(_withdraw_proof, publicInputs), "Withdraw proof is invalid");
        // calculate the new total encrypted supply offchain, replace existing value (not an increment)
        balances[_from] = _newEncryptedAmount;
        totalSupply -= _amount;
        token.transferFrom(address(this), _to, uint256(_amount * 10 ** (token.decimals() - decimals)));
    }

    /**
     * @notice the circuit processing this takes in a fixes number of pending transactions.
     *  It will take up to 4 at a time (TODO: research how big this num should this be?).
     *  The circuit checks that the publicKey and recipient match. it encrypts the totalAmount
     *  and adds it to the recipients encrypted balance. It checks that the provided encrypted
     *  balance and the calculated encrypted balances match.
     * @dev
     * @param _proof - proof to verify with the ProcessPendingTransfers circuit
     * @param _txsToProcess - an array indexes of PendingDeposits to process; max length 4
     * @param _feeRecipient - the recipient of the fees (typically the processor of these txs)
     * @param _recipient - the recipient of the pending transfers within the system
     * @param _publicKey - the public key of the recipient in the system
     * @param _newBalance - the new balance of the recipient after processing the pending transfers
     */

    function processPendingDeposit(
        bytes memory _proof,
        uint8[] memory _txsToProcess,
        address _feeRecipient,
        bytes32 _recipient,
        PublicKey memory _publicKey,
        EncryptedAmount calldata _newBalance
    ) public {
        uint8 numTxsToProcess = uint8(_txsToProcess.length);
        require(numTxsToProcess <= 4, "Too many txs to process");
        uint256 totalFees;
        uint256 totalAmount;
        EncryptedAmount memory oldBalance = balances[_recipient];
        PendingDeposit[] storage userPendingDepositsArray = allPendingDepositsMapping[_recipient];
        for (uint8 i = 0; i++; numTxsToProcess) {
            PendingDeposit memory deposit = sPopCheap(userPendingDepositsArray, _txsToProcess[i]);
            totalAmount += deposit.amount;
            totalFees += deposit.fee;
        }

        bytes32[] memory publicInputs = new bytes32[](12);
        publicInputs[0] = bytes32(_publicKey.X);
        publicInputs[1] = bytes32(_publicKey.Y);
        publicInputs[2] = bytes32(_recipient);
        publicInputs[3] = bytes32(totalAmount);
        publicInputs[4] = bytes32(oldBalance.C1x);
        publicInputs[5] = bytes32(oldBalance.C1y);
        publicInputs[6] = bytes32(oldBalance.C2x);
        publicInputs[7] = bytes32(oldBalance.C2y);
        publicInputs[8] = bytes32(_newBalance.C1x);
        publicInputs[9] = bytes32(_newBalance.C1y);
        publicInputs[10] = bytes32(_newBalance.C2x);
        publicInputs[11] = bytes32(_newBalance.C2y);

        require(PROCESS_DEPOSIT_VERIFIER.verify(_proof, publicInputs), "Process pending proof is invalid");
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
     * @param _txsToProcess - the indexs of the userPendingTransfersArray to process; max length 4
     * @param _feeRecipient - the recipient of the fees (typically the processor of these txs)
     * @param _recipient - the recipient of the pending transfers within the system
     * @param _newBalance - the new balance of the recipient after processing the pending transfers
     */

    function processPendingTransfer(
        bytes memory _proof,
        uint8[] memory _txsToProcess,
        address _feeRecipient,
        bytes32 _recipient,
        // PublicKey memory _publicKey,
        EncryptedAmount calldata _newBalance
    ) public {
        uint8 numTxsToProcess = uint8(_txsToProcess.length);
        require(_txsToProcess.length <= 4, "Too many txs to process");
        uint256 totalFees;
        EncryptedAmount memory oldBalance = balances[_recipient];
        EncryptedAmount[] memory encryptedAmounts = new EncryptedAmount[](numTxsToProcess);

        bytes32[] memory publicInputs = new bytes32[](35);
        // publicInputs[0] = bytes32(_publicKey.X);
        // publicInputs[1] = bytes32(_publicKey.Y);
        // publicInputs[2] = bytes32(_recipient);
        // publicInputs[3] = bytes32(encryptedAmounts.amount.C1x);
        publicInputs[4] = bytes32(oldBalance.C1x);
        publicInputs[5] = bytes32(oldBalance.C1y);
        publicInputs[6] = bytes32(oldBalance.C2x);
        publicInputs[7] = bytes32(oldBalance.C2y);
        publicInputs[8] = bytes32(_newBalance.C1x);
        publicInputs[9] = bytes32(_newBalance.C1y);
        publicInputs[10] = bytes32(_newBalance.C2x);
        publicInputs[11] = bytes32(_newBalance.C2y);

        PendingTransfer[] storage pendingTransfers = allPendingTransfersMapping[_recipient];
        for (uint8 i = 0; i++; numTxsToProcess) {
            // note that the sPopCheap changes the order of the array,
            // so _txsToProcess[i] should take that into account when choosing indexes
            PendingTransfer memory pendingTransfer = sPopCheap(pendingTransfers, _txsToProcess[i]);
            require(block.timestamp > pendingTransfer.time);
            publicInputs.push(pendingTransfer.amount.C1x);
            publicInputs.push(pendingTransfer.amount.C1y);
            publicInputs.push(pendingTransfer.amount.C2x);
            publicInputs.push(pendingTransfer.amount.C2x);
            totalFees += pendingTransfer.fee;
        }

        require(PROCESS_TRANSFER_VERIFIER.verify(_proof, publicInputs), "Process pending proof is invalid");
        balances[_recipient] = _newBalance;
        token.transfer(_feeRecipient, totalFees);
    }

    // from here: https://github.com/cryptofinlabs/cryptofin-solidity/blob/master/contracts/array-utils/AddressArrayUtils.sol

    function sPopCheap(PendingTransfer[] storage transfers, uint256 index) internal returns (PendingTransfer memory) {
        uint256 length = transfers.length;
        if (index >= length) {
            revert("Error: index out of bounds");
        }
        PendingTransfer memory entry = transfers[index];
        if (index != length - 1) {
            transfers[index] = transfers[length - 1];
            delete transfers[length - 1];
        }
        transfers.length--;
        return entry;
    }

    function sPopCheap(PendingDeposit[] storage deposits, uint256 index) internal returns (PendingDeposit memory) {
        uint256 length = deposits.length;
        if (index >= length) {
            revert("Error: index out of bounds");
        }
        PendingDeposit memory entry = deposits[index];
        if (index != length - 1) {
            deposits[index] = deposits[length - 1];
            delete deposits[length - 1];
        }
        deposits.length--;
        return entry;
    }
}
