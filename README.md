# Issue H-1: Incorrect implementation of the onDropMessage function in the L1ReverseCustomGateway contract 

Source: https://github.com/sherlock-audit/2024-08-morphl2-judging/issues/66 

## Found by 
0xRajkumar, mstpr-brainbot, sammy
## Summary and Vulnerability Detail
In the L1ReverseCustomGateway, tokens are burned during deposit and minted during the finalizeWithdrawERC20 process.

For failed deposits, we have the onDropMessage function to allow the user to retrieve their tokens.
```solidity
    function onDropMessage(bytes calldata _message) external payable virtual onlyInDropContext nonReentrant {
        // _message should start with 0x8431f5c1  =>  finalizeDepositERC20(address,address,address,address,uint256,bytes)
        require(bytes4(_message[0:4]) == IL2ERC20Gateway.finalizeDepositERC20.selector, "invalid selector");

        // decode (token, receiver, amount)
        (address _token, , address _receiver, , uint256 _amount, ) = abi.decode(
            _message[4:],
            (address, address, address, address, uint256, bytes)
        );

        // do dome check for each custom gateway
        _beforeDropMessage(_token, _receiver, _amount);

        IERC20Upgradeable(_token).safeTransfer(_receiver, _amount);

        emit RefundERC20(_token, _receiver, _amount);
    }
```
It will not work now because instead of using safeTransfer we should mint the tokens to _receiver.

## Impact
The impact is high because the dropMessage functionality will never work, preventing the user from recovering their tokens.


## Tool used

Manual Review

## Recommendation
My recommendation is to use `IMorphERC20Upgradeable(_token).mint(_receiver, _amount)` instead of transferring the tokens.
## References

https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/l1/gateways/L1ReverseCustomGateway.sol


https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/l1/gateways/L1ERC20Gateway.sol#L74-L90



## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/morph-l2/morph/pull/562


# Issue H-2: Sequencer will be underpaid because of incorrect `commitScalar` 

Source: https://github.com/sherlock-audit/2024-08-morphl2-judging/issues/90 

The protocol has acknowledged this issue.

## Found by 
PapaPitufo
### Summary

`GasPriceOracle.sol` underprices the cost of calling `commitBatch()`, so the `l1DataCost` paid by users will be substantially less than the true cost to the sequencer. This is made worse when transactions are heavily weighted towards L1 cost, in which case the sequencer can be responsible for payments 100X as large as the revenue collected.

### Root Cause

When new L2 transactions are submitted, the transaction cost is calculated as the L2 gas price plus an `l1DataFee`, which is intended to cover the cost of posting the data to L1.

The `l1DataFee` is actually calculated in go-ethereum [rollup/fees/rollup_fee.go#L153](https://github.com/morph-l2/go-ethereum/blob/e58ac01d16da31d9ca25a5e7e0e09bfdd352e76b/rollup/fees/rollup_fee.go#L153-L167), but is equivalent to this calculation in `GasPriceOracle.sol` as:
```solidity
function getL1FeeCurie(bytes memory _data) internal view returns (uint256) {
    // We have bounded the value of `commitScalar` and `blobScalar`, the whole expression won't overflow.
    return (commitScalar * l1BaseFee + blobScalar * _data.length * l1BlobBaseFee) / PRECISION;
}
```
We can summarize as:
- We pay 1 gas per byte that goes into a blob (because [GAS_PER_BLOB == 2**17](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4844.md)), so we can calculate the cost of the blob as `blobScalar * _data.length * l1BlobBaseFee`.
- We have to call `commitBatch()` as well, so we take the gas cost of that call and multiply by the `l1BaseFee`.

The config specifies that the `blobScalar = 0.4e9` and the `commitScalar = 230e9`.

This `commitScalar` is underpriced by a margin of 100X, as it should be `230_000e9`, not `230e9`.

The result is that transactions that are largely weighted towards the L1 fee will cost the sequencer way more to commit to than the user paid.

In an extreme, we can imagine an attack where users performed the most L1 data intensive transactions possible, which consist of filling a full batch with a single transaction that uses 128kb of calldata.

Let's look at the relative costs for the attacker and the sequencer of such a transaction:

- The attacker's fee is calculated as `intrinsic gas + calldata + l1DataFee`.
- Since blobs are 128kb, we need `1024 * 128 = 131,072` bytes of calldata to fill the blob.
- Assuming we need half non-zero to avoid compression, we can calculate the calldata cost as: `1024 * 128 * (4 + 16 / 2) = 1,310,720`.
- Therefore, the total gas used by the attacker is `21_000 + 1,310,720 = 1,331,720`.
- The l1DataFee is calculated as above. If we assume an l1BaseFee of 30 gwei, this gives a cost of `52,428 + (230 * 30) = 59,328 gwei`.
- Assuming an L2 gas price of 0.001 gwei (estimate from L1 message queue), our total cost is `(1,331,720 * 0.001) + 59,328 = 60,659 gwei = $0.13`.

On the other hands, let's look at the sequencer's cost:

- The blob cost is the same as the attacker's l1DataFee, as that is calculated correctly at `52,428 gwei`.
- The transaction cost, based on the Foundry estimate, is 230,000 gas. At 30 gwei per gas, that equals `230_000 * 30 = 6,900,000 gwei`.
- The total cost to the sequencer is `6,900,000 + 52,428 = 6,952,428 gwei = $15.98`.

This mismatch requires sequencers to spend more than 100X to progress the chain, when only X was collected in sequencer fees from the user.

### Internal Preconditions

None

### External Preconditions

None

### Attack Path

Note that this mispricing will cause the chain to slowly bleed revenue, regardless of any "attack". However, the most accute version of this attack would be as follows:

1. User send a transfer of 0 value on L2 with 128kb of calldata.
2. This costs them approximately $0.13 in L2 fees, but will require the sequencer to spent $15.98 in L1 gas to commit the batch.
3. The user can repeat this attack indefinitely, causing the sequencer to spend more money than it receives.

### Impact

Sequencers can be forced to spend 100X more than the fee revenue received in order to progress the chain, making the chain uneconomical.

### PoC

N/A

### Mitigation

`commitBatch()` should be set to `230_000e9`.

Note that it appears that this value was pulled from Scroll's current on chain implementation. This issue has been reported directly to Scroll as well, and has been deemed valid and awarded with a bounty via their Immunefi bounty program.

# Issue H-3: Malicious users can make failed messages unreplayable by exhausting `maxReplayTimes`, leading to funds stuck forever on the origin chain 

Source: https://github.com/sherlock-audit/2024-08-morphl2-judging/issues/177 

## Found by 
underdog
### Summary

The limitation of only allowing messages to be replayed up to `maxReplayTimes`, together with a conservative computation of the required gas limit to execute a message allows malicious users to prevent messages from being replayed. A malicious user can trigger `replayMessage` up to `maxReplayTimes` with a low gas limit, forcing the transaction to fail on the destination (Morph) chain, and making sender funds remain stuck forever in the L1.

### Root Cause

This bug requires some context prior to directly diving into the Root cause.

#### Introduction

Morph's `L1CrossDomainMessenger` acts as Morph’s entry point to transfer cross-layer messages. In order to send a message from L1->L2, the `sendMessage()` function is used, and the transaction executed will be internally tracked by encoding the following parameters into a unique identifier (the `xDomainCalldataHash`):

- `relayMessage()` method signature
- Sender of the transaction
- Receiver on the destination chain
- Value
- Nonce from the Message Queue
- The actual message

The encoding is done with the `_encodeXDomainCalldata()` internal function, which gives an encoded array of bytes that will later be hashed. This allows to track each specific message with a unique identifier:

```solidity
// File: L1CrossDomainMessenger.sol

function _sendMessage(
        address _to,
        uint256 _value,
        bytes memory _message,
        uint256 _gasLimit,
        address _refundAddress 
    ) internal nonReentrant {
        ...
        bytes memory _xDomainCalldata = _encodeXDomainCalldata(_msgSender(), _to, _value, _messageNonce, _message);

        ...

        // record the message hash for future use.
        bytes32 _xDomainCalldataHash = keccak256(_xDomainCalldata);

        // normally this won't happen, since each message has different nonce, but just in case.
        require(messageSendTimestamp[_xDomainCalldataHash] == 0, "Duplicated message");
        messageSendTimestamp[_xDomainCalldataHash] = block.timestamp;
        ...

    }

```

It is worth noting that `_gasLimit` is **NOT** encoded neither used to obtain the final `_xDomainCalldataHash`. This is done because sometimes the gas limit specified to send a cross-layer transaction might not be enough to correctly execute the transaction on the L2. If this occurs, Morph allows users to retrigger the transaction via the `replayMessage()` function.

#### Replaying messages

As mentioned in the introduction, cross-layer messages that failed on the destination chain can be replayed via the `replayMessage()` function:

```solidity
// File: L1CrossDomainMessenger.sol

function replayMessage( 
        address _from,
        address _to, 
        uint256 _value, 
        uint256 _messageNonce,  
        bytes memory _message,
        uint32 _newGasLimit,
        address _refundAddress
    ) external payable override whenNotPaused notInExecution { 
        ...
        
        bytes memory _xDomainCalldata = _encodeXDomainCalldata(_from, _to, _value, _messageNonce, _message);
        bytes32 _xDomainCalldataHash = keccak256(_xDomainCalldata);

        ...

        ReplayState memory _replayState = replayStates[_xDomainCalldataHash];
        // update the replayed message chain.
        unchecked {
            if (_replayState.lastIndex == 0) {
                // the message has not been replayed before.
                prevReplayIndex[_nextQueueIndex] = _messageNonce + 1;
            } else {
                prevReplayIndex[_nextQueueIndex] = _replayState.lastIndex + 1;
            }
        }
        _replayState.lastIndex = uint128(_nextQueueIndex);

        // update replay times
        require(_replayState.times < maxReplayTimes, "Exceed maximum replay times");
        unchecked {
            _replayState.times += 1;
        }
        replayStates[_xDomainCalldataHash] = _replayState;

        ...

    }

```

This functionality allows users that have had their cross-layer transactions failed on the L2 (maybe due to setting an incorrect gas limit) to be replayed with a greater gas limit.

There are two points worth mentioning from this function:

- `replayMessage()` allows to pass a `_newGasLimit` parameter. As mentioned before, the gas limit is not used to obtain the unique identifier `_xDomainCalldataHash`, so this allows users that have had their message fail on the L2 due to setting a low gas limit on `sendMessage()` to retrigger it with a different gas limit. It is also worth noting that the gas limit **is not required to be greater than the gas limit set in the original call**.
- There is a maximum number of times that a message can be replayed. This is done because Morph also allows messages to be dropped when the cross-layer transaction leads to a circuit overflow (this is described in the [Handling Cross-layer (Bridge) Failures section](https://docs.morphl2.io/docs/how-morph-works/general-protocol-design/communicate-between-morph-and-ethereum#handling-cross-layer-bridge-failures). `maxReplayTimes` limits the amount of times a message can be replayed, because the logic to drop a message iterates a list that contains all the replayed messages and drops all of them. If there was not a limit on the amount of replayed messages, then the message dropping logic could be DoS'ed by a malicious user by inflating the amount of replayed messages:
    
    ```solidity
    // File: L1CrossDomainMessenger.sol
    
        function dropMessage( 
            address _from,
            address _to,
            uint256 _value,
            uint256 _messageNonce,
            bytes memory _message
        ) external override whenNotPaused notInExecution {
            // The criteria for dropping a message: 
            // 1. The message is a L1 message.
            // 2. The message has not been dropped before.
            // 3. the message and all of its replacement are finalized in L1.
            // 4. the message and all of its replacement are skipped.
            //
            // Possible denial of service attack:
            // + replayMessage is called every time someone want to drop the message.
            // + replayMessage is called so many times for a skipped message, thus results a long list.
            //
            // We limit the number of `replayMessage` calls of each message, which may solve the above problem.
    
            
    
            ...
    
          
     
            // check message is skipped and drop it.
            // @note If the list is very long, the message may never be dropped.
            while (true) {
                IL1MessageQueue(_messageQueue).dropCrossDomainMessage(_lastIndex);
                _lastIndex = prevReplayIndex[_lastIndex]; 
                if (_lastIndex == 0) break;
                unchecked {
                    _lastIndex = _lastIndex - 1;
                }
            }
     
            isL1MessageDropped[_xDomainCalldataHash] = true;
    
            // set execution context
            xDomainMessageSender = Constants.DROP_XDOMAIN_MESSAGE_SENDER;
            IMessageDropCallback(_from).onDropMessage{value: _value}(_message);
            // clear execution context
            xDomainMessageSender = Constants.DEFAULT_XDOMAIN_MESSAGE_SENDER;
        }
    
    ```
    

#### Gas limit estimations

Every time a message is sent via the CrossDomainMessenger contract, a gas estimation is performed in order to verify wether the gas limit specified by the user is actually enough to properly execute the transaction on the destination chain. This is done inside the message queue's `appendCrossDomainMessage()` function, using the `_validateGasLimit()` internal function. The gas limit validation will be carried out via the following process:

1. Every time a message is sent, the queue's `appendCrossDomainMessage()` method is called to actually send the message:

```solidity
// File: L1CrossDomainMessenger.sol

function _sendMessage(
        address _to,
        uint256 _value,
        bytes memory _message,
        uint256 _gasLimit,
        address _refundAddress 
    ) internal nonReentrant {
        ...

        // append message to L1MessageQueue
        IL1MessageQueue(_messageQueue).appendCrossDomainMessage(_counterpart, _gasLimit, _xDomainCalldata);

        ...

    }

```

1. `appendCrossDomainMessage()` will call the `_validateGasLimit()` function, passing the gas limit specified by the user, together with the total `data` that must be sent to the destination. Among other checks, `_validateGasLimit()` will call the `calculateIntrinsicGasFee()` function, and a check will be performed to ensure that the gas limit passed by the user is equal or greater than the computed `intrinsicGas`:

```solidity
// File: L1MessageQueueWithGasPriceOracle.sol

function appendCrossDomainMessage(
        address _target,
        uint256 _gasLimit,
        bytes calldata _data
    ) external override onlyMessenger {
        // validate gas limit
        _validateGasLimit(_gasLimit, _data); 
   
        // do address alias to avoid replay attack in L2.
        address _sender = AddressAliasHelper.applyL1ToL2Alias(_msgSender());
   
        _queueTransaction(_sender, _target, 0, _gasLimit, _data); 
    }

    function _validateGasLimit(uint256 _gasLimit, bytes calldata _calldata) internal view {
        require(_gasLimit <= maxGasLimit, "Gas limit must not exceed maxGasLimit");
        // check if the gas limit is above intrinsic gas
        uint256 intrinsicGas = calculateIntrinsicGasFee(_calldata);
        require(_gasLimit >= intrinsicGas, "Insufficient gas limit, must be above intrinsic gas");
    }
```

1. `calculateIntrinsicGasFee()` will finally perform the estimation of the gas limit in order to deliver the message:

```solidity
// L1MessageQueueWithGasPriceOracle.sol

function calculateIntrinsicGasFee(bytes calldata _calldata) public pure virtual returns (uint256) { 
        // no way this can overflow `uint256`
        unchecked {
            return INTRINSIC_GAS_TX + _calldata.length * APPROPRIATE_INTRINSIC_GAS_PER_BYTE; 
        }
    }

```

As a summary, `calculateIntrinsicGasFee()` calculates the required gas limit by multiplying the total calldata length to be sent by the cost of sending each byte in the calldata (`APPROPRIATE_INTRINSIC_GAS_PER_BYTE`, which is hardcoded to 16, corresponding to the actual cost of a byte of calldata in Ethereum). Additionally,  the intrinsic gas cost of 21,000 units of gas to send a transaction in Ethereum is also added to the computation (as `INTRINSIC_GAS_TX`). 

The main concept to be aware of in this computation is that **the calculation only takes into account the cost of paying for the calldata, plus the 21,000 intrinsic gas cost for the external gas call**. This means that the actual amount of gas that will be consumed by the call on the destination chain is **NOT** accounted for when veryfing the gas limit. As a TLDR, this computation only ensures that the cost of sending a transaction plus delivering the calldata is enough, but it does not account for the actual cost that the transaction will consume when being executed (i.e, the cost of the opcodes and the logic executed inside the transaction).

#### The actual bug and root cause

The bug reported in this issue focuses on two main points in the implementation:

- **Limit on the amount of times a failed transaction can be replayed**: Because transactions can only be replayed up to `maxReplayTimes`, and the `replayMessage()` function is permissionless, a malicious user can trigger `replayMessage()` several times for any user's failed transactions, exhausting the amount of times the transaction can be replayed. Note that the user will not be able to drop the message unless it has failed due to being dropped on the destination (which will only occur for a specific subset of messages that have triggered a ciruit overflow).
- **Conservative estimation of gas limit**: Because the gas limit computation performed in `calculateIntrinsicGasFee()` is too conservative, it is possible for the attacker to replay the messages setting a gas limit that **is guaranteed to always make the message fail on the destination chain**. This is because, as shown before, `calculateIntrinsicGasFee()` only takes into account the cost of paying for the calldata.

The attack path section details how this can be leveraged to force user's funds to be stuck forever in the contract, as well as to completely DoS of the `replayMessage()` functionality in Morph.

### Internal pre-conditions

1. A user has sent a cross-layer transaction from the L1→L2.
2. The user has set an insufficient gas limit value, and the transaction on the L2 has failed due to an out of gas error.

### External pre-conditions

None.

### Attack Path

Because of this, the following scenario can take place:

1. A user wants to bridge some ETH from Ethereum to Morph. He calls the `depositETH()` function in the `L1ETHGateway` and 10 ETH are deposited into the protocol. `depositETH()` will then interact with the `L1CrossDomainMessenger` to send the L1->L2 cross-layer message. In this initial call (and due to the conservative gas estimations), the user sets a gas limit that is not enough to execute the message on the L2, so the message fails on the destination (note that this is a completely acceptable scenario, and as per the current implementation of Morph users should be able to replay their failed messages if situations like this occur).
2. A malicious user sees the failed transaction and calls `replayMessage()` up to `maxReplayTimes`. He sets the minimum possible gas limit in each replay call so that the function is guaranteed to fail on Morph (note that the gas limit is not required to be greater than the gas limit set in the original transaction, but only greater or equal to the gas cost estimated by `calculateIntrinsicGasFee()`). The transaction is guaranteed to fail on Morph due to the fact that, as mentioned in previous sections, the gas cost estimations are extremely conservative, and don’t account for the logic that will take place on the destination chain (they only account for the intrinsic gas costs + the cost of calldata).
3. As a result, the initial user can no longer replay the message because it has already been replayed up to `maxReplayTimes` by the malicious user. The replays have been guaranteed to fail due to the conservative nature of the current gas cost estimations, and the user can’t get the funds back by dropping the message because the `dropMessage()` functionality is only allowed for messages that are skipped (i.e messages that cause a circuit overflow), which is not the case as messages failing in the L2 due to a low gas limit are not skipped, and are actually considered valid transactions.

### Impact

As shown, the excessively conservative gas estimation in the gas limit computation, together with the limitation in the number of times a transaction can be replayed leads to two critical scenarios:

- The replay message functionality in the protocol can be effectively DoS'ed, as messages can always be replayed by anyone with a gas limit that is guaranteed to fail on the destination chain. This can lead to funds stuck on the L1. The amount will depend on each user’s transaction, but might vary from low amounts to huge amounts.
- User's funds that have already been transferred in a transaction that fails due to gas limit can be effectively locked forever in the contract, given that the replay functionality can be DoS'ed.

### PoC

_No response_

### Mitigation

For this scenario, it is recommended to always ensure that the caller of either the `replayMessage()` or `dropMessage()` functions is the actual `_from` address specified. If it is expected for Morph to also sometimes be able to replay or drop messages on behalf of users, an additional functionality that could be added to expand the flexibility of the functions would be to add an approvals mapping, so that users can approve who can replay/drop their messages.

In addition, I highly encourage the Morph team to explore how other cross-chain protocols apply mitigations to the core issues mentioned in this report.

- Optimism fixes the conservative gas limit estimation by adding extra values in the computation of the gas limit.
    - In their [`CrossDomainMessenger`'s `sendMessage()` function](https://github.com/ethereum-optimism/optimism/blob/d48b45954c381f75a13e61312da68d84e9b41418/packages/contracts-bedrock/src/universal/CrossDomainMessenger.sol#L176), gas limit is not only passed as the `_minGasLimit` parameter specified by the user, but an additional [baseGas](https://github.com/ethereum-optimism/optimism/blob/d48b45954c381f75a13e61312da68d84e9b41418/packages/contracts-bedrock/src/universal/CrossDomainMessenger.sol#L183) function is called in order to [account for additional gas that might be consumed on the destination chain](https://github.com/ethereum-optimism/optimism/blob/d48b45954c381f75a13e61312da68d84e9b41418/packages/contracts-bedrock/src/universal/CrossDomainMessenger.sol#L342-L359).

```solidity
// File: CrossDomainMessenger.sol (<https://github.com/ethereum-optimism/optimism/blob/d48b45954c381f75a13e61312da68d84e9b41418/packages/contracts-bedrock/src/universal/CrossDomainMessenger.sol#L342-L359>)
function baseGas(bytes calldata _message, uint32 _minGasLimit) public pure returns (uint64) {
        return
        // Constant overhead
        RELAY_CONSTANT_OVERHEAD
        // Calldata overhead
        + (uint64(_message.length) * MIN_GAS_CALLDATA_OVERHEAD)
        // Dynamic overhead (EIP-150)
        + ((_minGasLimit * MIN_GAS_DYNAMIC_OVERHEAD_NUMERATOR) / MIN_GAS_DYNAMIC_OVERHEAD_DENOMINATOR)
        // Gas reserved for the worst-case cost of 3/5 of the `CALL` opcode's dynamic gas
        // factors. (Conservative)
        + RELAY_CALL_OVERHEAD
        // Relay reserved gas (to ensure execution of `relayMessage` completes after the
        // subcontext finishes executing) (Conservative)
        + RELAY_RESERVED_GAS
        // Gas reserved for the execution between the `hasMinGas` check and the `CALL`
        // opcode. (Conservative)
        + RELAY_GAS_CHECK_BUFFER;
    }

```

- In Chainlink's CCIP, the gas limit specified by users when a transaction is replayed **[can't be smaller than the limit specified in the original cross-chain message](https://github.com/smartcontractkit/ccip/blob/ccip-develop/contracts/src/v0.8/ccip/offRamp/EVM2EVMOffRamp.sol#L246-L250)**. This prevents the issue where messages replayed can be set the same gas limit that made the original transaction to fail:

```solidity
// File: EVM2EVMOffRamp.sol (<https://github.com/smartcontractkit/ccip/blob/ccip-develop/contracts/src/v0.8/ccip/offRamp/EVM2EVMOffRamp.sol#L246-L250>)

function manuallyExecute(
    Internal.ExecutionReport memory report,
    GasLimitOverride[] memory gasLimitOverrides
  ) external {
    // We do this here because the other _execute path is already covered OCR2BaseXXX.
    ...
      // Checks to ensure message cannot be executed with less gas than specified.
      if (newLimit != 0) {
        if (newLimit < message.gasLimit) {
          revert InvalidManualExecutionGasLimit(message.messageId, message.gasLimit, newLimit);
        }
      }

}

```

In addition, neither Optimism nor CCIP limit the amount of times a message can be replayed. This prevents the bug described in this report from taking place.

# Issue H-4: `proveState()` can be frontrun, enabling malicious actors to steal sequencer's proof submission rewards 

Source: https://github.com/sherlock-audit/2024-08-morphl2-judging/issues/185 

## Found by 
PapaPitufo, Stiglitz, jasonxiale, sammy, underdog
### Summary

Because `proveState()` is permissionless, malicious actors can frontrun sequencers proving the correctness of a batch in order to steal the `challengeDeposit()`.

### Root Cause

Found in [Rollup.sol#L465](https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/l1/rollup/Rollup.sol#L465).

Morph incorporates a novel state verification process called Responsive Validity Proof (RVP). In this process, sequencers submit batches to the L1’s rollup contract. If a submitted batch is found to be incorrect, challengers can trigger `challengeState()` in order to start a challenge period, in which it is the sequencer’s responsibility to prove the correctness of the batch by submitting a ZK proof via the `proveState()` function in `Rollup.sol`.

As detailed in the [RVP is Friendly to Challengers section](https://docs.morphl2.io/docs/how-morph-works/optimistic-zkevm#rvp-is-friendly-to-challengers) the novel RVP process opens a potential attack vector. Quoting Morph’s documentation: 

- *“While there is a risk of challengers initiating unnecessary challenges to increase costs for sequencers, RVP mitigates this by requiring challengers to compensate sequencers for the costs incurred if a challenge is unsuccessful.”*
- *“This mechanism discourages frivolous challenges and ensures that only legitimate disputes are raised.”*

Essentially, when a batch is challenged, generating a proof to prove the correctness of the batch will incur computational costs that need to be handled by the sequencer that submitted the batch. Malicious challengers could then always challenge batches (even if they’re correct) to force sequencers to waste money and resources to generate the proof. In order to mitigate this, challengers are required to deposit a minimum `challengeDeposit()` when initiating a challenge:

```solidity
// File: Rollup.sol

function challengeState(uint64 batchIndex) external payable onlyChallenger nonReqRevert whenNotPaused { 
        ...
        // check challenge amount
        require(msg.value >= IL1Staking(l1StakingContract).challengeDeposit(), "insufficient value");

        ...
    }
```

Then, if the `proveState()` function is triggered with a valid proof proving the correctness of the batch, the defender will win and the `challengeDeposit()` will be

```solidity
// File: Rollup.sol
function proveState(
        bytes calldata _batchHeader,
        bytes calldata _aggrProof,
        bytes calldata _kzgDataProof
    ) external nonReqRevert whenNotPaused {
        ...

        // Check for timeout 
        if (challenges[_batchIndex].startTime + proofWindow <= block.timestamp) { 
            ...
        } else {
            _verifyProof(memPtr, _aggrProof, _kzgDataProof); 
            // Record defender win
            _defenderWin(_batchIndex, _msgSender(), "Proof success");
        }
    }
    
    function _defenderWin(uint256 batchIndex, address prover, string memory _type) internal {
        uint256 challengeDeposit = challenges[batchIndex].challengeDeposit;
        batchChallengeReward[prover] += challengeDeposit;
        emit ChallengeRes(batchIndex, prover, _type);
    }
```

It is important to note how the call to `_defenderWin()` passes `_msgSender()` as the `prover`, which is the address that will obtain the `challengeDeposit`.

As shown in the code snippet, there is no access control in `proveState()`, so it is possible for a malicious actor to frontrun sequencers that want to prove the correctness of a batch (and which have wasted money and resources to generate such proof) in order to obtain the `challengeDeposit`. It is then possible for anyone to steal challenge deposits every time a batch is proven to be correct, leading to a loss of funds for the sequencer that has generated the proof.

### Internal pre-conditions

1. A batch is challenged. The batch is correct.
2. The sequencer that submitted the batch has generated the proof that proves the correctness of the batch, and has triggered a call to `proveState()` to submit the proof.

### External pre-conditions

None.

### Attack Path

1. A sequencer submits a batch via `commitBatch()`.
2. A challenger then challenges the batch by calling `challengeState()`, and deposits the minimum `challengeDeposit`.
3. The sequencer generates the proof for the batch. When generated, it calls `proveState()`.
4. A malicious actor is monitoring calls to `proveState()`, and frontruns the sequencer. He calls `proveState()` with the exact same parameters triggered by the sequencer.
5. Due to the lack of access control in `proveState()`, the malicious’ actor call is first executed. The parameters (`_batchHeader`, `_aggrProof` and `_kzgDataProof`) are correct and prove the batch’s correctness, so a call to `_defenderWin()` is triggered, passing the address of the malicious actor as the `prover`.
6. The malicious actor obtains the challenge deposit, effectively stealing it from the sequencer.

Note that this bug also essentially enables malicious challengers to always challenge batches at no cost. If the malicious challengers act as the malicious actor frontrunning the call to `proveState()`, it is basically free (excluding gas costs) for malicious challengers to always challenge batches, affecting the proper functioning of Morph, given that data availability can be effectively delayed, and bypassing the expected behavior of the system for the vulnerability described in [Morph documentation](https://docs.morphl2.io/docs/how-morph-works/optimistic-zkevm#rvp-is-friendly-to-challengers).

### Impact

The sequencers can always lose the `challengeDeposit()` entitled to them in order to compensate them for the costs of generating the zero knowledge proof to prove the correctness of the batch. Moreover, there is essentially no cost for challengers to challenge correct batches and affect the proper behavior of the network.

### PoC

_No response_

### Mitigation

In order to mitigate this issue, ensure that proofs can only be submitted by the sequencer that submitted the batch. For this, the sequencer should be stored when committing a batch, given that as per the documentation the expected design of the system wants to reward the sequencer generating the proof. Another possible option is to allow any active sequencer to submit the proof, if any sequencer is expected to prove the correctness of batches:

```diff
// File: Rollup.sol

function proveState(
        bytes calldata _batchHeader,
        bytes calldata _aggrProof,
        bytes calldata _kzgDataProof
    ) external nonReqRevert whenNotPaused {
        ...

        // Check for timeout 
        if (challenges[_batchIndex].startTime + proofWindow <= block.timestamp) { 
            ...
        } else {
+          require(IL1Staking(l1StakingContract).isActiveStaker(_msgSender()), "only active staker allowed");
            _verifyProof(memPtr, _aggrProof, _kzgDataProof); 
            // Record defender win
            _defenderWin(_batchIndex, _msgSender(), "Proof success");
        }
    }
```



## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/morph-l2/morph/pull/563


# Issue M-1: `Rollup.sol` cannot split batches across blobs, allowing inexpensive block stuffing 

Source: https://github.com/sherlock-audit/2024-08-morphl2-judging/issues/91 

The protocol has acknowledged this issue.

## Found by 
PapaPitufo
### Summary

The maximum amount of calldata that can be passed to an L2 transaction is too large to fit in a single blob. Because `Rollup.sol` does not allow splitting batches across blobs, L2 blocks are capped by their calldata size. This is not properly accounted for in the L2 gas prices, and leads to an attack where blocks can be inexpensively stuffed, blocking all L2 transactions on the chain.

### Root Cause

Batches are expected to commit to many blocks. We can expect up to 100 blocks per chunk (`MaxBlocksPerChunk` in node/types/chunk.go), and 45 chunks per batch (`maxChunks` in Gov.sol). This means that a batch can commit to 4500 blocks.

However, `Rollup.sol` has the surprising quirk that a full batch must fit into a single blob. For that reason, the batch is not just limited based on blocks, but also by calldata. We can see this logic in [miner/pipeline.go#L260-266](https://github.com/morph-l2/go-ethereum/blob/e58ac01d16da31d9ca25a5e7e0e09bfdd352e76b/miner/pipeline.go#L260-L266), where the block size is being tracked, and we skip all transactions that push it over the limit for the blob.

In the event that a user submits a single transaction with enough calldata to fill a whole blob, this transaction will end the block, and the entire batch will consist of the single block with one transaction.

This has two important implications:

First, the gas cost of stuffing an entire block is loosely the price of sending 128kb of calldata. For a transaction with no execution or value, we can calculate the L2 gas cost as `intrinsic gas + calldata + l1DataFee`.

If we assume an l1BaseFee of 30 gwei, an l1BlobBaseFee of 1, and the scalar and l2BaseFee values from the [config file](https://docs.google.com/spreadsheets/d/1KDQ8LkB53yw7f0m8a0LCTIdyiANjKyqC-sKUQEQGSf8/edit?gid=0#gid=0), we get:
- `intrinsic gas = 21_000 gas = 21 gwei`
- `calldata = 1024 * 128 * (4 + 16) / 2 = 1,310,720 gas = 1,310 gwei` (assumes half non-zero bytes to avoid compression)
- `l1DataFee = (1024 * 128 * 1 * 0.4) + (230 * 30)= 59,328 gwei`
- `total cost = 21 + 1,310 + 59,328 = 60,659 gwei = $0.14`

Second, and more importantly, block stuffing is usually protected by EIP1559 style gas pricing, where the base fee increases dramatically if sequential blocks are full. However, this block stuffing attack has the strange quirk that only 1.3mm gas (out of 30mm gas limit) will be used, which will actually lower the base fee over time.

### Internal Preconditions

None

### External Preconditions

None

### Attack Path

1. Submit a large number of transactions on L2 that use 128kb of calldata.
2. Each time one is picked up (which should be each block), it costs only 1.3mm gas, but seals the block with no other L2 transactions.

### Impact

L2 blocks will be stuffed and most activity on L2 will be blocked. This can cause major and unpredictable issues, such as oracles getting out of date, liquidations not occurring on time, and users being unable to take other important actions.

### PoC

N/A

### Mitigation

The architecture should be changed so that batches can be split across multiple blobs if needed.


# Issue M-2: Possible wrong accounting in L1Staking.sol 

Source: https://github.com/sherlock-audit/2024-08-morphl2-judging/issues/104 

The protocol has acknowledged this issue.

## Found by 
0xRajkumar, PASCAL, PapaPitufo, n4nika
## Summary
Possible wrong accounting in L1Staking.sol during some slashing occasions.

## Vulnerability Detail
Stakers are permitted to commit batches in the rollup contract and these batches can be challenged by challengers, if the challenge is successful the challenger gets part of the stakers ETH and staker is removed, the owner also takes the rest; if it wasn't succesful the prover takes all the challengeDeposit from the challenger. According to the readMe https://github.com/sherlock-audit/2024-08-morphl2-Pascal4me#q-are-there-any-limitations-on-values-set-by-admins-or-other-roles-in-the-codebase-including-restrictions-on-array-lengths  `proofWindow` which is the time a challenged batch has to go without being proven for it to be successfully challenged can be set to as high as 604800 seconds which is 7 days and `withdrawalLockBlocks` default value is also 7 days(No relation between the two was done and owner can change `proofWindow` value in rollup contract). For this vulnerability we'll assume  `proofWindow`  is set to 7 days. The issue stems from a staker being able to commit a wrong batch and still being able to withdraw from the staking contract without that batch being finalized or proven.
Let's site this example with `proofWindow`  being set to 7 days
- Alice a staker commits a wrong batch and immediately goes ahead to withdraw her ETH from the staking contract, her 7 days period countdown start 
- Bob a challenger sees that wrong batch and challenges it and it since it's a wrong batch theres no proof for it, then 7 days couuntdown starts. 
    But remember the withdraw function 7 days started counting first so when it elapses Alice quickly goes ahead to withdraw her ETH, then when Bob calls `proveState()`, Alice is supposedly slashed but it's useless as she's already left the system. Then the contract is updated as though Alice's ETH is still in the contract 

`   uint256 reward = (valueSum * rewardPercentage) / 100;
        slashRemaining += valueSum - reward;
        _transfer(rollupContract, reward);  `


So a current staker's ETH is the one being sent to the rollup contract and being assigned to the owner via `slashRemaining`. So there's less ETH than the contract is accounting for which already an issue. This will be detrimental when all the ETH is being withdrawn by stakers and owner the last person transaction will revert becuase that ETH is not in the contract.

## Impact
Incorrect contract accounting 

## Code Snippet
https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/l1/staking/L1Staking.sol#L197-L201
https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/l1/rollup/Rollup.sol#L484-L487
https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/l1/rollup/Rollup.sol#L697-L707
https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/l1/staking/L1Staking.sol#L307-L311
https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/l1/staking/L1Staking.sol#L217-L237

## Tool used

Manual Review

## Recommendation
Ensure stakers can't withdraw if they have a batch that is unfinalized or unproven and always ensure that withdraw time block is > `proofWindow`

# Issue M-3: The 255th staker in `L1Staking.sol` can avoid getting slashed and inadvertently cause fund loss to stakers 

Source: https://github.com/sherlock-audit/2024-08-morphl2-judging/issues/142 

## Found by 
0xRajkumar, p0wd3r, sammy, zraxx
## Summary
The 255th staker in `L1Staking.sol` can avoid getting slashed and inadvertently cause fund loss to stakers
## Vulnerability Detail
The `L1Staking.sol` contract supports upto 255 stakers :

```solidity
    /// @notice all stakers (0-254)
    address[255] public stakerSet;

    /// @notice all stakers indexes (1-255). '0' means not exist. stakerIndexes[1] releated to stakerSet[0]
    mapping(address stakerAddr => uint8 index) public stakerIndexes;
```
Everytime a staker registers in `L1Staking.sol` they are added to the `stakerSet` and their index is stored in `stakerIndexes` as `index+1`

These stakers, while active, can commit batches in `Rollup.sol` using `commitBatch()` and the `batchDataStore[]` mapping is updated as follows :

```solidity
            batchDataStore[_batchIndex] = BatchData(
                block.timestamp,
                block.timestamp + finalizationPeriodSeconds,
                _loadL2BlockNumber(batchDataInput.chunks[_chunksLength - 1]),
                // Before BLS is implemented, the accuracy of the sequencer set uploaded by rollup cannot be guaranteed.
                // Therefore, if the batch is successfully challenged, only the submitter will be punished.
                IL1Staking(l1StakingContract).getStakerBitmap(_msgSender()) // => batchSignature.signedSequencersBitmap
            );
```
On a successful challenge, the `_challengerWin()` function is called, and here the `sequencersBitmap` is the one that was stored in `batchDataStore[]`
```solidity
    function _challengerWin(uint256 batchIndex, uint256 sequencersBitmap, string memory _type) internal {
        revertReqIndex = batchIndex;
        address challenger = challenges[batchIndex].challenger;
        uint256 reward = IL1Staking(l1StakingContract).slash(sequencersBitmap);
        batchChallengeReward[challenges[batchIndex].challenger] += (challenges[batchIndex].challengeDeposit + reward);
        emit ChallengeRes(batchIndex, challenger, _type);
    }
```

This function calls the `slash()` function in `L1Staking.sol` :

```solidity
    function slash(uint256 sequencersBitmap) external onlyRollupContract nonReentrant returns (uint256) {
        address[] memory sequencers = getStakersFromBitmap(sequencersBitmap);

        uint256 valueSum;
        for (uint256 i = 0; i < sequencers.length; i++) {
            if (withdrawals[sequencers[i]] > 0) {
                delete withdrawals[sequencers[i]];
                valueSum += stakingValue;
            } else if (!isStakerInDeleteList(sequencers[i])) {
                // If it is the first time to be slashed
                valueSum += stakingValue;
                _removeStaker(sequencers[i]);
                // remove from whitelist
                delete whitelist[sequencers[i]];
                removedList[sequencers[i]] = true;
            }
        }

        uint256 reward = (valueSum * rewardPercentage) / 100;
        slashRemaining += valueSum - reward;
        _transfer(rollupContract, reward);

        emit Slashed(sequencers);
        emit StakersRemoved(sequencers);

        // send message to remove stakers on l2
        _msgRemoveStakers(sequencers);

        return reward;
    }
```

The function converts the `sequencersBitmap` into an array by calling [`getStakersFromBitmap()`](https://github.com/sherlock-audit/2024-08-morphl2/blob/98e0ec4c5bbd0b28f3d3a9e9159d1184bc45b38d/morph/contracts/contracts/l1/staking/L1Staking.sol#L406) :

```solidity
    function getStakersFromBitmap(uint256 bitmap) public view returns (address[] memory stakerAddrs) {
        // skip first bit
        uint256 _bitmap = bitmap >> 1;
        uint256 stakersLength = 0;
        while (_bitmap > 0) {
            stakersLength = stakersLength + 1;
            _bitmap = _bitmap & (_bitmap - 1);
        }

        stakerAddrs = new address[](stakersLength);
        uint256 index = 0;
        for (uint8 i = 1; i < 255; i++) {
            if ((bitmap & (1 << i)) > 0) {
                stakerAddrs[index] = stakerSet[i - 1];
                index = index + 1;
                if (index >= stakersLength) {
                    break;
                }
            }
        }
    }
```

Since `bitmap` will only contain 1 staker's bit, the `stakersLength` here will be 1. The loop then checks every single bit of the bitmap to see if it's active. Notice, however, that `i` only goes up to 254, and 255 is skipped. This means that for the 255th staker having index of `254`, the array will contain `address(0)`.

This means that in `slash()`, this code will be execued :

```solidity
else if (!isStakerInDeleteList(sequencers[i])) {
                // If it is the first time to be slashed
                valueSum += stakingValue;
                _removeStaker(sequencers[i]);
                // remove from whitelist
                delete whitelist[sequencers[i]];
                removedList[sequencers[i]] = true;
            }
```
`_removeStaker()` is called with `addr = address(0)`:

```solidity 
    function _removeStaker(address addr) internal {
        require(deleteableHeight[addr] == 0, "already in deleteList");
        deleteList.push(addr);
        deleteableHeight[addr] = block.number + withdrawalLockBlocks;
    }
```

This means that the staker avoids being removed and the intended state changes are made to `address(0)` instead. The staker can continue committing invalid batches to the Rollup and not get slashed. Additionally, the `stakingValue` is still rewarded to the challenger, while the staker isn't actually removed from the protocol. Over time, the ETH of `L1Staking.sol` will run out and it won't be possible for stakers to withdraw or for them to get slashed.

## Impact
Critical - loss of funds and breaks protocol functionality


## Coded POC
```solidity
    function test_poc_255() external{
         address[] memory add = new address[](255);

         for(uint256 i = 0 ; i < 255 ; i++)
         {
            add[i] = address(bytes20(bytes32(keccak256(abi.encodePacked(1500 + i)))));
         }

        hevm.prank(multisig);
        l1Staking.updateWhitelist(add, new address[](0));

        // register all the 255 stakers
        for(uint256 i = 0 ; i < 255 ; i++)
         {
        Types.StakerInfo memory info;
        info.tmKey = bytes32(i+1);
        bytes memory blsKey = new bytes(256);
        blsKey[31] = bytes1(uint8(i)); 
        info.blsKey = blsKey;
        assert(info.blsKey.length == 256);
        hevm.deal(add[i], 5 * STAKING_VALUE);
        hevm.prank(add[i]);
        l1Staking.register{value: STAKING_VALUE}(info.tmKey, info.blsKey);
         }
        
        assertEq(add.length, 255);
        address[] memory arr = new address[](1);
        arr[0] = add[254];
         uint256 _bitmap = l1Staking.getStakersBitmap(arr); // this bitmap will contain the 255th staker only
        address[] memory stakers = l1Staking.getStakersFromBitmap(_bitmap);

        // as you can see the array is {address(0)}
        assertEq(stakers[0], address(0));

        // simulate the challenger win flow
        hevm.prank(l1Staking.rollupContract());
        uint256 balanceBefore = address(l1Staking).balance;
        uint256 reward = l1Staking.slash(_bitmap);    
        uint256 balanceAfter = address(l1Staking).balance;

        // the contract loses "reward" amount of ETH
        assertEq(balanceBefore, balanceAfter + reward);
        
        // the 255th staker still remains an active staker
        assert(l1Staking.isActiveStaker(arr[0]) == true);
}
```

To run the test, copy the above in `L1Staking.t.sol` and run `forge test --match-test "test_poc_255"`
## Code Snippet

## Tool used

Manual Review

## Recommendation

Make the following change :

```diff
-        for (uint8 i = 1; i < 255; i++) {
+        for (uint8 i = 1; i <= 255; i++) {
```



## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/morph-l2/morph/pull/562


# Issue M-4: Batches committed during an on going challenge can avoid being challenged 

Source: https://github.com/sherlock-audit/2024-08-morphl2-judging/issues/143 

## Found by 
PapaPitufo, sammy
 NOTE : This finding is not the same as Known issue # 10, that is about an invalid batch getting finalized due to `challengeState()` reverting (OOG error)

## Summary
Batches committed during an ongoing challenge can avoid being challenged and pre-maturely finalize if the defender wins

## Vulnerability Detail

After a batch is committed, there is a finalization window, in which challengers can challenge the batch's validity, after the period has elapsed, the batch can be finalized.

A batch can be challenged using `challengeState()` :

```solidity
    function challengeState(uint64 batchIndex) external payable onlyChallenger nonReqRevert whenNotPaused {
        require(!inChallenge, "already in challenge");
        require(lastFinalizedBatchIndex < batchIndex, "batch already finalized");
        require(committedBatches[batchIndex] != 0, "batch not exist");
        require(challenges[batchIndex].challenger == address(0), "batch already challenged");
        // check challenge window
        require(batchInsideChallengeWindow(batchIndex), "cannot challenge batch outside the challenge window");
        // check challenge amount
        require(msg.value >= IL1Staking(l1StakingContract).challengeDeposit(), "insufficient value");

        batchChallenged = batchIndex;
        challenges[batchIndex] = BatchChallenge(batchIndex, _msgSender(), msg.value, block.timestamp, false, false);
        emit ChallengeState(batchIndex, _msgSender(), msg.value);

        for (uint256 i = lastFinalizedBatchIndex + 1; i <= lastCommittedBatchIndex; i++) {
            if (i != batchIndex) {
                batchDataStore[i].finalizeTimestamp += proofWindow;
            }
        }

        inChallenge = true;
    }
```

As you can see, the function loops through all the unfinalized batches, except the batch being challenged and adds a `proofWindow` to their finalization timestamp. This is to compensate for the amount of time these batches cannot be challenged, which is the duration of the current challenge, i.e, `proofWindow` (only one batch can be challenged at a time).

However, [`commitBatch()`](https://github.com/sherlock-audit/2024-08-morphl2/blob/98e0ec4c5bbd0b28f3d3a9e9159d1184bc45b38d/morph/contracts/contracts/l1/rollup/Rollup.sol#L201) allows batches to get committed even when a challenge is going on and does not compensate for time spent inside the challenge :

```solidity
            batchDataStore[_batchIndex] = BatchData(
                block.timestamp,
                block.timestamp + finalizationPeriodSeconds, 
                _loadL2BlockNumber(batchDataInput.chunks[_chunksLength - 1]),
                // Before BLS is implemented, the accuracy of the sequencer set uploaded by rollup cannot be guaranteed.
                // Therefore, if the batch is successfully challenged, only the submitter will be punished.
                IL1Staking(l1StakingContract).getStakerBitmap(_msgSender()) // => batchSignature.signedSequencersBitmap
            );
```

As you can see, the new batch can be finalized after `finalizationPeriodSeconds`.

Currently the value of `finalizationPeriodSeconds` is `86400`, i.e, `1 Day` and `proofWindow` is `172800`, i.e, `2 Days`
[Source](https://docs.google.com/spreadsheets/d/1KDQ8LkB53yw7f0m8a0LCTIdyiANjKyqC-sKUQEQGSf8/edit?gid=0#gid=0). This means that a batch committed just after the start of a challenge will be ready to be finalized in just 1 day, before the ongoing challenge even ends.

Now, consider the following scenario :

- A batch is finalized 
- A challenger challenges this batch, challenge will end 2 days from the start
- A staker commits a new batch
- After 1 day, this new batch is ready to be finalized, but can't be finalized yet as the parent batch (the challenged batch) needs to be finalized first
- After 1.5 days, the original batch finishes its challenge, the defender wins(by providing a valid ZK proof), and the batch is ready to be finalized
- Right after the original batch is finalized, the new batch is finalized

This leaves no time for a challenger to challenge the new batch, and this can lead to invalid batches getting committed, even if the batch committer (sequencer) doesn't act maliciously.

Since `finalizeBatch()` is permissionless and only checks whether a batch is in the finalization window, anyone can batch the two `finalizeBatch()` calls which finalize both the original batch and the invalid batch, right after the challenge ends (by back running `proveState()`), leaving no time for a challenger to call `challengeState()`

If a sequencer is malicious, they can easily exploit this to commit invalid batches
## Impact
Critical - Can brick the entire Morph L2 protocol
## Code Snippet

## Tool used

Manual Review

## Recommendation
You can make the following change, which correctly compensates for the lost finalization time:

```diff
            batchDataStore[_batchIndex] = BatchData(
                block.timestamp,
-                block.timestamp + finalizationPeriodSeconds, 
+                 block.timestamp + finalizationPeriodSeconds + (inChallenge ? proofWindow - (block.timestamp - challenges[batchChallenged].startTime) : 0),
                _loadL2BlockNumber(batchDataInput.chunks[_chunksLength - 1]),
                // Before BLS is implemented, the accuracy of the sequencer set uploaded by rollup cannot be guaranteed.
                // Therefore, if the batch is successfully challenged, only the submitter will be punished.
                IL1Staking(l1StakingContract).getStakerBitmap(_msgSender()) // => batchSignature.signedSequencersBitmap
            );
```



## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/morph-l2/morph/pull/577


# Issue M-5: A batch can be unintentionally be challenged during L1 reorg leading to loss of funds 

Source: https://github.com/sherlock-audit/2024-08-morphl2-judging/issues/146 

## Found by 
HaxSecurity, PASCAL, PapaPitufo, sammy
### Summary

A batch can be unintentionally be challenged during L1 reorg leading to loss of funds

### Root Cause

The incorrect batch can be challenged during L1 reorg leading to loss of funds. Firstly the README states:

>  But if there is any issue about Ethereum L1 re-org leading to financial loss, that issue is valid.

In the `challengeBatch` function, the batch that is challenged is referenced by the `batchIndex`.

[Rollup.sol#L366-L388](https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/l1/rollup/Rollup.sol#L366-L388)
```solidity
    /// @dev challengeState challenges a batch by submitting a deposit.
    function challengeState(uint64 batchIndex) external payable onlyChallenger nonReqRevert whenNotPaused {
        require(!inChallenge, "already in challenge");
        require(lastFinalizedBatchIndex < batchIndex, "batch already finalized");
        require(committedBatches[batchIndex] != 0, "batch not exist");
        require(challenges[batchIndex].challenger == address(0), "batch already challenged");
        // check challenge window
        require(batchInsideChallengeWindow(batchIndex), "cannot challenge batch outside the challenge window");
        // check challenge amount
        require(msg.value >= IL1Staking(l1StakingContract).challengeDeposit(), "insufficient value");

        batchChallenged = batchIndex;
        challenges[batchIndex] = BatchChallenge(batchIndex, _msgSender(), msg.value, block.timestamp, false, false);
        emit ChallengeState(batchIndex, _msgSender(), msg.value);

        for (uint256 i = lastFinalizedBatchIndex + 1; i <= lastCommittedBatchIndex; i++) {
            if (i != batchIndex) {
                batchDataStore[i].finalizeTimestamp += proofWindow;
            }
        }

        inChallenge = true;
    }
```
However, this poses a problem because a reorg can cause the batch present in the `committedBatches[batchIndex]` to change and the challenger unintentionally challenging the incorrect batch, losing the challenge and their ETH.

For instance, consider the scenario where the sequencers upload two different batches at the same `batchIndex`, a correct batch and an incorrect batch. The initial transaction ordering is:

1. Transaction to upload a incorrect batch at `batchIndex = x`
2. Transaction to upload a correct batch (it will revert, as it is already occupied) at `batchIndex = x`
3. Challenger calls `challengeState` at `batchIndex = x`.

An L1 reorg occurs, resulting in the new transaction ordering

1. Transaction to upload a correct batch (it will revert, as it is already occupied) at `batchIndex = x`
2. Transaction to upload a incorrect batch at `batchIndex = x`
3. Challenger calls `challengeState` at `batchIndex = x`.

Due to the L1 reorg, the challenger will now be challenging a correct batch and will proceed to lose their challenge stake as it can be proven by the sequencer.

This issue is really similar to the Optimism reorg finding: https://github.com/sherlock-audit/2024-02-optimism-2024-judging/issues/201, where the incorrect state root can also be challenged leading to loss of bonds.

### Internal pre-conditions

1. L1 reorg


### External pre-conditions

n/a

### Attack Path

n/a

### Impact

A batch can be unintentionally challenged leading to loss of funds for the challenger

### PoC

_No response_

### Mitigation

In the `challengeState` function, allow loading the `batchHeader` and verifying that the `committedBatches[_batchIndex]` is equal to the `_batchHash` as is done in the other functions such as `revertBatch`
```diff
   /// @dev challengeState challenges a batch by submitting a deposit.
-    function challengeState(uint64 batchIndex) external payable onlyChallenger nonReqRevert whenNotPaused {
+    function challengeState(bytes calldata _batchHeader) external payable onlyChallenger nonReqRevert whenNotPaused {
        require(!inChallenge, "already in challenge");

+       (uint256 memPtr, bytes32 _batchHash) = _loadBatchHeader(_batchHeader);
+       // check batch hash
+       uint256 _batchIndex = BatchHeaderCodecV0.getBatchIndex(memPtr);
+       require(committedBatches[_batchIndex] == _batchHash, "incorrect batch hash");

        require(lastFinalizedBatchIndex < batchIndex, "batch already finalized");
        require(committedBatches[batchIndex] != 0, "batch not exist");
        require(challenges[batchIndex].challenger == address(0), "batch already challenged");

        // check challenge window
        require(batchInsideChallengeWindow(batchIndex), "cannot challenge batch outside the challenge window");
        // check challenge amount
        require(msg.value >= IL1Staking(l1StakingContract).challengeDeposit(), "insufficient value");

        batchChallenged = batchIndex;
        challenges[batchIndex] = BatchChallenge(batchIndex, _msgSender(), msg.value, block.timestamp, false, false);
        emit ChallengeState(batchIndex, _msgSender(), msg.value);

        for (uint256 i = lastFinalizedBatchIndex + 1; i <= lastCommittedBatchIndex; i++) {
            if (i != batchIndex) {
                batchDataStore[i].finalizeTimestamp += proofWindow;
            }
        }

        inChallenge = true;
    }
```




## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/morph-l2/morph/pull/558


# Issue M-6: Delegators can lose their rewards when a delegator has removed a delegatee and claims all of his rewards before delegating again to a previous removed delegatee. 

Source: https://github.com/sherlock-audit/2024-08-morphl2-judging/issues/157 

## Found by 
0xStalin
### Summary

The lose of funds is the result of two bugs, which are:

1. The first bug occurs when **a delegator claims all his rewards after he removed one or more delegatees.**
This first bug is about the logic implemented to [claim all the delegator's rewards](https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/l2/staking/Distribute.sol#L206-L214). When claiming all the rewards after a delegator has removed a delegatee, the undelegated delegatee is removed from the AddressSet of delegatees. 
- The problem is that [when a delegatee is removed](https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/l2/staking/Distribute.sol#L372-L373), the length of the AddressSet is reduced, which it affects the total number of delegatees that will be iterated to claim the rewards. As the AddressSet shrinks, the `i` variable controlling the iterations of the for loop grows, which at some point, `i` will be equals to the new length of the shrinked AddressSet, causing the for to exit the iteration and leaving some delegatees without claiming their rewards.
```solidity
function claimAll(address delegator, uint256 targetEpochIndex) external onlyL2StakingContract {
    ...
    //@audit-issue => `i` grows in each iteration while the delegatees AddressSet shrinks each time an undelegated delegatee is foud!
    for (uint256 i = 0; i < unclaimed[delegator].delegatees.length(); i++) {
        address delegatee = unclaimed[delegator].delegatees.at(i);
        if (
            unclaimed[delegator].delegatees.contains(delegatee) &&
            unclaimed[delegator].unclaimedStart[delegatee] <= endEpochIndex
        ) {
            ///@audit => If the delegator has unclaimed the delegatee at an epoch < endEpochIndex, the delegatee will be removed from the delegatees AddressSet
              //@audit-issue => Removing the delegatee from the AddressSet causes the Set to shrink!
            reward += _claim(delegatee, delegator, endEpochIndex);
        }
    }
    ...
}

function _claim(address delegatee, address delegator, uint256 endEpochIndex) internal returns (uint256 reward) {
    ...

    for (uint256 i = unclaimed[delegator].unclaimedStart[delegatee]; i <= endEpochIndex; i++) {
        ...

        // if undelegated, remove delegator unclaimed info after claimed all
        if (unclaimed[delegator].undelegated[delegatee] && unclaimed[delegator].unclaimedEnd[delegatee] == i) {
            //@audit-issue => Removing the delegatee from the AddressSet causes the Set to shrink!
            unclaimed[delegator].delegatees.remove(delegatee);
            delete unclaimed[delegator].undelegated[delegatee];
            delete unclaimed[delegator].unclaimedStart[delegatee];
            delete unclaimed[delegator].unclaimedEnd[delegatee];
            break;
        }
    }
    ...
}
```

Find below a simple PoC where it is demonstrated this bug. It basically adds and undelegates some delegatees to one delegator, then, the delegator claims all of his rewards, and, because the delegator has some undelegated delegatees, the bug will occur causing the function to not claim the rewards of all the delegatees.
- Create a new file on the [test/ folder](https://github.com/sherlock-audit/2024-08-morphl2-stalinMacias/tree/main/morph/contracts/contracts/test) and add the below code in it:
```solidity
pragma solidity ^0.8.13;

import {EnumerableSetUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol";

import {Test, console2} from "forge-std/Test.sol";

contract SimpleDelegations {

  using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;

  struct Unclaimed {
      EnumerableSetUpgradeable.AddressSet delegatees;
      mapping(address delegator => bool undelegated) undelegated;
      // mapping(address delegator => uint256 startEpoch) unclaimedStart;
      // mapping(address delegator => uint256 endEpoch) unclaimedEnd;
  }

  mapping(address delegator => Unclaimed) private unclaimed;

  function addDelegatee(address delegatee) external {
    unclaimed[msg.sender].delegatees.add(delegatee);
  }
  
  function undelegate(address delegatee) external {
    unclaimed[msg.sender].undelegated[delegatee] = true;
  }

  //@audit-issue => Existing logic that causes to not claim all the delegatees
  //@audit-issue => The problem is that when there are undelegated delegatees, they will be removed from the delegator in the `_claim()`, which makes the `unclaimed.delegatees` AddressSet lenght to shrink, which unintentionally causes the for loop to do less iterations than the original amount of delegatees at the begining of the call!
  function claimAll() external returns (uint256 reward) {
    for (uint256 i = 0; i < unclaimed[msg.sender].delegatees.length(); i++) {
      console2.log("delegatees.lenght: ", unclaimed[msg.sender].delegatees.length());
      address delegatee = unclaimed[msg.sender].delegatees.at(i);
      // console2.log("i: ", i);
      console2.log("delegatee: ", delegatee);
      if (
          unclaimed[msg.sender].delegatees.contains(delegatee)
          // unclaimed[delegator].unclaimedStart[delegatee] <= endEpochIndex
      ) {
          reward += _claim(delegatee, msg.sender);
      }

    }
  }

  //@audit-recommendation => This would be the fix for the first bug!
  // function claimAll() external returns (uint256 reward) {
  //   uint256 totalDelegatees = unclaimed[msg.sender].delegatees.length();
  //   address[] memory delegatees = new address[](totalDelegatees);

  //   //@audit => Make a temporal copy of the current delegates of the delegator
  //   for (uint256 i = 0; i < unclaimed[msg.sender].delegatees.length(); i++) {
  //       delegatees[i] = unclaimed[msg.sender].delegatees.at(i);
  //   }

  //   //@audit => Iterate over the temporal copy, in this way, if a delegatee is removed from the AddressSet, the for loop will still iterate over all the delegatees at the start of the call!
  //   for (uint256 i = 0; i < delegatees.length; i++) {
  //     // console2.log("delegatee: ", delegatees[i]);
  //     if (
  //         unclaimed[msg.sender].delegatees.contains(delegatees[i])
  //         // unclaimed[delegator].unclaimedStart[delegatees[i]] <= endEpochIndex
  //     ) {
  //         reward += _claim(delegatees[i], msg.sender);
  //     }
  //   }
  // }

  function _claim(address delegatee, address delegator) internal returns(uint256 reward) {
    require(unclaimed[delegator].delegatees.contains(delegatee), "no remaining reward");
    
    reward = 10;

    //@audit-issue => Removes an undelegated delegatee from the delegator's delegatees!
    if (unclaimed[delegator].undelegated[delegatee]) {
      //@audit-issue => The `unclaimed[delegator].delegatees.length()` shrinks, causing the for loop to not iterate over all the delegatees!
      unclaimed[delegator].delegatees.remove(delegatee);
      delete unclaimed[delegator].undelegated[delegatee];
    }
  }

  function getDelegatees() external view returns (address[] memory) {
    return unclaimed[msg.sender].delegatees.values();
  }
}

contract BugWhenClaimingAllRewards is Test {
  function test_claimingAllRewardsReproducingBug() public {
    SimpleDelegations delegations = new SimpleDelegations();

    delegations.addDelegatee(address(1));
    delegations.addDelegatee(address(2));
    delegations.addDelegatee(address(3));

    delegations.undelegate(address(1));
    delegations.undelegate(address(3));

    //@audit => Should claim 30 of rewards! There are 3 delegatees and each delegatee gives 10 of rewards
    uint256 rewards = delegations.claimAll();
    console2.log("Total rewards: ", rewards);

    console2.log("delegatees list after claiming");
    address[] memory delegatees = delegations.getDelegatees();
    for(uint i = 0; i < delegatees.length; i++) {
      console2.log("delegatee: ", delegatees[i]);
    }

    //@audit => If all delegatees would have been claimed, then, delegatees 1 & 3 would have been deleted from the `unclaimed.delegatees` AddressSet, but because the delegatee 3 was never reached, (and the rewards of this delegatee were not claimed), this delegatee is still part of the list of delegatees for the delegator with unclaimed rewards!
  }
}
```
Run the previous PoC with the next command: `forge test --match-test test_claimingAllRewardsReproducingBug -vvvv`
@note => This PoC simply reproduces the first bug. The next PoC will be a full coded PoC working with the contracts of the system where the full scenario that causes the users to lose their rewards is reproduced.


2. The second bug occurs when **a delegator delegates to a previously undelegated delegatee.**
When delegating to a previous undelegated delegatee, the logic does not check if there are any pending rewards of this delegatee to be claimed, it simply [updates the `unclaimedStart` to the effectiveEpoch](https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/l2/staking/Distribute.sol#L109-L112).
```solidity
function notifyDelegation(
    ...
    //@audit => effectiveEpoch would be the next epoch (currentEpoch() + 1)
    uint256 effectiveEpoch,
    ...
) public onlyL2StakingContract {
  ...
  // update unclaimed info
  if (newDelegation) {
      unclaimed[delegator].delegatees.add(delegatee);
      //@audit => Regardless if there is any unclaimed rewards for this delegatee, sets the `unclaimedStart` to be the effectiveEpoch.
      unclaimed[delegator].unclaimedStart[delegatee] = effectiveEpoch;
  }
}
```

Setting the `unclaimedStart` without verifying if there are any pending rewards causes that rewards can only be claimed starting at the effectiveEpoch, any pending rewards that were earned prior to the effectiveEpoch will be lost, since the [`_claim() function` enforces that the epoch been claimed must not be <= the unclaimedStart.](https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/l2/staking/Distribute.sol#L337-L339)
```solidity
function _claim(address delegatee, address delegator, uint256 endEpochIndex) internal returns (uint256 reward) {
  require(unclaimed[delegator].delegatees.contains(delegatee), "no remaining reward");
  //@audit-info => Rewards can be claimed only from the `unclaimedStart` epoch onwards!
  require(unclaimed[delegator].unclaimedStart[delegatee] <= endEpochIndex, "all reward claimed");
}
```

As we will see in the next coded PoC, the user did everything correctly, he claimed all of his rewards, but due to the first bug, some rewards were left unclaimed. And then, the user claims his undelegation for an undelegated delegatee, afterwards, he proceeded to delegate a lower amount to an undelegated delegatee. The combination of the two bugs is what causes the lose of the rewards that were not claimed when the user indicated to claim all of his rewards. The user did not make any misstake, the bugs present on the contract caused the user to lose his rewards.

### Root Cause

Bug when claiming all delegator's rewards after a delegatee(s) were removed.

Bug when a delegator delegatees to a delegatee that was previously undelegated.

### Internal pre-conditions

User claims all his rewards after one or more delegatees were removed, and afterwards, it delegates to a delegatee that was previously removed.


### External pre-conditions

none

### Attack Path

1. Delegator undelegates to one or more of his delegatees.
2. Delegator claims all of his rewards.
3. Delegator claims his undelegations on the L2Staking contract.
4. Delegator delegates again to a previous removed delegatee.

### Impact

User's rewards are lost and become unclaimable, those rewards get stuck on the Distribute contract.


### PoC

Add the next PoC in the [`L2Staking.t.sol`](https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/test/L2Staking.t.sol) test file:
```solidity
function test_DelegatorLosesRewardsPoC() public {
    hevm.startPrank(alice);
    morphToken.approve(address(l2Staking), type(uint256).max);
    l2Staking.delegateStake(firstStaker, 5 ether);
    l2Staking.delegateStake(secondStaker, 5 ether);
    hevm.stopPrank();

    //@audit => Bob delegates to the 3 stakers
    hevm.startPrank(bob);
    morphToken.approve(address(l2Staking), type(uint256).max);
    l2Staking.delegateStake(firstStaker, 5 ether);
    l2Staking.delegateStake(secondStaker, 5 ether);
    l2Staking.delegateStake(thirdStaker, 5 ether);
    hevm.stopPrank();

    uint256 time = REWARD_EPOCH;
    hevm.warp(time);

    hevm.prank(multisig);
    l2Staking.startReward();

    // staker set commission
    hevm.prank(firstStaker);
    l2Staking.setCommissionRate(1);
    hevm.prank(secondStaker);
    l2Staking.setCommissionRate(1);
    hevm.prank(thirdStaker);
    l2Staking.setCommissionRate(1);

    // *************** epoch = 1 ******************** //
    time = REWARD_EPOCH * 2;
    hevm.warp(time);

    uint256 blocksCountOfEpoch = REWARD_EPOCH / 3;
    hevm.roll(blocksCountOfEpoch * 2);
    hevm.prank(oracleAddress);
    record.setLatestRewardEpochBlock(blocksCountOfEpoch);
    _updateDistribute(0);

    // *************** epoch = 2 ******************** //
    time = REWARD_EPOCH * 3;
    hevm.roll(blocksCountOfEpoch * 3);
    hevm.warp(time);
    _updateDistribute(1);

    // *************** epoch = 3 ******************** //
    time = REWARD_EPOCH * 4;
    hevm.roll(blocksCountOfEpoch * 4);
    hevm.warp(time);
    _updateDistribute(2);

    uint256 bobReward1;
    uint256 bobReward2;
    uint256 bobReward3;

    {
        (address[] memory delegetees, uint256[] memory bobRewards) = distribute.queryAllUnclaimed(bob);
        bobReward1 = distribute.queryUnclaimed(firstStaker, bob);
        bobReward2 = distribute.queryUnclaimed(secondStaker, bob);
        bobReward3 = distribute.queryUnclaimed(thirdStaker, bob);
        assertEq(delegetees[0], firstStaker);
        assertEq(delegetees[1], secondStaker);
        assertEq(delegetees[2], thirdStaker);
        assertEq(bobRewards[0], bobReward1);
        assertEq(bobRewards[1], bobReward2);
        assertEq(bobRewards[2], bobReward3);
    }

    // *************** epoch = 4 ******************** //
    time = REWARD_EPOCH * 5;
    hevm.roll(blocksCountOfEpoch * 5);
    hevm.warp(time);
    _updateDistribute(3);

    //@audit => Bob undelegates to 1st and 3rd staker at epoch 4 (effective epoch 5)!
    hevm.startPrank(bob);
    l2Staking.undelegateStake(firstStaker);
    l2Staking.undelegateStake(thirdStaker);
    // l2Staking.undelegateStake(secondStaker);
    IL2Staking.Undelegation[] memory undelegations = l2Staking.getUndelegations(bob);
    assertEq(undelegations.length, 2);

    // *************** epoch = 5 ******************** //
    time = REWARD_EPOCH * 6;
    hevm.roll(blocksCountOfEpoch * 6);
    hevm.warp(time);
    _updateDistribute(4);

    //@audit => Undelegation happened on epoch 4 (effective epoch 5)
    time = rewardStartTime + REWARD_EPOCH * (ROLLUP_EPOCH + 5);
    hevm.warp(time);

    bobReward1 = distribute.queryUnclaimed(firstStaker, bob);
    bobReward2 = distribute.queryUnclaimed(secondStaker, bob);
    bobReward3 = distribute.queryUnclaimed(thirdStaker, bob);


    //@audit => Bob claims all of his rewards for all the epochs
    hevm.startPrank(bob);
    uint256 balanceBefore = morphToken.balanceOf(bob);
    l2Staking.claimReward(address(0), 0);

    uint256 balanceAfter = morphToken.balanceOf(bob);
    //@audit => assert that balanceAfter is less than balanceBefore + all the rewards that Bob has earned.
    assert(balanceAfter < balanceBefore + bobReward1 + bobReward2 + bobReward3);

    //@audit => Bob claims his undelegations on the L2Staking
    l2Staking.claimUndelegation();

    //@audit => Rewards that Bob can claim before delegating to an staker that he undelegeated in the past
    //@audit => This value will be used to validate that Bob will lose rewards after he delegates to the 3rd staker (because the bug when claiming all the rewards while the delegator has undelegated delegatees), in combination with the bug when delegating to a delegatee that the user has pending rewards to claim.
    uint256 bobRewardsBeforeLosing;
    {
        (address[] memory delegetees, uint256[] memory bobRewards) = distribute.queryAllUnclaimed(bob);
        for(uint i = 0; i < bobRewards.length; i++) {
            bobRewardsBeforeLosing += bobRewards[i];
        }
    }
    //@audit => Substracting 1 ether because that will be the new delegation for the thirdStaker
    uint256 bobMorphBalanceBeforeDelegating = morphToken.balanceOf(bob) - 1 ether;

    //@audit => Bob delegates again to 3rd staker a lower amount than the previous delegation
    l2Staking.delegateStake(thirdStaker, 1 ether);

    //@audit => Bob's rewards after delegating to the 3rd staker.
    uint256 bobRewardsAfterLosing;
    {
        (address[] memory delegetees, uint256[] memory bobRewards) = distribute.queryAllUnclaimed(bob);
        for(uint i = 0; i < bobRewards.length; i++) {
            bobRewardsAfterLosing += bobRewards[i];
        }
    }
    uint256 bobMorphBalanceAfterDelegating = morphToken.balanceOf(bob);

    //@audit-issue => This assertion validates that Bob lost rewards after the delegation to the 3rd staker.
    assert(bobRewardsBeforeLosing > bobRewardsAfterLosing && bobMorphBalanceBeforeDelegating == bobMorphBalanceAfterDelegating);
}

```
Run the previous PoC with the next command: `forge test --match-test test_DelegatorLosesRewardsPoC -vvvv`

### Mitigation

Since there are two bugs involved in this problem, it is required to fix each of them.

The mitigation for the first bug (problem when claiming all the rewards):
- Refactor the [`Delegations.claimAll() function`](https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/l2/staking/Distribute.sol#L200-L218) as follows:
```solidity
function claimAll(address delegator, uint256 targetEpochIndex) external returns (uint256 reward) {
  require(mintedEpochCount != 0, "not minted yet");
  uint256 endEpochIndex = (targetEpochIndex == 0 || targetEpochIndex > mintedEpochCount - 1)
      ? mintedEpochCount - 1
      : targetEpochIndex;
  uint256 reward;

  //@audit => Make a temporal copy of the current delegates of the delegator
  uint256 totalDelegatees = unclaimed[delegator].delegatees.length();
  address[] memory delegatees = new address[](totalDelegatees);

  for (uint256 i = 0; i < unclaimed[delegator].delegatees.length(); i++) {
        delegatees[i] = unclaimed[delegator].delegatees.at(i);
  }

  //@audit => Iterate over the temporal copy, in this way, if a delegatee is removed from the AddressSet, the for loop will still iterate over all the delegatees at the start of the call!
  for (uint256 i = 0; i < delegatees.length; i++) {
    if (
          unclaimed[delegator].delegatees.contains(delegatees[i]) &&
              unclaimed[delegator].unclaimedStart[delegatee] <= endEpochIndex
    ) {
          reward += _claim(delegatees[i], delegator);
    }
  }

  if (reward > 0) {
      _transfer(delegator, reward);
  }
}
```

The mitigation for the second bug (delegating to a previous undelegated delegatee causes all pending rewards to be lost):
- [Before setting the `unclaimedStart`](https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/l2/staking/Distribute.sol#L109-L112), check if there is any pending rewards, and if there are any, either revert the tx or proceed to claim the rewards of the delegatee on behalf of the delegator.

```solidity
function notifyDelegation(
    ...
) public onlyL2StakingContract {
  ...
  // update unclaimed info
  if (newDelegation) {
      //@audit-recommendation => Add the next code to validate that the delegator does not have any pending rewards to claim on the delegatee!
      if(unclaimed[delegator].undelegated[delegatee] && unclaimed[delegator].unclaimedEnd[delegatee] != 0) {
        //@audit => The claim function will stop claiming rewards when it reaches the epoch when the delegator undelegated the delegatee!
        uint256 rewards = _claim(delegatee, delegator, effectiveEpoch - 1);
        if (reward > 0) {
            _transfer(delegator, reward);
        }
      }

      unclaimed[delegator].delegatees.add(delegatee);
      unclaimed[delegator].unclaimedStart[delegatee] = effectiveEpoch;
  }
}
```

# Issue M-7: Stakers lose their commission if they unstake as they cannot claim their pending rewards anymore after unstaking 

Source: https://github.com/sherlock-audit/2024-08-morphl2-judging/issues/168 

## Found by 
0xStalin, mstpr-brainbot, n4nika, p0wd3r, sammy, underdog, zraxx
### Summary

Once a staker unstakes or gets removed, they permanently lose access to all their accrued commissions.

This is a problem as it can either happen mistakenly or if the staker gets removed by an admin or slashed. However even in that case, they should still be able to claim their previously accrued rewards since they did not act negatively during that period.


### Root Cause

[`L2Staking.sol::claimCommission`](https://github.com/sherlock-audit/2024-08-morphl2/blob/98e0ec4c5bbd0b28f3d3a9e9159d1184bc45b38d/morph/contracts/contracts/l2/staking/L2Staking.sol#L215) has the `onlyStaker` modifier, making it only callable by stakers.


### Internal pre-conditions

None

### External pre-conditions

None

### Attack Path

Issue path in this case

* Staker stakes and accrues commissions over a few epochs
* Now either the staker unstakes or gets removed forcibly by the admin
* The staker has now lost access to all previously accrued rewards


### Impact

Loss of unclaimed rewards


### PoC

_No response_

### Mitigation

Consider removing the `onlyStaker` modifier and allow anyone to call it. This should not be a problem since normal users do not have any claimable commission anyways except if they were a staker before.




## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/morph-l2/morph/pull/516


# Issue M-8: Attacker can fill merkle tree in `L2ToL1MessagePasser`, blocking any future withdrawals 

Source: https://github.com/sherlock-audit/2024-08-morphl2-judging/issues/178 

## Found by 
mstpr-brainbot, n4nika
### Summary

An attacker can fill the merkle tree used for withdrawals from `L2 -> L1`, preventing any withdrawals from `L2` to `L1`.


### Root Cause

The protocol uses one single merkle tree with a maximum of `2**32-1` entries for all ever happening withdrawals. Once that tree is full, any calls made to `L2CrossDomainMessenger.sol::_sendMessage` will fail, since [`Tree.sol::_appendMessageHash`](https://github.com/sherlock-audit/2024-08-morphl2/blob/98e0ec4c5bbd0b28f3d3a9e9159d1184bc45b38d/morph/contracts/contracts/libraries/common/Tree.sol#L34-L36), called in `L2ToL1MessagePasser.sol::appendMessage` will revert.

```solidity
function _appendMessageHash(bytes32 leafHash) internal {
    bytes32 node = leafHash;

    // Avoid overflowing the Merkle tree (and prevent edge case in computing `_branch`)
    if (leafNodesCount >= _MAX_DEPOSIT_COUNT) {
        revert MerkleTreeFull();
    }
    // [...]
}
```

### Internal pre-conditions

None

### External pre-conditions

None

### Attack Path

* attacker deploys a contract with a function which initiates `200` withdrawals from `L2` to `L1` per transaction by calling `l2CrossDomainMessenger.sendMessage(payable(0), 0, "", 0)` `200` times 
* they then automate calling that contract as many times as it takes to fill the `2**32-1` entries of the withdrawal merkel tree in `Tree.sol` (`~ 21_000_000 times`)
* this fills the merkle tree and once it is full, any withdrawals are blocked permanently

Cost for a DoS with the lowest gas cost: `~51152 USD` at `2400 USD/ETH`

Note that this exploit takes some time to execute. However with the low gas costs and block times on L2, it is absolutely feasible to do so causing massive damage to the protocol. Additionally, if the ether price goes down, this will cost even less to execute.


### Impact

Permanent DoS of the rollup as no `L2 -> L1` withdrawals/messages will be possible anymore.


### PoC

The following exploit puts `200 calls` into one transaction, using close to the block gas limit of `10_000_000 gas`. To run it please add it to `L2Staking.t.sol` and execute it with `forge test --match-test test_lowGasSendMessage`.

```solidity
function test_lowGasSendMessage() public {
    for (uint256 i = 0; i < 200; ++i) {
        l2CrossDomainMessenger.sendMessage(payable(0), 0, "", 0);
    }
}
```
The forge output will show it costing about `9_924_957 gas` with which the calculations in `Attack Path` were made.


### Mitigation

Consider adding different handling for when a merkle tree is full, not bricking the rollup because of a filled merkle tree.


# Issue M-9: In the `revertBatch` function, `inChallenge` is set to `false` incorrectly, causing challenges to continue after the protocol is paused. 

Source: https://github.com/sherlock-audit/2024-08-morphl2-judging/issues/220 

## Found by 
0xRajkumar, mstpr-brainbot, p0wd3r, ulas
### Summary

An unchecked batch reversion will cause challenge invalidation for any committed batch, leading to batch rollback issues for challengers, as the isChallenged flag will reset unexpectedly.

### Root Cause

In the [revertBatch function](https://github.com/sherlock-audit/2024-08-morphl2/blob/main/morph/contracts/contracts/l1/rollup/Rollup.sol#L345), the `inChallenge` state is set to false even if the batch that was challenged is not part of the reverted batch set. This causes ongoing challenges to be incorrectly invalidated:

```Solidity
function revertBatch(bytes calldata _batchHeader, uint256 _count) external onlyOwner {
            .... REDACTED FOR BREVITY ...
            if (!challenges[_batchIndex].finished) {
                batchChallengeReward[challenges[_batchIndex].challenger] += challenges[_batchIndex].challengeDeposit;
                inChallenge = false;
            }
            .... REDACTED FOR BREVITY ...
```
In the above code, `if (!challenges[_batchIndex].finished)` will hold `true` for challenges that doesn't exist. If there are no challenges for a specific `_batchIndex`, then `challenges[_batchIndex].finished` will be `false` which in turn will make the `if` condition true. 

This will cause `inChallenge` to be set to `false` even when there are ongoing challenges. Lets assume the following batches were commit to L1 Rollup::


```Text
┌────────────┐      ┌────────────┐      ┌────────────┐      ┌────────────┐
│            │      │            │      │            │      │            │
│ Batch 123  ├─────►│ Batch 124  ├─────►│ Batch 125  ├─────►│ Batch 126  ├
│            │      │            │      │            │      │            │
└────────────┘      └────────────┘      └────────────┘      └────────────┘

``` 
Challenger calls `challengeState` on batch 123. This sets `isChallenged` storage variable to true. 
```Text
┌────────────┐      ┌────────────┐      ┌────────────┐      ┌────────────┐
│            │      │            │      │            │      │            │
│ Batch 123  ├─────►│ Batch 124  ├─────►│ Batch 125  ├─────►│ Batch 126  ├
│            │      │            │      │            │      │            │
└────────────┘      └────────────┘      └────────────┘      └────────────┘
      ▲
      │
  challenged

isChallenged = true
```
While the challenge is ongoing owner calls `revertBatch` on Batch 125 to revert both Batch 125 and Batch 126. 
```Text
 ┌────────────┐      ┌────────────┐      ┌────────────┐      ┌────────────┐
 │            │      │            │      │            │      │            │
 │ Batch 123  ├─────►│ Batch 124  ├─────►│ Batch 125  ├─────►│ Batch 126  ├
 │            │      │            │      │            │      │            │
 └────────────┘      └────────────┘      └────────────┘      └────────────┘
       ▲                                       ▲                           
       │                                       │                           
  challenged                             revert batch                      
  
  isChallenged = true
```
Due to the bug in the `revertBatch` function, `isChallenged` is set to `false` even though the challenged batch wasn’t in the reverted batches. 

```Text
                                                     
    ┌────────────┐      ┌────────────┐               
    │            │      │            │               
    │ Batch 123  ├─────►│ Batch 124  ├               
    │            │      │            │               
    └────────────┘      └────────────┘               
          ▲                                          
          │                                          
     challenged                                      
     
     isChallenged = false                                            
```

This will lead to issues when the protocol is paused. Due to the following check in the `setPause` function, the challenge will not be deleted while the protocol is paused:
```Solidity
function setPause(bool _status) external onlyOwner {
            .... REDACTED FOR BREVITY ...
            // inChallenge is set to false due to the bug in revertBatch
             if (inChallenge) {
                batchChallengeReward[challenges[batchChallenged].challenger] += challenges[batchChallenged]
                    .challengeDeposit;
                delete challenges[batchChallenged];
                inChallenge = false;
            }
            .... REDACTED FOR BREVITY ...
```
During the protocol pause, the prover will not be able to verify the proof and if the pause period is larger than the proof window, prover will lose the challenge and gets slashed.

### Internal pre-conditions

1. Owner calls `revertBatch` on batch n, reverting the nth batch.
2. Challenger monitors the mempool and initiates a challenge on the n-1 batch.
3. Due to the bug in `revertBatch`, the `inChallenge` flag is reset to `false`, even though batch n-1 is under challenge.
4. Owner calls `setPause` and the protocol is paused longer than the challenge window.

### External pre-conditions

_No response_

### Attack Path

1. The owner calls `revertBatch` on batch n, reverting batch n.
2. A challenger monitors the mempool and calls `challengeBatch` on batch n-1.
3. The `revertBatch` function incorrectly resets the `inChallenge` flag to false despite batch n-1 being under challenge.
4. The protocol is paused, preventing the challenge from being deleted.
5. The prover cannot prove the batch in time due to the paused protocol.
6. The prover gets slashed, even though the batch is valid.

### Impact

If the protocol is paused when there's an ongoing challenge (albeit inChallenge is set to `false` due to the vulnerability explained above) , the protocol slashes the batch submitter for failing to prove the batch within the challenge window, even though the batch is valid. The challenger may incorrectly receive the challenge reward + slash reward despite no actual issue in the batch.

### PoC

_No response_

### Mitigation

Use `batchInChallenge` function to verify the batch is indeed challenged:

```Solidity
function revertBatch(bytes calldata _batchHeader, uint256 _count) external onlyOwner {
				// ... Redacted for brevity ...
        while (_count > 0) {
            emit RevertBatch(_batchIndex, _batchHash);

            committedBatches[_batchIndex] = bytes32(0);
            // if challenge exist and not finished yet, return challenge deposit to challenger
            if (batchInChallenge(_batchIndex)) {
                batchChallengeReward[challenges[_batchIndex].challenger] += challenges[_batchIndex].challengeDeposit;
                inChallenge = false;
            }
            delete challenges[_batchIndex];

						// ... Redacted for brevity ...
        }
    }

```



## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/morph-l2/morph/pull/561


