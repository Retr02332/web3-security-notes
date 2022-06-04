// SPDX-License-Identifier: MIT
// an example of a smart contract (sc) for a lottery system written in solidity

pragma solidity ^0.8.11;

contract Lottery {

    address public owner; // owner address
    address payable[] public players; // list of players, payable > means that can receive ether

    // this will save the address that deployed the sc as the owner
    constructor() {
        owner = msg.sender;
    }

    // this modifier will allow us to implement onlyOwner for a function
    // meaning that only the owner of the smart contract can call it
    modifier onlyOwner(){
        require(msg.sender == owner);
        _; // this means: whatever code there is after onlyOwner, run it only after the requirement is met
    }

    // print the balance of the player
    function getBalance() public view returns (uint) {
        return address(this).balance;
    }

    // print the list of players
    // memory means that the value is stored only for the duration of the function
    function getPlayers() public view returns (address payable[] memory) {
        return players;
    }

    // in the context of a function, the address is the one that called that function
    // so it's different from the constructor
    function enter() public payable {

        require (msg.value > .01 ether); // this enforce the user to pay .01 ether to join the lottery

        players.push(payable(msg.sender)); // it insert the address of the players into the array
                                           // it need to be casted payble since the address may not be payable
        
    }

    function getRandomNumber() public view returns (uint){
        return uint(keccak256(abi.encodePacked(owner, block.timestamp)));
    }

    // pick a winner and transfer the funds
    function pickWinner() public onlyOwner {
        uint index = getRandomNumber() % players.length;
        players[index].transfer(address(this).balance);

        //reset the state of the contract
        players = new address payable[](0);
    }


    // this function kill the smart contract
    // it withdrawals all the funds of the sc and makes it unusable
    function kill() public onlyOwner{
		selfdestruct(payable(owner));
    }

}
