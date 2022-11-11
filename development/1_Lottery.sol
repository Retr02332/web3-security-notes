// SPDX-License-Identifier: MIT
// an example of a smart contract (sc) for a lottery system written in solidity

import '@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol';
import '@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol';

pragma solidity ^0.8.11;

contract Lottery is VRFConsumerBaseV2{

    address public owner; // owner address
    address payable[] public players; // list of players, payable > means that can receive ether
    uint public lotteryID; // the ID of the current lottery
    mapping (uint => address payable) public winners_history; // list of winners of the lottery. mapping is like a java obj where all the keys have the same value

    event RequestSent(uint256 requestId, uint32 numWords);
    event RequestFulfilled(uint256 requestId, uint256[] randomWords);

    struct RequestStatus {
        bool fulfilled; // whether the request has been successfully fulfilled
        bool exists; // whether a requestId exists
        uint256[] randomWords;
    }
    mapping(uint256 => RequestStatus) public s_requests; /* requestId --> requestStatus */
    VRFCoordinatorV2Interface COORDINATOR;

    // Your subscription ID.
    uint64 s_subscriptionId;

    // past requests Id.
    uint256[] public requestIds;
    uint256 public lastRequestId;

    // The gas lane to use, which specifies the maximum gas price to bump to.
    // For a list of available gas lanes on each network,
    // see https://docs.chain.link/docs/vrf/v2/subscription/supported-networks/#configurations
    bytes32 keyHash = 0x79d3d8832d904592c0bf9818b621522c988bb8b0c05cdc3b15aea1b6e8db0c15;

    // Depends on the number of requested values that you want sent to the
    // fulfillRandomWords() function. Storing each word costs about 20,000 gas,
    // so 100,000 is a safe default for this example contract. Test and adjust
    // this limit based on the network that you select, the size of the request,
    // and the processing of the callback request in the fulfillRandomWords()
    // function.
    uint32 callbackGasLimit = 100000;

    // The default is 3, but you can set this higher.
    uint16 requestConfirmations = 3;

    // For this example, retrieve 2 random values in one request.
    // Cannot exceed VRFCoordinatorV2.MAX_NUM_WORDS.
    uint32 numWords = 2;

    // Assumes the subscription is funded sufficiently.
    function requestRandomWords() internal onlyOwner returns (uint256 requestId) {
        // Will revert if subscription is not set and funded.
        requestId = COORDINATOR.requestRandomWords(
            keyHash,
            s_subscriptionId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );
        s_requests[requestId] = RequestStatus({randomWords: new uint256[](0), exists: true, fulfilled: false});
        requestIds.push(requestId);
        lastRequestId = requestId;
        emit RequestSent(requestId, numWords);
        return requestId;
    }

    function fulfillRandomWords(uint256 _requestId, uint256[] memory _randomWords) internal override {
        require(s_requests[_requestId].exists, 'request not found');
        s_requests[_requestId].fulfilled = true;
        s_requests[_requestId].randomWords = _randomWords;
        emit RequestFulfilled(_requestId, _randomWords);
    }

    function getRequestStatus(uint256 _requestId) external view returns (bool fulfilled, uint256[] memory randomWords) {
        require(s_requests[_requestId].exists, 'request not found');
        RequestStatus memory request = s_requests[_requestId];
        return (request.fulfilled, request.randomWords);
    }
    /**
     * HARDCODED FOR GOERLI
     * COORDINATOR: 0x2Ca8E0C643bDe4C2E08ab1fA0da3401AdAD7734D
     */
    // this will also save the address that deployed the sc as the owner
    constructor(uint64 subscriptionId)
        VRFConsumerBaseV2(0x2Ca8E0C643bDe4C2E08ab1fA0da3401AdAD7734D)
    {
        COORDINATOR = VRFCoordinatorV2Interface(0x2Ca8E0C643bDe4C2E08ab1fA0da3401AdAD7734D);
        s_subscriptionId = subscriptionId;
        owner = msg.sender;
        lotteryID = 0;
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

    // it returns the winner a given lotteryID
    function getWinnerByLottery(uint lottery_ID) public view returns (address payable){
        return winners_history[lottery_ID];
    }

    // in the context of a function, the address is the one that called that function
    // so it's different from the constructor
    function enter() public payable {

        require (msg.value > .01 ether); // this enforce the user to pay .01 ether to join the lottery

        players.push(payable(msg.sender)); // it insert the address of the players into the array
                                           // it need to be casted payble since the address may not be payable
        
    }

    // get random number using block variable
    function getRandomNumber() public view returns (uint){
        return uint(keccak256(abi.encodePacked(owner, block.timestamp)));
    }

    // pick a winner and transfer the funds
    function pickWinner() public onlyOwner {

        //uint index = getRandomNumber() % players.length; //old index for getRandomNumber()
        uint256 index = requestRandomWords() % players.length;
        players[index].transfer(address(this).balance);

        winners_history[lotteryID] = players[index];

        // note about reentrancy attacks: it's good practice to - update first and transfer after
        // this to avoid this type of attack. In this case, the update of the lotteryID value does not constitute a risk
        // (+) this function can be called only by the owner of the smart contract
        lotteryID++; 

        //reset the state of the contract
        players = new address payable[](0);
    }


    // this function kill the smart contract
    // it withdrawals all the funds of the sc and makes it unusable
    function kill() public onlyOwner{
		selfdestruct(payable(owner));
    }

}
