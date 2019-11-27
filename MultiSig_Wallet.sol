pragma solidity ^0.5.1;

contract MultiSigWallert{
    
    address private owner;
    
    uint256 constant minSignsRequired = 2;
    
    function () payable external{
        
    }
    
     struct Transaction {
        address to;
        address from;
        uint amount;
        uint sigCount;
    }
    
    mapping(uint => Transaction) private transactions; 
    
    uint private txCOunt = 0;
    
    uint[] public pendingTx;
    
    mapping(address => uint) validOwners;
    
    constructor () public{
        owner = msg.sender ;
    }
    
    modifier onlyOwner{
      require(msg.sender == owner);
      _;  
    }
    
     modifier validOwner{
      require(msg.sender == owner || validOwners[msg.sender] == 1);
      _;  
    }
     
    function makeValidAddress(address _addr) public onlyOwner{
        validOwners[_addr] = 1;
    }
    
    function withdraw(uint amount) public onlyOwner{
        sendto(msg.sender, amount);
    }
    
    function sendto(address to, uint amount) validOwner public{
        
        txCOunt++;
        Transaction memory txn;
        txn.to = to;
        txn.from = msg.sender;
        txn.amount = amount;
        txn.sigCount =0;
        
         transactions[txCOunt] = txn;
         
         pendingTx.push(txCOunt);
    }
    
    function signTx(uint txID) validOwner public{
        Transaction storage txx = transactions[txID];
        txx.sigCount++;
        
        if(txx.sigCount >= minSignsRequired){
        require(address(this).balance >= txx.amount);
    //    txx.to.transfer(txx.amount);
        }
        
       // deletePendingTx(txID);
       delete(transactions[txID]);
        
        
    }
    
   
}