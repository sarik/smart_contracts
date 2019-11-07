pragma solidity ^0.5.0;
//pragma experimental ABIEncoderV2; 
contract AnalysisContract{
    string[] public researchInfo;ß
    //string[] bmxProvider;
    
    address participatingEnterprise;
    
    bool public paidBMX;
    bool public paidShivom;
    uint analysisCost;
    uint costPaid;
    
     struct participant {
        string parType;
        address payable add;
        bool paid;
        uint256 amountToPay ;
        uint256 amountPaid;
        uint256 lastPaid ;
    }
    
    
     //Data Owner
    address payable[]  dataOwners;
    mapping(address => participant) ownersMapping;
    
    participant shivom;
    
    constructor() public{
     shivom =   participant({
           parType:'Shivom',
           add: msg.sender,
           paid: false,
           amountToPay:0,
           amountPaid: 0,
           lastPaid:0
        }); 
       // analysisCost += initialCost;
        ownersMapping[msg.sender] = shivom;
        admins[msg.sender] =true;
    }
    
     function paidDataowners() public onlyAdmin view returns(bool){
       // bool allOwnerPaid = true;
         for(uint i =0;i < dataOwners.length;i++){
               if(ownersMapping[dataOwners[i]].paid == false){
                //allOwnerPaid = false;  
                  return  false;
               }
            
           }
           return true;
    }
   
    
    //to remove
    function currentContratHoldings() onlyAdmin public view returns(uint256){
      return address(this).balance;
    }
    
   
    
    //BMX
    participant bmxInfo;
    mapping(address => bool) public admins;
   
    
    //add research info,add any amount if to be paid to shivom/admin
    function addResearchInfo(string memory name,string memory analyzer,
    address enterpriseAdd,
    string memory additionalInfo,
    uint256  amountToPayToShivom)
    onlyAdmin public{
        researchInfo.push(name);
        researchInfo.push(analyzer);
        //convert current time to string
        //researchInfo.push(block.timestamp);
        researchInfo.push(additionalInfo);
        participatingEnterprise = enterpriseAdd;
        
        
        ownersMapping[msg.sender].amountToPay = amountToPayToShivom;
        shivom.amountToPay = amountToPayToShivom;
        analysisCost += amountToPayToShivom;
    }
    
    modifier onlyDataOwner(address payable addr){
        require(ownersMapping[addr].add != address(0x0));
        _;
    }
    
    modifier onlyAdmin{
        require(admins[msg.sender]);
        _;
    }
    
    modifier adminOrEnterprise(address addr){
        require(admins[msg.sender] || addr == participatingEnterprise);
        _;
    }
    
 function wasUserDataUsed(address payable addr) onlyAdmin public view returns(bool) {
    return (ownersMapping[addr].add != address(0x0));
}

function wasMyDataUsed() onlyDataOwner(msg.sender) public view returns(bool) {
   return (ownersMapping[msg.sender].add != address(0x0));
}


function howMuchWasUserPaid(address payable addr) onlyAdmin public view returns(bool,uint256) {
    return(ownersMapping[addr].paid,ownersMapping[addr].amountPaid);
}

function howMuchWasIPaid() onlyDataOwner(msg.sender) public view returns(bool,uint256) {
    return(ownersMapping[msg.sender].paid,ownersMapping[msg.sender].amountPaid);
}


function compareStrings (string memory a, string memory b) internal pure 
       returns (bool) {
  return (keccak256(abi.encodePacked((a))) == keccak256(abi.encodePacked((b))) );

       }
    
    function addParticipant(string memory parType,address payable addr,uint256 amountToPay) 
    public onlyAdmin  {
         participant memory par = participant({
           parType:parType,
           add: addr,
           paid: false,
           amountToPay:amountToPay,
           amountPaid: 0,
           lastPaid:0
        });
        
        analysisCost += amountToPay;
        
        ownersMapping[addr] = par;
        
        if(compareStrings("BMX",parType))
        {bmxInfo = par;
         return;}
        

        dataOwners.push(addr);
        
    }
    
    //function() external payable{}
    
    function payCost() payable public{
        //require(msg.value <= analysisCost - costPaid);
       //address(this).transfer(msg.value);
       costPaid += msg.value;
       
      // bool allOwnerPaid = true;
       
       if(costPaid >= analysisCost){
           for(uint i =0;i < dataOwners.length;i++){
               payEntity('DataOwner',dataOwners[i],ownersMapping[dataOwners[i]].amountToPay);
               //dataOwners[i].paid == true;
               //if(dataOwners[i].paid == false){
                // allOwnerPaid = false;  
               //}
           }
           //paidDataowners = allOwnerPaid;
           
           if(bmxInfo.add != address(0x0))
           payEntity("BMX",bmxInfo.add,bmxInfo.amountToPay);
           
           payEntity("Shivom",shivom.add,shivom.amountToPay);
            
       }
    }
    
    function payEntity(string memory parType ,address payable addr, uint amountToPay) 
     
    internal{
       
        participant storage par = ownersMapping[addr];
         //require(analysisCost == costPaid && amountToPay == par.amountToPay);
         
         par.amountPaid += amountToPay;
         par.lastPaid = block.timestamp ;
         //par.paid = (par.amountPaid == par.amountToPay);
         par.paid = true;
         //costPaid += msg.value;
         
         if(compareStrings("BMX",parType)){
          paidBMX = (par.amountPaid == par.amountToPay);
          bmxInfo = par;
         }
         
          
          else if (compareStrings("Shivom",parType))
          {
          paidShivom = (par.amountPaid == par.amountToPay);
          shivom = par;
    }
          
          ownersMapping[addr] = par;
          
          addr.transfer(amountToPay);
          
          
    }
    
    function readDataOwner(address add) onlyAdmin public view returns(bool,uint){
        return (ownersMapping[add].paid,ownersMapping[add].lastPaid);
    }
    
     function getAnalysisCost() adminOrEnterprise(msg.sender) public view returns(uint){
        return analysisCost;
    }
    
     function getTotalCostPaid() adminOrEnterprise(msg.sender)  public view returns(uint){
        return costPaid;
    }
}