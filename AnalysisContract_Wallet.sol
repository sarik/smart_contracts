pragma solidity ^0.5.0;
//pragma experimental ABIEncoderV2; 
contract AnalysisContract{
    
    
    struct analysis {
        string about;
        address payable enterprise;
        address payable [] dataOwners;
        //bool paid;
        uint256 amountToPayByEnt ;
        uint256 amountToPayToDO;
        uint256 lastPaidAt ;
    }
    
    mapping(address => bool) public admins;
    
    mapping(string => analysis) analysisMapping;
    
    modifier onlyAdmin{
        require(admins[msg.sender]);
        _;
    }
    
    modifier involvedInAnalysis(string memory _analysisId,address payable _addr){
        
        bool isInvolved = false;
        for(uint i =0;i < analysisMapping[_analysisId].dataOwners.length;i++){
        if (analysisMapping[_analysisId].dataOwners[i] == _addr)
        {
            isInvolved = true;
        }
        }
        
        require(isInvolved);
        _;
    }
    
    function addAdmins(address _addr) public onlyAdmin returns(bool){
       admins[_addr] =true;
   }
    
    
    function createAnalysis(string memory _analysisId,
    string memory _about,
    address payable _ent,
    address payable[] memory _dataOwners,
    uint256  _amountReceivedFromEnt,
    uint256  _amountToPayToDO) 
    public onlyAdmin{
        
           
           analysis memory __analysis = analysis({
           about:_about,
           enterprise: _ent,
           amountToPayByEnt: _amountReceivedFromEnt,
           //paid: false,
           dataOwners:_dataOwners,
           amountToPayToDO: _amountToPayToDO,
           lastPaidAt:block.timestamp
        });
        
        analysisMapping[_analysisId] = __analysis;
    }
    
    function wasMyDataUsedForAnalysis(string memory _analysisId)
    involvedInAnalysis(_analysisId, msg.sender)
    public view returns(bool) {
        return true;
    }
  
   function wasUserDataUsedForAnalysis(string memory _analysisId, address payable _addr) 
   onlyAdmin
   involvedInAnalysis(_analysisId, _addr)
   public view returns(bool) {
        return true;
  }
  
  function howMuchWasUserPaidForAnalysis(address payable _addr,string memory _analysisId) 
  involvedInAnalysis(_analysisId, _addr)
  onlyAdmin public view returns(uint256) {
    return analysisMapping[_analysisId].amountToPayToDO;
  }

  function howMuchWasIPaidForAnalysis(string memory _analysisId) 
  involvedInAnalysis(_analysisId, msg.sender)
  public view returns(uint256) {
    return analysisMapping[_analysisId].amountToPayToDO;
  }
  
  function howMuchIPaidForAnalysis(string memory _analysisId) 
  involvedInAnalysis(_analysisId, msg.sender)
  public view returns(uint256) {
    require(analysisMapping[_analysisId].enterprise == msg.sender);
    return analysisMapping[_analysisId].amountToPayByEnt;
  }
       
}
