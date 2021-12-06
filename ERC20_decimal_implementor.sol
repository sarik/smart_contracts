pragma solidity ^0.8.0;

import "./ERC20.sol";
contract HLTH is ERC20 {

    constructor(uint256 initialSupply, address initialMintee) public ERC20 ("HLTH Token","HLTH") {
           _mint(initialMintee, initialSupply);
  }
}
