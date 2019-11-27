pragma solidity ^0.5.0;
library strings {
    struct slice {
        uint _len;
        uint _ptr;
    }

    function memcpy(uint dest, uint src, uint len) private pure {
        // Copy word-length chunks while possible
        for(; len >= 32; len -= 32) {
            assembly {
                mstore(dest, mload(src))
            }
            dest += 32;
            src += 32;
        }

        // Copy remaining bytes
        uint mask = 256 ** (32 - len) - 1;
        assembly {
            let srcpart := and(mload(src), not(mask))
            let destpart := and(mload(dest), mask)
            mstore(dest, or(destpart, srcpart))
        }
    }

    /*
     * @dev Returns a slice containing the entire string.
     * @param self The string to make a slice from.
     * @return A newly allocated slice containing the entire string.
     */
    function toSlice(string memory self) internal pure returns (slice memory) {
        uint ptr;
        assembly {
            ptr := add(self, 0x20)
        }
        return slice(bytes(self).length, ptr);
    }

    /*
     * @dev Copies a slice to a new string.
     * @param self The slice to copy.
     * @return A newly allocated string containing the slice's text.
     */
    function toString(slice memory self) internal pure returns (string memory) {
        string memory ret = new string(self._len);
        uint retptr;
        assembly { retptr := add(ret, 32) }

        memcpy(retptr, self._ptr, self._len);
        return ret;
    }
    
    /*
     * @dev Returns a positive number if `other` comes lexicographically after
     *      `self`, a negative number if it comes before, or zero if the
     *      contents of the two slices are equal. Comparison is done per-rune,
     *      on unicode codepoints.
     * @param self The first slice to compare.
     * @param other The second slice to compare.
     * @return The result of the comparison.
     */
    function compare(slice memory self, slice memory other) internal pure returns (int) {
        uint shortest = self._len;
        if (other._len < self._len)
            shortest = other._len;

        uint selfptr = self._ptr;
        uint otherptr = other._ptr;
        for (uint idx = 0; idx < shortest; idx += 32) {
            uint a;
            uint b;
            assembly {
                a := mload(selfptr)
                b := mload(otherptr)
            }
            if (a != b) {
                // Mask out irrelevant bytes and check again
                uint256 mask = uint256(-1); // 0xffff...
                if(shortest < 32) {
                  mask = ~(2 ** (8 * (32 - shortest + idx)) - 1);
                }
                uint256 diff = (a & mask) - (b & mask);
                if (diff != 0)
                    return int(diff);
            }
            selfptr += 32;
            otherptr += 32;
        }
        return int(self._len) - int(other._len);
    }

    /*
     * @dev Returns true if the two slices contain the same text.
     * @param self The first slice to compare.
     * @param self The second slice to compare.
     * @return True if the slices are equal, false otherwise.
     */
    function equals(slice memory self, slice memory other) internal pure returns (bool) {
        return compare(self, other) == 0;
    }

    

    /*
     * @dev If `self` starts with `needle`, `needle` is removed from the
     *      beginning of `self`. Otherwise, `self` is unmodified.
     * @param self The slice to operate on.
     * @param needle The slice to search for.
     * @return `self`
     */
    function beyond(slice memory self, slice memory needle) internal pure returns (slice memory) {
        if (self._len < needle._len) {
            return self;
        }

        bool equal = true;
        if (self._ptr != needle._ptr) {
            assembly {
                let length := mload(needle)
                let selfptr := mload(add(self, 0x20))
                let needleptr := mload(add(needle, 0x20))
                equal := eq(keccak256(selfptr, length), keccak256(needleptr, length))
            }
        }

        if (equal) {
            self._len -= needle._len;
            self._ptr += needle._len;
        }

        return self;
    }
    
    /*
     * @dev Returns true if `self` starts with `needle`.
     * @param self The slice to operate on.
     * @param needle The slice to search for.
     * @return True if the slice starts with the provided text, false otherwise.
     */
    function startsWith(slice memory self, slice memory needle) internal pure returns (bool) {
        if (self._len < needle._len) {
            return false;
        }

        if (self._ptr == needle._ptr) {
            return true;
        }

        bool equal;
        assembly {
            let length := mload(needle)
            let selfptr := mload(add(self, 0x20))
            let needleptr := mload(add(needle, 0x20))
            equal := eq(keccak256(selfptr, length), keccak256(needleptr, length))
        }
        return equal;
    }


    /*
     * @dev Returns true if the slice ends with `needle`.
     * @param self The slice to operate on.
     * @param needle The slice to search for.
     * @return True if the slice starts with the provided text, false otherwise.
     */
    function endsWith(slice memory self, slice memory needle) internal pure returns (bool) {
        if (self._len < needle._len) {
            return false;
        }

        uint selfptr = self._ptr + self._len - needle._len;

        if (selfptr == needle._ptr) {
            return true;
        }

        bool equal;
        assembly {
            let length := mload(needle)
            let needleptr := mload(add(needle, 0x20))
            equal := eq(keccak256(selfptr, length), keccak256(needleptr, length))
        }

        return equal;
    }

    /*
     * @dev If `self` ends with `needle`, `needle` is removed from the
     *      end of `self`. Otherwise, `self` is unmodified.
     * @param self The slice to operate on.
     * @param needle The slice to search for.
     * @return `self`
     */
    function until(slice memory self, slice memory needle) internal pure returns (slice memory) {
        if (self._len < needle._len) {
            return self;
        }

        uint selfptr = self._ptr + self._len - needle._len;
        bool equal = true;
        if (selfptr != needle._ptr) {
            assembly {
                let length := mload(needle)
                let needleptr := mload(add(needle, 0x20))
                equal := eq(keccak256(selfptr, length), keccak256(needleptr, length))
            }
        }

        if (equal) {
            self._len -= needle._len;
        }

        return self;
    }

    // Returns the memory address of the first byte of the first occurrence of
    // `needle` in `self`, or the first byte after `self` if not found.
    function findPtr(uint selflen, uint selfptr, uint needlelen, uint needleptr) private pure returns (uint) {
        uint ptr = selfptr;
        uint idx;

        if (needlelen <= selflen) {
            if (needlelen <= 32) {
                bytes32 mask = bytes32(~(2 ** (8 * (32 - needlelen)) - 1));

                bytes32 needledata;
                assembly { needledata := and(mload(needleptr), mask) }

                uint end = selfptr + selflen - needlelen;
                bytes32 ptrdata;
                assembly { ptrdata := and(mload(ptr), mask) }

                while (ptrdata != needledata) {
                    if (ptr >= end)
                        return selfptr + selflen;
                    ptr++;
                    assembly { ptrdata := and(mload(ptr), mask) }
                }
                return ptr;
            } else {
                // For long needles, use hashing
                bytes32 hash;
                assembly { hash := keccak256(needleptr, needlelen) }

                for (idx = 0; idx <= selflen - needlelen; idx++) {
                    bytes32 testHash;
                    assembly { testHash := keccak256(ptr, needlelen) }
                    if (hash == testHash)
                        return ptr;
                    ptr += 1;
                }
            }
        }
        return selfptr + selflen;
    }

    /*
     * @dev Splits the slice, setting `self` to everything after the first
     *      occurrence of `needle`, and `token` to everything before it. If
     *      `needle` does not occur in `self`, `self` is set to the empty slice,
     *      and `token` is set to the entirety of `self`.
     * @param self The slice to split.
     * @param needle The text to search for in `self`.
     * @param token An output parameter to which the first token is written.
     * @return `token`.
     */
    function split(slice memory self, slice memory needle, slice memory token) internal pure returns (slice memory) {
        uint ptr = findPtr(self._len, self._ptr, needle._len, needle._ptr);
        token._ptr = self._ptr;
        token._len = ptr - self._ptr;
        if (ptr == self._ptr + self._len) {
            // Not found
            self._len = 0;
        } else {
            self._len -= token._len + needle._len;
            self._ptr = ptr + needle._len;
        }
        return token;
    }

    /*
     * @dev Splits the slice, setting `self` to everything after the first
     *      occurrence of `needle`, and returning everything before it. If
     *      `needle` does not occur in `self`, `self` is set to the empty slice,
     *      and the entirety of `self` is returned.
     * @param self The slice to split.
     * @param needle The text to search for in `self`.
     * @return The part of `self` up to the first occurrence of `delim`.
     */
    function split(slice memory self, slice memory needle) internal pure returns (slice memory token) {
        split(self, needle, token);
    }
    
    /*
     * @dev Counts the number of nonoverlapping occurrences of `needle` in `self`.
     * @param self The slice to search.
     * @param needle The text to search for in `self`.
     * @return The number of occurrences of `needle` found in `self`.
     */
    function count(slice memory self, slice memory needle) internal pure returns (uint cnt) {
        uint ptr = findPtr(self._len, self._ptr, needle._len, needle._ptr) + needle._len;
        while (ptr <= self._ptr + self._len) {
            cnt++;
            ptr = findPtr(self._len - (ptr - self._ptr), ptr, needle._len, needle._ptr) + needle._len;
        }
    }

    /*
     * @dev Returns a newly allocated string containing the concatenation of
     *      `self` and `other`.
     * @param self The first slice to concatenate.
     * @param other The second slice to concatenate.
     * @return The concatenation of the two strings.
     */
    function concat(slice memory self, slice memory other) internal pure returns (string memory) {
        string memory ret = new string(self._len + other._len);
        uint retptr;
        assembly { retptr := add(ret, 32) }
        memcpy(retptr, self._ptr, self._len);
        memcpy(retptr + self._len, other._ptr, other._len);
        return ret;
    }

   
}
library ECRecovery {

  function recover(bytes32 hash, bytes memory sig) public pure returns (address) {
    bytes32 r;
    bytes32 s;
    uint8 v;

    //Check the signature length
    if (sig.length != 65) {
      return (address(0));
    }

    // Divide the signature in r, s and v variables
    assembly {
      r := mload(add(sig, 32))
      s := mload(add(sig, 64))
      v := byte(0, mload(add(sig, 96)))
    }

    // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
    if (v < 27) {
      v += 27;
    }

    // If the version is correct return the signer address
    if (v != 27 && v != 28) {
      return (address(0));
    } else {
      return ecrecover(hash, v, r, s);
    }
  }

}
contract Permission_Oct{
    using strings for *;
    
    mapping(address => mapping(address => bool)) public permissions;
    
    mapping (address => int8) public permissionToAll;
    
    mapping(address => bool) public  admins;
    
    mapping(address => bool) public  monetizing;
    
    
    
    //enterprise outline
    struct enterprise {
        address add;
        string name;
        uint active; //0 - inactive 1-active
    }
    
    //array of all enterprises for iteration
    enterprise[] public allEnterprises;
    
    //keeps track of enterprise added as a number
    mapping (address => uint256) public enterpriseMapper;
    
    constructor() public{
     
        admins[msg.sender] =true;
        
    }
    
    modifier onlyAdmin{
        require(admins[msg.sender]);
        _;
    }
    
    function addAdmins(address _addr) public onlyAdmin returns(bool){
       admins[_addr] =true;
   }
    
    modifier adminOrRestricted(address addr){
       if(admins[msg.sender] || msg.sender == addr)
       _;
    }
    
    function clearPermission(address entity) internal returns(bool){
        uint8 i=0;
            
            //make sure nobody has permissionn now
            for (i;i<allEnterprises.length;i++){
            enterprise memory curr = allEnterprises[i];
            if(permissions[entity][curr.add]){
            permissions[entity][curr.add] = false;
            }
    }
    return true;
    }
    
    function uint2str(uint _i) internal pure returns (string memory _uintAsString) {
        if (_i == 0) {
            return "0";
        }
        uint j = _i;
        uint len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len - 1;
        while (_i != 0) {
            bstr[k--] = byte(uint8(48 + _i % 10));
            _i /= 10;
        }
        return string(bstr);
    }
    
    function setString(string memory s) public returns(bool){
        
        return true;
    }
    
     function getMessageHash(string memory mesg) internal pure returns(bytes32) {
       uint length = bytes(mesg).length;
       string memory prefix = "\x19Ethereum Signed Message:\n";
       prefix = prefix.toSlice().concat(uint2str(length).toSlice());
       prefix = prefix.toSlice().concat(mesg.toSlice());
        bytes32 hash = keccak256(bytes(prefix));
        return hash;
  }
    
    function validateUser(string memory fullPermissionObj,bytes memory sig) 
      public onlyAdmin view returns(address){
      bytes32 hash = getMessageHash(fullPermissionObj);
      return ECRecovery.recover(hash,sig);
    }
  
    //1-add a new eenterprise
    //2-remove an existing eenterprise
    //3-modify an existing enterprise
    //4-activate an inactive eenterprise
    function changeEnterprise(address entAddr,string memory name,uint8 change) public onlyAdmin returns(bool) {
       // allEnterprises[enterprise]=name;
       if(change == 1){
       enterprise memory curr = enterprise(entAddr,name,1);
       uint256 currSize = allEnterprises.push(curr);
       enterpriseMapper[entAddr] = currSize;
       
       return true;
       }
       else if (change == 2){
          allEnterprises[enterpriseMapper[entAddr]].active=0;
          return true;
       }
       else if (change == 3){
           allEnterprises[enterpriseMapper[entAddr]].name = name;
           return true;
       }
       else{
          allEnterprises[enterpriseMapper[entAddr]].active=1;
          return true;
       }
       
       
       //check if to make all permissions to 3 for existing permission level
    }
    
    
    function changeEnterpriseWithoutVal(address entAddr,string memory name,uint8 change) public returns(bool) {
       // allEnterprises[enterprise]=name;
       if(change == 1){
       enterprise memory curr = enterprise(entAddr,name,1);
       uint256 currSize = allEnterprises.push(curr);
       enterpriseMapper[entAddr] = currSize;
       
       return true;
       }
       else if (change == 2){
          allEnterprises[enterpriseMapper[entAddr]].active=0;
          return true;
       }
       else if (change == 3){
           allEnterprises[enterpriseMapper[entAddr]].name = name;
           return true;
       }
       else{
          allEnterprises[enterpriseMapper[entAddr]].active=1;
          return true;
       }
       
       
       //check if to make all permissions to 3 for existing permission level
    }
    
    
    //change grantLevel for an address
    function modifyGrantLevel(address granter,int8 grantLevel) onlyAdmin public returns(bool) {
        permissionToAll[granter] = grantLevel;
        return true;
    }
    
    function makeEnterpriseDataPublic(address granter) onlyAdmin public returns(bool) {
        permissionToAll[granter] = -2;
        return true;
    }
    
    
    function viewAllEnterprises() public view returns(string memory) {
        uint8 i=0;
        strings.slice memory per;
        for (i;i<allEnterprises.length;i++){
            enterprise memory curr = allEnterprises[i];
           
            strings.slice memory currName = curr.name.toSlice();
            per = per.concat(currName).toSlice();
            
            if(curr.active == 0){
                per = per.concat("(I)".toSlice()).toSlice();
            }
            per = per.concat("\n".toSlice()).toSlice();
        }
        return per.toString();
    }
    
    
    //will not clear all permissions,,change custom permission
    function changePermission(address granter,address receiver,bool addOrRevoke) onlyAdmin public returns(bool) {
        if(permissions[granter][receiver] != addOrRevoke)
        permissions[granter][receiver]=addOrRevoke;
    }
    
    //will not clear all permissions,change custom permission
    function grantMonetizingPermission(address granter,address[] memory receiver,bool[] memory addOrRevoke) onlyAdmin public returns(bool) {
        uint8 i=0;
        modifyGrantLevel(granter,-3);
        for (i;i<receiver.length;i++){
            if(permissions[granter][receiver[i]] != addOrRevoke[i]){
                permissions[granter][receiver[i]] = addOrRevoke[i];
            }
        }
        
        //if(permissions[granter][receiver] != addOrRevoke)
        //permissions[granter][receiver]=addOrRevoke;
    }
    
    function grantMonetizingPermissionToAll(address granter) onlyAdmin public returns(bool) {
       
        modifyGrantLevel(granter,-4);
        return true;
    }
    
    function changeToCustomPermission(address granter,address[] memory receiver,bool[] memory addOrRevoke) onlyAdmin public returns(bool) {
        uint8 i=0;
        modifyGrantLevel(granter,-1);
        for (i;i<receiver.length;i++){
            if(permissions[granter][receiver[i]] != addOrRevoke[i]){
                permissions[granter][receiver[i]] = addOrRevoke[i];
            }
        }
        
        //if(permissions[granter][receiver] != addOrRevoke)
        //permissions[granter][receiver]=addOrRevoke;
    }
    
    //internal
    //-1 (access to some Enterprises but non monetized)
    //-2 (access to all Enterprises including the future one)
    //-3 (access to some Enterprises and monetized)
    //-4 (access to all Enterprises and  monetized)
    //0- (access to none)
    //>0 (access to all Enterprises from 0 to n-1, basically public)
    function readPermissions(address entity) internal view returns(string memory){
       uint8 i=0;
       
       if (permissionToAll[entity] == 0){
           return "No one can access your data";
       }
       else if (permissionToAll[entity] == -2){
           return "All Enterprises,including the ones joining in future, can access your data for free";
       }
       else if (permissionToAll[entity] == -4){
           return "All Enterprises can access your data,including the ones joining in future.And you get paid";
       }
       else if (permissionToAll[entity] > 0){
           strings.slice memory per ="Free Access To:".toSlice();
           for (i;i<int(permissionToAll[entity]);i++){
            enterprise memory curr = allEnterprises[i];
            //return only active user
           // if(permissions[entity][curr.add]){
            strings.slice memory currName = curr.name.toSlice();
            
            per = per.concat(currName).toSlice();
            if(curr.active == 0){
                per = per.concat("(I)".toSlice()).toSlice();
            }
            per = per.concat("\n".toSlice()).toSlice();
           // }
           
            
        }
           return per.toString();
       }
       
       //-1 and -3 cases(Custom)
       else {
           strings.slice memory per;
           if (permissionToAll[entity] == -1)
           {per ="Free Access To:".toSlice();
           }
           else{
               per ="Paid Access To:".toSlice();
           }
        for (i;i<allEnterprises.length;i++){
            
            enterprise memory curr = allEnterprises[i];
            //return only active user
            //if(permissions[entity][curr.add] && curr.active == 1){
            if(permissions[entity][curr.add]){
            strings.slice memory currName = curr.name.toSlice();
            per = per.concat(currName).toSlice();
            if(curr.active == 0){
                per = per.concat("(I)".toSlice()).toSlice();
            }
            per = per.concat("\n".toSlice()).toSlice();
            }
            
        }
        
        return per.toString();
    }
    }
    
    //onlyAdmin - Read full permission object for any user
    function readPermission(address entity) onlyAdmin public view returns(string memory){
        return readPermissions(entity);
        
    }
    
    //user reads full permission
    function readPermission()  public view returns(string memory){
       return readPermissions(msg.sender);
    }
}