pragma solidity ^0.5.0;
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

contract ShivomPermissionContract{
    using strings for *;
    
    function recoverUser(bytes32 hash,bytes memory sig) internal view returns(address){
        return ECRecovery.recover(hash, sig);
    }
    
    address admin;
    mapping (string => string) versionObjects;
    mapping (address => string) allPermissionObj;
    string public latestVersion ;
    
    mapping(address => bool) admins;
    
    constructor() public{
       admins[msg.sender] = true;
       }
    
    modifier onlyAdmin{
      if(admins[msg.sender])
      _;
    }
    
    //Can be invoked by either admin or by user on own address
    modifier adminOrRestricted(address addr){
       if(admins[msg.sender] || msg.sender == addr)
       _;
    }
   
   function addAdmins(address _addr) public onlyAdmin returns(bool){
       admins[_addr] =true;
   }
   
   function changeLatestVersion(string memory version) public onlyAdmin returns(bool){
       latestVersion = version;
   }
   
    //onlyAdmin - add a new version object.Ex addNewVersion("V2",
    //"A Everyone:B Not-for-profit:C Shivom-Researchers:D For-profit:E Patient-Support-Groups:F Government-Agencies:G Healthcare-Providers:H Solution-Providers"),
    function addNewVersion(string memory _versionName,string memory _versionObj) onlyAdmin public returns(bool){
        versionObjects[_versionName] = _versionObj;
        latestVersion = _versionName;
        return true;
    }
    
    function getLatestVersionObj() public view onlyAdmin returns(string memory){
       return versionObjects[latestVersion];
   }
   
    function getVersionObj(string memory version) public view onlyAdmin returns(string memory){
       return versionObjects[version];
   }
   
    
     //onlyAdmin - get permission object for any user
     function getPermissionObj(address _user) adminOrRestricted(_user) public onlyAdmin view returns(string memory){
        return allPermissionObj[_user];
    }
    
    //internal
    function replaceSubstr(string memory originalString,string memory toReplace,
    string memory replaceWith) internal pure returns(string memory){
        uint count =  strings.count(originalString.toSlice(), toReplace.toSlice());
        strings.slice memory sortedString;
        strings.slice memory pc=originalString.toSlice();
        for(uint i =0; i< count ;i++){
        sortedString= pc.split(toReplace.toSlice());
        sortedString = sortedString.concat(replaceWith.toSlice()).toSlice();
        pc = sortedString.concat(pc).toSlice();
         }
         return pc.toString();
    }
   
    //internal
    function formPermissionString(string memory entityType,string memory version,
    string memory permissionAliasString)
    internal view returns(string memory)
    {
     version = versionObjects[version];
     strings.slice memory vo= version.toSlice();
    string memory permissionAlias;
     permissionAlias = "";
      if(!permissionAliasString.toSlice().startsWith("A1".toSlice()))
     permissionAlias = permissionAlias.toSlice().concat(permissionAliasString.toSlice());
     uint count = version.toSlice().count(":".toSlice());
     strings.slice memory curr;
     strings.slice memory next;
     for(uint i=0;i<=count;i++){
         if(i!=count)
         curr = vo.split(":".toSlice());
         else
         curr = vo;
         next = curr.split(" ".toSlice());
         if(!permissionAliasString.toSlice().startsWith("A1".toSlice())){
         permissionAlias =replaceSubstr(permissionAlias,  next.concat("0".toSlice()),curr.concat("0".toSlice()));
         permissionAlias =replaceSubstr(permissionAlias,  next.concat("1".toSlice()),curr.concat("1".toSlice()));
         }
         else
         permissionAlias = permissionAlias.toSlice().concat((curr.concat(":Yes\n".toSlice()).toSlice()));
     }
     permissionAlias = replaceSubstr(permissionAlias,"0",":No\n");
     permissionAlias = replaceSubstr(permissionAlias,"1",":Yes\n");
     permissionAlias = entityType.toSlice().concat(" Permissions:\n".toSlice()).toSlice()
      .concat(permissionAlias.toSlice());
    return permissionAlias;
     
    }
    
    //user reads full permission
    function returnFullPermissionString()
    public view returns(string memory){
        return returnFullPermissionString(allPermissionObj[msg.sender]);
    }
    
    //onlyAdmin - Read full permission object for any user
    function returnFullPermissionString(address addr)
    public onlyAdmin view returns(string memory){
        return returnFullPermissionString(allPermissionObj[addr]);
    }
     
    //internal
    function returnFullPermissionString(string memory _shortenedPermissionObj) internal view returns(string memory){
       strings.slice memory _permObjSlice = _shortenedPermissionObj.toSlice();
       string memory version = _permObjSlice.split(":".toSlice()).toString();
       
       strings.slice memory _firstPermSlice = _permObjSlice.split(":".toSlice());
       return formPermissionString("Research",version,_firstPermSlice.toString()).toSlice().
       concat(
          formPermissionString("Contact",version,_permObjSlice.toString()).toSlice()
           );
    }
    
    //internal
    function formShortenedPermissionString(string memory fullPermissionObj)internal view returns(string memory){
      if(fullPermissionObj.toSlice().startsWith("Everyone:Yes".toSlice()))
       return "A1";
      strings.slice memory latestVersionSlice = versionObjects[latestVersion].toSlice(); 
      uint count = latestVersionSlice.count(":".toSlice());
     strings.slice memory curr;
     strings.slice memory next;
     for(uint i=0;i<=count;i++){
         if(i!=count)
         curr = latestVersionSlice.split(":".toSlice());
         else
         curr = latestVersionSlice;
         next = curr.split(" ".toSlice());
        
         fullPermissionObj =replaceSubstr(fullPermissionObj,  curr.toString(),next.toString());
           }
     fullPermissionObj =replaceSubstr(fullPermissionObj, "Yes","1");
     fullPermissionObj =replaceSubstr(fullPermissionObj, "No","0");
     fullPermissionObj =replaceSubstr(fullPermissionObj, ":","");
     fullPermissionObj =replaceSubstr(fullPermissionObj, " ","");
         
     return fullPermissionObj;
     
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
    
    function getMessageHash(string memory mesg) internal pure returns(bytes32) {
       uint length = bytes(mesg).length;
       string memory prefix = "\x19Ethereum Signed Message:\n";
       prefix = prefix.toSlice().concat(uint2str(length).toSlice());
       prefix = prefix.toSlice().concat(mesg.toSlice());
        bytes32 hash = keccak256(bytes(prefix));
        return hash;
  }
  
  function processIncomingRequest(string memory fullPermissionObj) public view onlyAdmin
  returns(string memory){
   fullPermissionObj = replaceSubstr(fullPermissionObj,"\n","");
   fullPermissionObj = replaceSubstr(fullPermissionObj,": ",":");
    strings.slice memory contactFullPermission = fullPermissionObj.toSlice();
    contactFullPermission.split(":".toSlice());
    strings.slice memory researchFullPermission =contactFullPermission.split("Contact".toSlice());
    contactFullPermission.split(":".toSlice());
    
    string memory finalString =  latestVersion.toSlice().concat(":".toSlice());
    finalString = finalString.toSlice().concat(formShortenedPermissionString(researchFullPermission.toString()).toSlice());
    finalString = finalString.toSlice().concat(":".toSlice());
    finalString = finalString.toSlice().concat(formShortenedPermissionString(contactFullPermission.toString()).toSlice());
    return finalString;
      
  }
  
  function validateUser(string memory fullPermissionObj,bytes memory sig) 
  public onlyAdmin view returns(address){
      bytes32 hash = getMessageHash(fullPermissionObj);
      return ECRecovery.recover(hash,sig);
  }
    
    //function called by admin once user signs his permission data                 
    function registerUserPermission(
    //bytes memory sig,
    address user,
    //string memory fullPermissionObj,
    string memory compactPermissionObject) public onlyAdmin 
    returns(bool){
    //Research Permissions:Everyone:YesGovernment:YesPharma:YesContact Permissions:Everyone:NoGovernment:Yes
    //versionObject = "A Everyone:B Government:C Pharma:D Non-Profit";
    //"A Not-for-profit:B Shivom-Researchers:C For-profit:D Patient-Support-Groups:E Government-Agencies:F Healthcare-Providers:G Solution-Providers";
    //bytes32 hash = getMessageHash(fullPermissionObj);
    //require(ECRecovery.recover(hash,sig) == user );
    allPermissionObj[user] = compactPermissionObject;
    return true;
        }
}