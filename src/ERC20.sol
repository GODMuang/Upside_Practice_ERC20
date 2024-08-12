// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract ERC20{

    //----- test 1 관련 변수들------
    string private _name;
    string private _symbol;
    address private _owner;
    
    mapping(address account => uint256) private _balances;
    uint256 private _totalSupply;

    bool private _paused;
    mapping(address account => mapping(address spender => uint256)) private _allowances;


    //----- test 2 관련 변수들------
    // PERMIT_TYPEHASH는 EIP-712와 관련이 있는 변수
    // 구조화된 데이터에 서명할 수 있는 방법이 정의된 EIP-712에 사용.
    // permit 함수에서 아래와 같은 인자를 받기때문에 그들을 묶어 keccak함.
    bytes32 private constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    // 사용자들의 nonce를 관리하는 변수.
    // nonce를 이용해 replayAttack을 방지한다.
    mapping(address account => uint256) private _nonces;


    constructor(string memory name_, string memory symbol_) {
        _owner = msg.sender;
        _name = name_;
        _symbol = symbol_;
    }


    // ----- test 2 : ecdsa 라이브러리에서 가져온 오류 핸들링 파트 ----
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS
    }
    
    error ECDSAInvalidSignature();
    error ECDSAInvalidSignatureLength(uint256 length);
    error ECDSAInvalidSignatureS(bytes32 s);

    function _throwError(RecoverError error, bytes32 errorArg) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert ECDSAInvalidSignature();
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert ECDSAInvalidSignatureLength(uint256(errorArg));
        } else if (error == RecoverError.InvalidSignatureS) {
            revert ECDSAInvalidSignatureS(errorArg);
        }
    }
    // --------------------------------------------------------


    // ----- test 1 관련 함수들-----------------------------------

    // 토큰을 전송하는 transfer 함수입니다.
    // zero address로 토큰이 오고가지 않도록 확인하며
    // 토큰을 충분히 가지고 있지 않다면 전송에 실패하도록 합니다.
    // _balances 변수를 통해 가지고 있는 토큰의 양을 확인합니다.
    // owner는 해당 함수를 마음대로 조작할 수 있습니다.
    modifier transferModifier(address from, address to, uint256 value){
        require(_paused == false, "Token has Paused!");
        require(from != address(0) && to != address(0), "address should not be zero!");
        _;
    }
    function transfer(address to, uint256 value) public transferModifier(msg.sender, to, value){
        require(_balances[msg.sender] >= value || msg.sender == _owner, "not enought balance to transfer");
        unchecked {
            _balances[msg.sender] -= value;
            _balances[to] += value;
        }

        // ERC20 - transfer, _transfer(), _update() 참고.
    }
    
    // transfer를 중지하도록 만드는 pause() 함수입니다.
    // _paused 플래그를 변화시켜 작동합니다.
    function pause()public {
        require(msg.sender == _owner, "only owner allowed");
        _paused = true;
    }

    // allowance : 계좌 Owner로부터 spender가 꺼내갈 수 있는 자산을 확인합니다.
    function allowance(address owner, address spender) public view virtual returns (uint256) {
        return _allowances[owner][spender];
    }

    // approve : 계좌 owner로부터 spender가 꺼내갈 수 있는 자산을 설정합니다.
    // approve의 owner는 msg.sender로 설정되어 있어서
    // 계좌의 소유주가 approve 해준다는 컨셉을 담고있습니다.
    function _approve(address owner, address spender, uint value) public{
        require(owner != address(0), "approve from the zero address");
        require(spender != address(0), "approve to the zero address");
        _allowances[owner][spender] = value;
    }
    function approve(address spender, uint value) public {
        _approve(msg.sender, spender, value);

    }

    
    // 계정 소유자 from으로부터 허가 allow를 확인한 뒤.
    // 계정 소유자가 아닌 대상이, 계정 소유자 -> to 로 transfer가 가능하게 하는 함수
    // _allowances 변수에 from으로부터 호출자 msg.sender가 이동시킬 수 있는 양이 명시됨.
    // 앞서 사용한 transferModifier를 재사용.
    function transferFrom(address from, address to, uint value)public transferModifier(from, to, value){
        uint256 currentAllowance = _allowances[from][msg.sender];
        require(currentAllowance >= value || currentAllowance == type(uint256).max, "insufficient allowance");
        unchecked {
            _allowances[from][msg.sender] -= value;
        }
        require(_balances[from] >= value, "value exceeds balance");
        unchecked {
            _balances[from] -= value;
            _balances[to] += value;
        }
        // emit Transfer(_from, _to, _value);
        // ERC 20 - _approve(), transferFrom(), _spendAllowance() 참고.
    }
    //---------------------------------------------------------


    // ----- test 2 관련 함수들-----------------------------------

    // @openzepplin/contracts/utils/Nonces.sol 참고.
    // 사용자의 nonce를 관리할 수 있게하는 함수.
    function nonces(address owner) public view virtual returns (uint256) {
        return _nonces[owner];
    }
    function _useNonce(address owner) internal virtual returns (uint256) {
        unchecked {
            return _nonces[owner]++;
        }
    }

    // @openzepplin/contracts/utils/cryptography/EIP712.sol 참고.
    // Domain Separator를 생성하는 함수
    // 스마트컨트랙트의 서명된 메세지가 해당 컨트랙트, 체인에서만 유효하도록 보장
    function _buildDomainSeparator() private view returns (bytes32) {
        bytes32 TYPE_HASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        string memory version = "1";
        bytes32 _hashedName;
        bytes32  _hashedVersion;
        _hashedName = keccak256(bytes(_name));
        _hashedVersion = keccak256(bytes(version));
        return keccak256(abi.encode(TYPE_HASH, _hashedName, _hashedVersion, block.chainid, address(this)));
    }

    
    // @openzepplin/contracts/utils/cryptography/toTypedDataHash.sol 참고
    // EIP191 : 이더리움에서 signed data를 어떻게 다룰 것인지에 대한 표준 정의
    // EIP-712 표준에 맞춘 구조화된 데이터를 해싱해, 서명에 사용될 keccak값을 생성하는 함수.
    // 중간에 1901은 EIP191 표준에 맞췄으며 EIP712 구조를 따름을 의미한다.
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) public pure returns (bytes32 digest) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, hex"1901") //0x19 (EIP191) + 0x01 (EIP712)
            mstore(add(ptr, 0x02), domainSeparator)
            mstore(add(ptr, 0x22), structHash)
            digest := keccak256(ptr, 0x42)
        }
    }
    function _toTypedDataHash(bytes32 structHash) public returns (bytes32 digest) {
        return toTypedDataHash(_buildDomainSeparator(), structHash);
    }


    
    // @openzepplin/contracts/utils/cryptography/ECDSA.sol 참고.
    // tryRecover 함수는 서명과 해시로부터 서명자 주소를 복구해내는 함수.
    // recover 함수는 tryRecover를 호출하고 오류를 핸들링함.
    // v : 서명에서 사용되는 recovery id. 서명이 유효한지 확인하는데 사용됨
    // r, s : 서명의 일부
    function tryRecover(bytes32 hash, uint8 v, bytes32 r,bytes32 s)
             internal pure returns (address, RecoverError, bytes32) {
        // 잘못된 s값 확인 
        // 상한선 값보다 크면 잘못된 값. n/2로 도출됨.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return (address(0), RecoverError.InvalidSignatureS, s);
        }

        // ecrecover함수를 이용해 서명자 주소 복구
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature, bytes32(0));
        }
        return (signer, RecoverError.NoError, bytes32(0));
    }
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, v, r, s);
        _throwError(error, errorArg);
        return recovered;
    }
    


    //permit 함수.
    // owner가 생성한 서명이 맞는지 검증 후에 approve할 수 있도록 한다.
    function permit(address owner,address spender,uint256 value,
                    uint256 deadline,uint8 v,bytes32 r,bytes32 s)public{
        // 서명의 데드라인을 확인한다.
        require(block.timestamp <= deadline, "sign expired");
        // 파라미터를 이용해 해시한 뒤
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, _useNonce(owner), deadline));
        // 구조화된 해시를 생성
        bytes32 hash = _toTypedDataHash(structHash);

        // 도출한 해시와 서명을 이용해, 서명자 주소를 복구
        address signer = recover(hash, v, r, s);
        if (signer != owner) {
            revert("INVALID_SIGNER");
        }
        // 서명이 올바르다면 approve.
        _approve(owner, spender, value);
    }
    
}

// test1 
// https://docs.openzeppelin.com/contracts/2.x/api/token/erc20
// https://docs.openzeppelin.com/contracts/2.x/api/token/erc20#ERC20Pausable


// test2
//https://velog.io/@frenchkebab/ERC-191-Signed-Data-Standard
// https://velog.io/@frenchkebab/EIP-712-Typed-structured-data-hashing-and-signing
//https://velog.io/@frenchkebab/ERC-2612-Permit-Extension-for-EIP-20-Signed-Approvals#replay-attack