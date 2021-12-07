<!--This file is autogenerated-->



# Variables

## UNWRAP_ETH
```solidity
  uint256 public constant UNWRAP_ETH;
```
Flag to unwrap ETH
## REVERT_IF_EXTERNAL_FAIL
```solidity
  uint256 public constant REVERT_IF_EXTERNAL_FAIL;
```
Flag to revert if external call fails
## PROXY_WITH_SENDER
```solidity
  uint256 public constant PROXY_WITH_SENDER;
```
Flag to call proxy with a sender contract

# Functions
## getFlag
```solidity
  function getFlag(
            uint256 _packedFlags,
            uint256 _flag
  ) internal returns (bool)
```

Get flag

### Parameters:
| Name | Type | Description                                                          |
| :--- | :--- | :------------------------------------------------------------------- |
|`_packedFlags` | uint256 | Flags packed to uint256
|`_flag` | uint256 | Flag to check



