// SPDX-License-Identifier: MIT
pragma solidity ^0.8.2;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "../interfaces/IUniswapV2Pair.sol";
import "../interfaces/IUniswapV2Factory.sol";
import "../interfaces/IDeBridgeGate.sol";
import "../interfaces/IStrategy.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract DefiController is Initializable,
                           AccessControlUpgradeable {

    using SafeERC20 for IERC20;

    struct Strategy {
        bool isSupported;
        bool isEnabled;
        // bool isRecoverable;
        uint16 maxReservesBps;
        address stakeToken;
        address strategyToken;
        // address rewardToken;
        // uint256 totalShares;
        // uint256 totalReserves;
    }


    /* ========== STATE VARIABLES ========== */

    uint256 public constant BPS_DENOMINATOR = 10000;
    uint256 public constant STRATEGY_RESERVES_DELTA_BPS = 200; // 2%
    bytes32 public constant WORKER_ROLE = keccak256("WORKER_ROLE"); // role allowed to submit the data

    mapping(address => Strategy) public strategies;
    IDeBridgeGate public deBridgeGate;

     /* ========== MODIFIERS ========== */

    modifier onlyWorker {
        require(hasRole(WORKER_ROLE, msg.sender), "onlyWorker: bad role");
        _;
    }

    modifier onlyAdmin {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "onlyAdmin: bad role");
        _;
    }

    /* ========== CONSTRUCTOR  ========== */

    function initialize()//IDeBridgeGate _deBridgeGate)
        public initializer {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        // deBridgeGate = _deBridgeGate;
        // TODO: pausable for workers
        // TODO: fix DefiController tests
        // TODO: what if in some cases strategyToken balance != stake token balance?
    }

    function addStrategy(
        address _strategy,
        bool _isEnabled,
        uint16 _maxReservesBps,
        address _stakeToken,
        address _strategyToken
    ) external onlyAdmin {

        require(_maxReservesBps == 0 ||
            (_maxReservesBps > STRATEGY_RESERVES_DELTA_BPS && BPS_DENOMINATOR > _maxReservesBps),
            "invalid maxReservesBps");
        Strategy storage strategy = strategies[_strategy];
        require(!strategy.isSupported, "strategy already exists");
        strategy.isSupported = true;
        strategy.isEnabled = _isEnabled;
        strategy.maxReservesBps = _maxReservesBps;
        strategy.stakeToken = _stakeToken;
        strategy.strategyToken = _strategyToken;
    }


    function depositToStrategy(uint256 _amount, address _strategy) internal {
        Strategy memory strategy = strategies[_strategy];
        require(strategy.isEnabled, "strategy is not enabled");
        IStrategy strategyController = IStrategy(_strategy);

        // Check that strategy will use only allowed % of all avaliable for DefiController reserves
        uint256 avaliableReserves = deBridgeGate.getDefiAvaliableReserves(strategy.stakeToken);
        uint256 maxStrategyReserves = avaliableReserves * strategy.maxReservesBps / BPS_DENOMINATOR;
        uint256 currentReserves = strategyController.updateReserves(address(this), strategy.strategyToken);
        require(currentReserves + _amount < maxStrategyReserves, "");

        // Get tokens from Gate
        deBridgeGate.requestReserves(strategy.stakeToken, _amount);

        // Deposit tokens to strategy
        IERC20(strategy.stakeToken).safeApprove(address(strategyController), 0);
        IERC20(strategy.stakeToken).safeApprove(address(strategyController), _amount);
        strategyController.deposit(strategy.stakeToken, _amount);
    }

    function withdrawFromStrategy(uint256 _amount, address _strategy) internal {
        Strategy memory strategy = strategies[_strategy];
        require(strategy.isEnabled, " strategy is not enabled");
        IStrategy strategyController = IStrategy(_strategy);

        // Withdraw tokens from strategy
        strategyController.withdraw(strategy.strategyToken, _amount);
        IERC20(strategy.stakeToken).safeApprove(address(deBridgeGate), 0);
        IERC20(strategy.stakeToken).safeApprove(address(deBridgeGate), _amount);

        // TODO: get rewards from strategy

        // Return tokens to Gate
        deBridgeGate.returnReserves(strategy.stakeToken, _amount);
    }

    function rebalanceStrategy(address _strategy) external onlyWorker returns (bool) {
        Strategy memory strategy = strategies[_strategy];
        // require(strategy.isEnabled, "strategy is not enabled");
        IStrategy strategyController = IStrategy(_strategy);

        // avaliableReserves = 100%
        uint256 avaliableReserves = deBridgeGate.getDefiAvaliableReserves(strategy.stakeToken);
        // current strategy reserves in bps
        uint256 currentReserves = strategyController.updateReserves(address(this), strategy.strategyToken);
        uint256 currentReservesBps = currentReserves * BPS_DENOMINATOR / avaliableReserves;

        // calculate optimal value of strategy reserves in bps:
        uint256 optimalReservesBps = strategy.maxReservesBps == 0 ? 0
            : strategy.maxReservesBps - STRATEGY_RESERVES_DELTA_BPS / 2;
        if (optimalReservesBps == 0) {
            // maxReservesBps is zero, withdraw all current reserves from strategy
            withdrawFromStrategy(currentReserves, _strategy);
            return true;
        } else if (currentReservesBps > strategy.maxReservesBps) {
            // strategy reserves are more than allowed value, withdraw some to keep optimal balance
            uint256 amount = (currentReservesBps - optimalReservesBps) * avaliableReserves / BPS_DENOMINATOR;
            withdrawFromStrategy(amount, _strategy);
            return true;
        } else if (currentReservesBps + STRATEGY_RESERVES_DELTA_BPS < strategy.maxReservesBps) {
            // strategy reserves are less than optimal value, deposit some to keep optimal balance
            uint256 amount = (optimalReservesBps - currentReservesBps) * avaliableReserves / BPS_DENOMINATOR;
            depositToStrategy(amount, _strategy);
            return true;
        }
        return false;
    }

    // TODO
    // function isStrategyUnbalanced(address _strategy) external view returns (bool) {
    //     Strategy memory strategy = strategies[_strategy];
    //     if (strategy.isSupported) {

    //     }
    //     return false;
    // }

    function setDeBridgeGate(IDeBridgeGate _deBridgeGate) external onlyAdmin {
        deBridgeGate = _deBridgeGate;
    }

    function addWorker(address _worker) external onlyAdmin {
        grantRole(WORKER_ROLE, _worker);
    }

    function removeWorker(address _worker) external onlyAdmin {
        revokeRole(WORKER_ROLE, _worker);
    }
}
