// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// This contract intentionally contains vulnerabilities for testing Harvesto Scanner

contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalDeposits;

    constructor() {
        owner = msg.sender;
    }

    // VULN: Reentrancy — external call before state update (Critical)
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // BUG: sends ETH before updating balance
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update happens AFTER external call
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }

    // VULN: Missing access control on sensitive function (Critical)
    function mint(address to, uint256 amount) external {
        // No access control! Anyone can mint
        balances[to] += amount;
        totalDeposits += amount;
    }

    // VULN: Missing access control on setOwner (Critical)
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function deposit() external payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    // VULN: Unchecked low-level call (Medium)
    function emergencyTransfer(address payable to) external {
        require(msg.sender == owner, "Not owner");
        to.call{value: address(this).balance}("");
        // Return value not checked!
    }

    receive() external payable {}
}

// VULN: Flash loan callback without initiator validation (Critical)
contract VulnerableFlashReceiver {
    address public vault;

    constructor(address _vault) {
        vault = _vault;
    }

    // No validation of who initiated the flash loan
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        // Process without checking msg.sender or initiator
        for (uint i = 0; i < assets.length; i++) {
            // do something dangerous with assets
        }
        return true;
    }
}

// VULN: Price manipulation via spot price (Critical)
interface IUniswapV3Pool {
    function slot0() external view returns (
        uint160 sqrtPriceX96, int24 tick, uint16 observationIndex,
        uint16 observationCardinality, uint16 observationCardinalityNext,
        uint8 feeProtocol, bool unlocked
    );
}

contract VulnerablePriceOracle {
    IUniswapV3Pool public pool;

    constructor(address _pool) {
        pool = IUniswapV3Pool(_pool);
    }

    // VULN: Using slot0 spot price — manipulable via flash loan
    function getPrice() public view returns (uint256) {
        (uint160 sqrtPriceX96,,,,,,) = pool.slot0();
        return uint256(sqrtPriceX96);
    }

    function liquidate(address user) external {
        uint256 price = getPrice(); // Uses manipulable spot price
        // ... liquidation logic based on spot price
    }
}

// VULN: Missing slippage protection (High)
interface ISwapRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata params) external returns (uint256);
}

contract VulnerableSwapper {
    ISwapRouter public router;

    constructor(address _router) {
        router = ISwapRouter(_router);
    }

    function swapTokens(address tokenIn, address tokenOut, uint256 amountIn) external {
        // VULN: amountOutMinimum = 0 — sandwich attack possible
        router.exactInputSingle(ISwapRouter.ExactInputSingleParams({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            fee: 3000,
            recipient: msg.sender,
            deadline: block.timestamp,
            amountIn: amountIn,
            amountOutMinimum: 0,  // BUG: No slippage protection!
            sqrtPriceLimitX96: 0
        }));
    }
}

// Safe contract (should NOT be flagged)
contract SafeVault {
    mapping(address => uint256) public balances;
    address public owner;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "Reentrancy");
        locked = true;
        _;
        locked = false;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // SAFE: Has reentrancy guard
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }

    // SAFE: Has access control
    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    // SAFE: Internal function
    function _internalCalc(uint256 a) internal pure returns (uint256) {
        return a * 2;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {}
}
