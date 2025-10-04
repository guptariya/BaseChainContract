// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @title BaseToken
 * @dev Secure ERC20 Token optimized for Base Chain with hardened security
 * @notice This contract implements a production-ready ERC20 token with:
 * - Two-step ownership transfer (prevents accidental ownership loss)
 * - Pausable functionality for emergency stops
 * - Transfer fee mechanism with precise calculation
 * - Whitelist for fee-exempt addresses
 * - Reentrancy protection
 * - Timelock for critical parameter changes
 */
contract BaseToken is ERC20, Ownable2Step, Pausable, ReentrancyGuard {
    
    // Constants
    uint256 public constant MAX_SUPPLY = 1_000_000_000 * 10**18; // 1 billion tokens
    uint256 public constant TRANSFER_FEE_PERCENT = 1; // 1% transfer fee
    uint256 public constant FEE_DENOMINATOR = 100;
    uint256 public constant MAX_BATCH_SIZE = 50; // Reduced from 100 for safety
    uint256 public constant TIMELOCK_DURATION = 2 days; // Timelock for fee collector updates
    
    // State variables
    address public feeCollector;
    address public pendingFeeCollector;
    uint256 public feeCollectorUpdateTime;
    uint256 public totalFeesCollected;
    
    // Mappings
    mapping(address => bool) public isWhitelisted;
    
    // Events
    event FeeCollected(address indexed from, address indexed to, uint256 amount);
    event WhitelistUpdated(address indexed account, bool status);
    event FeeCollectorUpdateProposed(address indexed oldCollector, address indexed newCollector, uint256 effectiveTime);
    event FeeCollectorUpdated(address indexed oldCollector, address indexed newCollector);
    event TokensBurned(address indexed burner, uint256 amount);
    event TokensMinted(address indexed to, uint256 amount);
    event ContractPaused(address indexed by);
    event ContractUnpaused(address indexed by);
    
    /**
     * @dev Constructor to initialize the token
     * @param _name Token name
     * @param _symbol Token symbol
     * @param _initialSupply Initial supply to mint to deployer
     */
    constructor(
        string memory _name,
        string memory _symbol,
        uint256 _initialSupply
    ) ERC20(_name, _symbol) Ownable(msg.sender) {
        require(_initialSupply <= MAX_SUPPLY, "Initial supply exceeds max supply");
        
        feeCollector = msg.sender;
        
        // Whitelist the owner and fee collector
        isWhitelisted[msg.sender] = true;
        isWhitelisted[address(this)] = true;
        
        // Mint initial supply
        _mint(msg.sender, _initialSupply);
        
        emit TokensMinted(msg.sender, _initialSupply);
    }
    
    /**
     * @dev Override _update function to include fee mechanism with precise math
     * @notice Uses Math.mulDiv for accurate fee calculation without precision loss
     */
    function _update(
        address from,
        address to,
        uint256 amount
    ) internal virtual override whenNotPaused {
        // Skip fee for minting/burning
        if (from == address(0) || to == address(0)) {
            super._update(from, to, amount);
            return;
        }
        
        // If sender or recipient is whitelisted, no fee
        if (isWhitelisted[from] || isWhitelisted[to]) {
            super._update(from, to, amount);
            return;
        }
        
        // Calculate fee using Math.mulDiv for precision (rounds up to favor protocol)
        uint256 feeAmount = Math.mulDiv(amount, TRANSFER_FEE_PERCENT, FEE_DENOMINATOR, Math.Rounding.Ceil);
        uint256 amountAfterFee = amount - feeAmount;
        
        // Transfer fee to collector
        if (feeAmount > 0) {
            super._update(from, feeCollector, feeAmount);
            totalFeesCollected += feeAmount;
            emit FeeCollected(from, feeCollector, feeAmount);
        }
        
        // Transfer remaining amount to recipient
        super._update(from, to, amountAfterFee);
    }
    
    /**
     * @dev Override transfer to ensure fee logic is applied
     */
    function transfer(address to, uint256 amount) public virtual override whenNotPaused returns (bool) {
        return super.transfer(to, amount);
    }
    
    /**
     * @dev Override transferFrom to ensure fee logic is applied
     */
    function transferFrom(address from, address to, uint256 amount) public virtual override whenNotPaused returns (bool) {
        return super.transferFrom(from, to, amount);
    }
    
    /**
     * @dev Mint new tokens (only owner, respects pause state)
     * @param to Address to mint tokens to
     * @param amount Amount of tokens to mint
     */
    function mint(address to, uint256 amount) external onlyOwner whenNotPaused {
        require(totalSupply() + amount <= MAX_SUPPLY, "Would exceed max supply");
        _mint(to, amount);
        emit TokensMinted(to, amount);
    }
    
    /**
     * @dev Burn tokens from caller's balance (respects pause state)
     * @param amount Amount of tokens to burn
     */
    function burn(uint256 amount) external whenNotPaused {
        _burn(msg.sender, amount);
        emit TokensBurned(msg.sender, amount);
    }
    
    /**
     * @dev Burn tokens from specific address (requires approval, respects pause state)
     * @param from Address to burn tokens from
     * @param amount Amount of tokens to burn
     */
    function burnFrom(address from, uint256 amount) external whenNotPaused {
        _spendAllowance(from, msg.sender, amount);
        _burn(from, amount);
        emit TokensBurned(from, amount);
    }
    
    /**
     * @dev Update whitelist status for an address
     * @param account Address to update
     * @param status Whitelist status
     */
    function updateWhitelist(address account, bool status) external onlyOwner {
        require(account != address(0), "Invalid address");
        isWhitelisted[account] = status;
        emit WhitelistUpdated(account, status);
    }
    
    /**
     * @dev Batch update whitelist (gas efficient)
     * @param accounts Array of addresses to update
     * @param status Whitelist status for all accounts
     */
    function batchUpdateWhitelist(address[] calldata accounts, bool status) external onlyOwner {
        require(accounts.length <= MAX_BATCH_SIZE, "Batch size exceeds limit");
        for (uint256 i = 0; i < accounts.length; i++) {
            require(accounts[i] != address(0), "Invalid address");
            isWhitelisted[accounts[i]] = status;
            emit WhitelistUpdated(accounts[i], status);
        }
    }
    
    /**
     * @dev Propose new fee collector address (Step 1 of 2)
     * @param newCollector New fee collector address
     * @notice Requires timelock before execution
     */
    function proposeFeeCollectorUpdate(address newCollector) external onlyOwner {
        require(newCollector != address(0), "Invalid address");
        require(newCollector != feeCollector, "Already fee collector");
        
        pendingFeeCollector = newCollector;
        feeCollectorUpdateTime = block.timestamp + TIMELOCK_DURATION;
        
        emit FeeCollectorUpdateProposed(feeCollector, newCollector, feeCollectorUpdateTime);
    }
    
    /**
     * @dev Execute fee collector update (Step 2 of 2)
     * @notice Can only be called after timelock period
     */
    function executeFeeCollectorUpdate() external onlyOwner {
        require(pendingFeeCollector != address(0), "No pending update");
        require(block.timestamp >= feeCollectorUpdateTime, "Timelock not expired");
        
        address oldCollector = feeCollector;
        feeCollector = pendingFeeCollector;
        
        // Automatically whitelist new fee collector
        isWhitelisted[feeCollector] = true;
        
        // Clear pending update
        pendingFeeCollector = address(0);
        feeCollectorUpdateTime = 0;
        
        emit FeeCollectorUpdated(oldCollector, feeCollector);
    }
    
    /**
     * @dev Cancel pending fee collector update
     */
    function cancelFeeCollectorUpdate() external onlyOwner {
        require(pendingFeeCollector != address(0), "No pending update");
        
        pendingFeeCollector = address(0);
        feeCollectorUpdateTime = 0;
    }
    
    /**
     * @dev Pause all token transfers (emergency use only)
     */
    function pause() external onlyOwner {
        _pause();
        emit ContractPaused(msg.sender);
    }
    
    /**
     * @dev Unpause token transfers
     */
    function unpause() external onlyOwner {
        _unpause();
        emit ContractUnpaused(msg.sender);
    }
    
    /**
     * @dev Batch transfer tokens to multiple addresses
     * @param recipients Array of recipient addresses
     * @param amounts Array of amounts to transfer
     * @notice Limited to MAX_BATCH_SIZE recipients to prevent gas exhaustion
     */
    function batchTransfer(
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external nonReentrant whenNotPaused {
        require(recipients.length == amounts.length, "Arrays length mismatch");
        require(recipients.length > 0, "Empty arrays");
        require(recipients.length <= MAX_BATCH_SIZE, "Batch size exceeds limit");
        
        for (uint256 i = 0; i < recipients.length; i++) {
            require(recipients[i] != address(0), "Invalid recipient");
            require(amounts[i] > 0, "Invalid amount");
            transfer(recipients[i], amounts[i]);
        }
    }
    
    /**
     * @dev Get contract information
     */
    function getContractInfo() external view returns (
        uint256 currentSupply,
        uint256 maxSupply,
        uint256 feesCollected,
        address collector,
        address pendingCollector,
        uint256 collectorUpdateTime,
        bool isPaused
    ) {
        return (
            totalSupply(),
            MAX_SUPPLY,
            totalFeesCollected,
            feeCollector,
            pendingFeeCollector,
            feeCollectorUpdateTime,
            paused()
        );
    }
    
    /**
     * @dev Get pending fee collector update details
     */
    function getPendingFeeCollectorUpdate() external view returns (
        address pending,
        uint256 effectiveTime,
        bool canExecute
    ) {
        return (
            pendingFeeCollector,
            feeCollectorUpdateTime,
            pendingFeeCollector != address(0) && block.timestamp >= feeCollectorUpdateTime
        );
    }
}