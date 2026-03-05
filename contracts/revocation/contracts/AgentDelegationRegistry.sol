// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title SauronID Agent Delegation Registry
 * @notice On-chain registry for agentic delegation lifecycle management.
 *
 * Tracks which AI agents have active delegations and allows:
 *   - Human owners to revoke agent access
 *   - Issuers to suspend delegations system-wide
 *   - Verifiers to check if a delegation is still active
 *
 * Integrates with the A-JWT protocol: agent_checksum → on-chain status.
 */
contract AgentDelegationRegistry is AccessControl {
    bytes32 public constant DELEGATOR_ROLE = keccak256("DELEGATOR_ROLE");
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;

    struct Delegation {
        bytes32 parentChecksum;   // Parent agent or human identity hash
        address registeredBy;     // EOA that registered the delegation
        uint256 createdAt;
        uint256 expiresAt;
        bool active;
        bool revoked;
        string scope;            // JSON-encoded scope restrictions
    }

    // agentChecksum → Delegation
    mapping(bytes32 => Delegation) private _delegations;

    // Track all registered agent checksums
    bytes32[] private _allAgents;

    uint256 public totalDelegations;
    uint256 public activeDelegations;

    // ─── Events ───────────────────────────────────────────────────

    event DelegationRegistered(
        bytes32 indexed agentChecksum,
        bytes32 indexed parentChecksum,
        address indexed registeredBy,
        uint256 expiresAt,
        string scope
    );

    event DelegationRevoked(
        bytes32 indexed agentChecksum,
        address indexed revokedBy,
        uint256 timestamp,
        string reason
    );

    event DelegationExpired(
        bytes32 indexed agentChecksum,
        uint256 timestamp
    );

    // ─── Constructor ──────────────────────────────────────────────

    constructor() {
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(DELEGATOR_ROLE, msg.sender);
    }

    // ─── Registration ─────────────────────────────────────────────

    /**
     * @notice Register a new agent delegation on-chain.
     * @param agentChecksum  SHA-256 hash of the agent's behavioral config
     * @param parentChecksum Hash of the parent agent/human that delegated
     * @param expiresAt      Unix timestamp when delegation expires
     * @param scope          JSON-encoded scope restrictions
     */
    function registerDelegation(
        bytes32 agentChecksum,
        bytes32 parentChecksum,
        uint256 expiresAt,
        string calldata scope
    ) external onlyRole(DELEGATOR_ROLE) {
        require(!_delegations[agentChecksum].active, "Delegation already active");
        require(expiresAt > block.timestamp, "Expiry must be in the future");

        _delegations[agentChecksum] = Delegation({
            parentChecksum: parentChecksum,
            registeredBy: msg.sender,
            createdAt: block.timestamp,
            expiresAt: expiresAt,
            active: true,
            revoked: false,
            scope: scope
        });

        _allAgents.push(agentChecksum);
        totalDelegations++;
        activeDelegations++;

        emit DelegationRegistered(agentChecksum, parentChecksum, msg.sender, expiresAt, scope);
    }

    // ─── Revocation ───────────────────────────────────────────────

    /**
     * @notice Revoke an agent's delegation.
     * @param agentChecksum  The agent to revoke
     * @param reason         Reason for revocation
     */
    function revokeDelegation(
        bytes32 agentChecksum,
        string calldata reason
    ) external onlyRole(DELEGATOR_ROLE) {
        require(_delegations[agentChecksum].active, "Delegation not active");

        _delegations[agentChecksum].active = false;
        _delegations[agentChecksum].revoked = true;
        activeDelegations--;

        emit DelegationRevoked(agentChecksum, msg.sender, block.timestamp, reason);
    }

    // ─── Queries ──────────────────────────────────────────────────

    /**
     * @notice Check if an agent delegation is currently active.
     * @param agentChecksum  The agent's checksum
     * @return active  true if delegation exists, is not revoked, and hasn't expired
     */
    function isDelegationActive(bytes32 agentChecksum) external view returns (bool) {
        Delegation storage d = _delegations[agentChecksum];
        return d.active && !d.revoked && block.timestamp < d.expiresAt;
    }

    /**
     * @notice Get full delegation details.
     */
    function getDelegation(bytes32 agentChecksum) external view returns (
        bytes32 parentChecksum,
        address registeredBy,
        uint256 createdAt,
        uint256 expiresAt,
        bool active,
        bool revoked,
        string memory scope
    ) {
        Delegation storage d = _delegations[agentChecksum];
        return (
            d.parentChecksum,
            d.registeredBy,
            d.createdAt,
            d.expiresAt,
            d.active,
            d.revoked,
            d.scope
        );
    }

    // ─── Admin ────────────────────────────────────────────────────

    function grantDelegator(address account) external onlyRole(ADMIN_ROLE) {
        grantRole(DELEGATOR_ROLE, account);
    }

    function revokeDelegator(address account) external onlyRole(ADMIN_ROLE) {
        revokeRole(DELEGATOR_ROLE, account);
    }
}
