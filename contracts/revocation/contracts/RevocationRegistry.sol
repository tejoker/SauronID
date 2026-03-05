// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title SauronID Revocation Registry
 * @notice On-chain revocation registry for Verifiable Credentials.
 *
 * Design principles:
 *   - NO personal data on-chain (GDPR compliant)
 *   - Only keccak256 digests of credential hashes are stored
 *   - Role-based access control (only authorized issuers can revoke)
 *   - Batch revocation for gas optimization
 *   - Events for off-chain indexing (The Graph)
 *
 * Usage:
 *   1. Issuer registers as ISSUER_ROLE via admin
 *   2. When revoking, issuer calls revoke(keccak256(credentialHash))
 *   3. Verifiers check isRevoked(digest) or query The Graph subgraph
 */
contract RevocationRegistry is AccessControl, ReentrancyGuard {
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;

    struct RevocationRecord {
        address revoker;
        uint256 timestamp;
        string reason;   // Optional human-readable reason code
        bool revoked;
    }

    // digest → RevocationRecord
    mapping(bytes32 => RevocationRecord) private _revocations;

    // Total revocation count
    uint256 public totalRevocations;

    // ─── Events ───────────────────────────────────────────────────

    event CredentialRevoked(
        bytes32 indexed digest,
        address indexed revoker,
        uint256 timestamp,
        string reason
    );

    event CredentialBatchRevoked(
        bytes32[] digests,
        address indexed revoker,
        uint256 timestamp
    );

    event IssuerGranted(address indexed issuer, address indexed grantedBy);
    event IssuerRevoked(address indexed issuer, address indexed revokedBy);

    // ─── Constructor ──────────────────────────────────────────────

    constructor() {
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(ISSUER_ROLE, msg.sender);
    }

    // ─── Revocation ───────────────────────────────────────────────

    /**
     * @notice Revoke a credential by its digest (keccak256 of the credential hash).
     * @param digest   keccak256(credentialHash)
     * @param reason   Optional reason code (e.g., "compromised", "expired", "user_request")
     */
    function revoke(bytes32 digest, string calldata reason) external onlyRole(ISSUER_ROLE) {
        require(!_revocations[digest].revoked, "Already revoked");

        _revocations[digest] = RevocationRecord({
            revoker: msg.sender,
            timestamp: block.timestamp,
            reason: reason,
            revoked: true
        });

        totalRevocations++;

        emit CredentialRevoked(digest, msg.sender, block.timestamp, reason);
    }

    /**
     * @notice Batch revoke multiple credentials for gas efficiency.
     * @param digests  Array of credential digests to revoke
     */
    function batchRevoke(bytes32[] calldata digests) external onlyRole(ISSUER_ROLE) nonReentrant {
        for (uint256 i = 0; i < digests.length; i++) {
            if (!_revocations[digests[i]].revoked) {
                _revocations[digests[i]] = RevocationRecord({
                    revoker: msg.sender,
                    timestamp: block.timestamp,
                    reason: "batch",
                    revoked: true
                });
                totalRevocations++;
            }
        }

        emit CredentialBatchRevoked(digests, msg.sender, block.timestamp);
    }

    // ─── Queries ──────────────────────────────────────────────────

    /**
     * @notice Check if a credential has been revoked.
     * @param digest  keccak256(credentialHash)
     * @return        true if revoked
     */
    function isRevoked(bytes32 digest) external view returns (bool) {
        return _revocations[digest].revoked;
    }

    /**
     * @notice Get full revocation details.
     * @param digest  keccak256(credentialHash)
     */
    function getRevocation(bytes32 digest) external view returns (
        address revoker,
        uint256 timestamp,
        string memory reason,
        bool revoked
    ) {
        RevocationRecord storage rec = _revocations[digest];
        return (rec.revoker, rec.timestamp, rec.reason, rec.revoked);
    }

    // ─── Issuer Management ────────────────────────────────────────

    /**
     * @notice Grant ISSUER_ROLE to an address.
     */
    function grantIssuer(address issuer) external onlyRole(ADMIN_ROLE) {
        grantRole(ISSUER_ROLE, issuer);
        emit IssuerGranted(issuer, msg.sender);
    }

    /**
     * @notice Revoke ISSUER_ROLE from an address.
     */
    function revokeIssuer(address issuer) external onlyRole(ADMIN_ROLE) {
        revokeRole(ISSUER_ROLE, issuer);
        emit IssuerRevoked(issuer, msg.sender);
    }
}
