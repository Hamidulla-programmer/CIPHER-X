// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title CIPHER-X Evidence Anchor
/// @notice Stores only SHA-256 evidence hashes, never email content or PII.
contract EvidenceAnchor {
    struct Anchor { uint256 timestamp; address submitter; string caseId; }
    mapping(bytes32 => Anchor) private anchors;
    event EvidenceAnchored(bytes32 indexed evidenceHash, string indexed caseId, uint256 timestamp, address submitter);

    function anchorEvidence(bytes32 evidenceHash, string calldata caseId) external {
        require(anchors[evidenceHash].timestamp == 0, "Evidence already anchored");
        anchors[evidenceHash] = Anchor(block.timestamp, msg.sender, caseId);
        emit EvidenceAnchored(evidenceHash, caseId, block.timestamp, msg.sender);
    }

    function getAnchor(bytes32 evidenceHash) external view returns (uint256, address, string memory) {
        Anchor memory item = anchors[evidenceHash];
        return (item.timestamp, item.submitter, item.caseId);
    }
}
