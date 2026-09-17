"""Optional blockchain evidence anchoring for Polygon/Ethereum-compatible networks.

Only an existing SHA-256 evidence hash and a case ID are submitted. Raw email,
subjects, sender addresses and credentials never leave CIPHER-X.
"""
from __future__ import annotations
import os

ABI = [{"inputs":[{"internalType":"bytes32","name":"evidenceHash","type":"bytes32"},{"internalType":"string","name":"caseId","type":"string"}],"name":"anchorEvidence","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"evidenceHash","type":"bytes32"}],"name":"getAnchor","outputs":[{"internalType":"uint256","type":"uint256"},{"internalType":"address","type":"address"},{"internalType":"string","type":"string"}],"stateMutability":"view","type":"function"}]

try:
    from web3 import Web3
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False


def status() -> dict:
    configured = all(os.getenv(k) for k in ("CIPHERX_BLOCKCHAIN_RPC_URL", "CIPHERX_BLOCKCHAIN_CONTRACT", "CIPHERX_BLOCKCHAIN_PRIVATE_KEY"))
    return {"platform": os.getenv("CIPHERX_BLOCKCHAIN_PLATFORM", "Polygon Amoy testnet"), "configured": configured, "library_available": WEB3_AVAILABLE, "data_policy": "Only SHA-256 evidence hashes and case IDs are anchored; raw emails and personal data are never sent on-chain."}


def _contract():
    if not WEB3_AVAILABLE: raise RuntimeError("Blockchain library missing. Run pip install -r requirements.txt.")
    if not status()["configured"]: raise RuntimeError("Blockchain setup is incomplete. Configure RPC URL, deployed contract address and a dedicated testnet wallet private key locally.")
    web3 = Web3(Web3.HTTPProvider(os.environ["CIPHERX_BLOCKCHAIN_RPC_URL"]))
    if not web3.is_connected(): raise RuntimeError("Could not connect to the configured blockchain RPC endpoint.")
    return web3, web3.eth.contract(address=Web3.to_checksum_address(os.environ["CIPHERX_BLOCKCHAIN_CONTRACT"]), abi=ABI)


def anchor(case_id: str, evidence_hash: str) -> dict:
    web3, contract = _contract()
    account = web3.eth.account.from_key(os.environ["CIPHERX_BLOCKCHAIN_PRIVATE_KEY"])
    tx = contract.functions.anchorEvidence(bytes.fromhex(evidence_hash), case_id).build_transaction({"from":account.address,"nonce":web3.eth.get_transaction_count(account.address),"chainId":web3.eth.chain_id})
    signed = account.sign_transaction(tx)
    transaction_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = web3.eth.wait_for_transaction_receipt(transaction_hash, timeout=120)
    return {"case_id":case_id,"evidence_hash":evidence_hash,"transaction_hash":transaction_hash.hex(),"block_number":receipt.blockNumber,"network":status()["platform"],"status":"anchored"}


def verify(evidence_hash: str) -> dict:
    web3, contract = _contract()
    timestamp, submitter, case_id = contract.functions.getAnchor(bytes.fromhex(evidence_hash)).call()
    return {"anchored": bool(timestamp), "case_id":case_id, "timestamp":timestamp, "submitter":submitter, "network":status()["platform"]}
