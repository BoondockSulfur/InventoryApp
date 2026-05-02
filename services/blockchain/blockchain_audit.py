"""
Blockchain Audit Trail Service for InventoryApp

Provides immutable audit logs using blockchain technology.
Supports both private blockchain (Hyperledger Fabric) and public blockchain (Ethereum).

Features:
- Immutable transaction logs
- Cryptographic verification
- Timestamping
- Chain of custody
- Compliance reporting
"""

import hashlib
import json
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
import uuid

# For production, use web3.py for Ethereum or Hyperledger Fabric SDK
# This is a simplified implementation for demonstration

class Block:
    """
    Represents a single block in the blockchain

    Each block contains:
    - index: Position in chain
    - timestamp: When block was created
    - transactions: List of audit events
    - previous_hash: Hash of previous block
    - nonce: Proof of work nonce
    - hash: This block's hash
    """

    def __init__(self, index: int, transactions: List[Dict], previous_hash: str, timestamp: Optional[float] = None):
        self.index = index
        self.timestamp = timestamp or time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        """
        Calculate SHA-256 hash of block contents
        """
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'transactions': self.transactions,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce
        }, sort_keys=True)

        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty: int = 4):
        """
        Mine block using Proof of Work

        Args:
            difficulty: Number of leading zeros required in hash
        """
        target = '0' * difficulty

        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()

        print(f"Block mined: {self.hash}")

    def to_dict(self) -> Dict:
        """Convert block to dictionary"""
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'transactions': self.transactions,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'hash': self.hash
        }


class Blockchain:
    """
    Blockchain for audit trail

    Maintains chain of blocks with cryptographic integrity
    """

    def __init__(self, difficulty: int = 4):
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict] = []
        self.difficulty = difficulty
        self.mining_reward = 0  # No mining reward for audit chain

        # Create genesis block
        self.create_genesis_block()

    def create_genesis_block(self):
        """
        Create the first block in the chain
        """
        genesis_block = Block(0, [], "0")
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)

    def get_latest_block(self) -> Block:
        """Get the most recent block in the chain"""
        return self.chain[-1]

    def add_transaction(self, transaction: Dict):
        """
        Add a transaction to pending transactions

        Args:
            transaction: Dict containing audit event data
        """
        # Validate transaction
        required_fields = ['action', 'user_id', 'resource_type', 'resource_id']
        for field in required_fields:
            if field not in transaction:
                raise ValueError(f"Missing required field: {field}")

        # Add metadata
        transaction['transaction_id'] = str(uuid.uuid4())
        transaction['timestamp'] = datetime.utcnow().isoformat()

        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self):
        """
        Mine a new block with all pending transactions
        """
        if not self.pending_transactions:
            return None

        new_block = Block(
            index=len(self.chain),
            transactions=self.pending_transactions,
            previous_hash=self.get_latest_block().hash
        )

        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

        # Clear pending transactions
        self.pending_transactions = []

        return new_block

    def is_chain_valid(self) -> bool:
        """
        Verify the integrity of the blockchain

        Returns:
            True if chain is valid, False otherwise
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Verify current block's hash
            if current_block.hash != current_block.calculate_hash():
                print(f"Invalid hash at block {i}")
                return False

            # Verify link to previous block
            if current_block.previous_hash != previous_block.hash:
                print(f"Invalid previous_hash at block {i}")
                return False

        return True

    def get_transaction_proof(self, transaction_id: str) -> Optional[Dict]:
        """
        Get cryptographic proof of a transaction's existence

        Args:
            transaction_id: ID of transaction to prove

        Returns:
            Dictionary with proof data or None if not found
        """
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.get('transaction_id') == transaction_id:
                    return {
                        'transaction': transaction,
                        'block_index': block.index,
                        'block_hash': block.hash,
                        'block_timestamp': block.timestamp,
                        'chain_length': len(self.chain),
                        'verified': self.is_chain_valid()
                    }

        return None

    def get_resource_history(self, resource_type: str, resource_id: int) -> List[Dict]:
        """
        Get complete audit history for a resource

        Args:
            resource_type: Type of resource (item, user, budget, etc.)
            resource_id: ID of resource

        Returns:
            List of all transactions for this resource
        """
        history = []

        for block in self.chain:
            for transaction in block.transactions:
                if (transaction.get('resource_type') == resource_type and
                    transaction.get('resource_id') == resource_id):
                    history.append({
                        **transaction,
                        'block_index': block.index,
                        'block_hash': block.hash,
                        'block_timestamp': block.timestamp
                    })

        return sorted(history, key=lambda x: x['timestamp'])

    def export_chain(self) -> List[Dict]:
        """
        Export entire blockchain as JSON-serializable list
        """
        return [block.to_dict() for block in self.chain]

    def get_chain_summary(self) -> Dict:
        """
        Get summary statistics for the blockchain
        """
        total_transactions = sum(len(block.transactions) for block in self.chain)

        return {
            'chain_length': len(self.chain),
            'total_transactions': total_transactions,
            'latest_block_hash': self.get_latest_block().hash,
            'chain_valid': self.is_chain_valid(),
            'difficulty': self.difficulty,
            'pending_transactions': len(self.pending_transactions)
        }


class AuditLogger:
    """
    High-level audit logging interface

    Wraps blockchain operations with application-specific logic
    """

    def __init__(self, blockchain: Blockchain):
        self.blockchain = blockchain

    def log_item_created(self, item_id: int, item_name: str, user_id: int, tenant_id: str):
        """Log item creation event"""
        self.blockchain.add_transaction({
            'action': 'create',
            'resource_type': 'item',
            'resource_id': item_id,
            'user_id': user_id,
            'tenant_id': tenant_id,
            'details': {
                'item_name': item_name,
                'event': 'Item created'
            }
        })

    def log_item_updated(self, item_id: int, user_id: int, tenant_id: str, changes: Dict):
        """Log item update event"""
        self.blockchain.add_transaction({
            'action': 'update',
            'resource_type': 'item',
            'resource_id': item_id,
            'user_id': user_id,
            'tenant_id': tenant_id,
            'details': {
                'changes': changes,
                'event': 'Item updated'
            }
        })

    def log_item_deleted(self, item_id: int, user_id: int, tenant_id: str):
        """Log item deletion event"""
        self.blockchain.add_transaction({
            'action': 'delete',
            'resource_type': 'item',
            'resource_id': item_id,
            'user_id': user_id,
            'tenant_id': tenant_id,
            'details': {
                'event': 'Item deleted'
            }
        })

    def log_loan_created(self, loan_id: int, item_id: int, borrower_id: int, user_id: int, tenant_id: str):
        """Log loan creation"""
        self.blockchain.add_transaction({
            'action': 'create',
            'resource_type': 'loan',
            'resource_id': loan_id,
            'user_id': user_id,
            'tenant_id': tenant_id,
            'details': {
                'item_id': item_id,
                'borrower_id': borrower_id,
                'event': 'Loan created'
            }
        })

    def log_budget_transaction(self, budget_id: int, amount: float, transaction_type: str, user_id: int, tenant_id: str):
        """Log budget transaction"""
        self.blockchain.add_transaction({
            'action': 'transaction',
            'resource_type': 'budget',
            'resource_id': budget_id,
            'user_id': user_id,
            'tenant_id': tenant_id,
            'details': {
                'amount': amount,
                'transaction_type': transaction_type,
                'event': f'Budget {transaction_type}'
            }
        })

    def log_access(self, user_id: int, resource_type: str, resource_id: int, action: str, tenant_id: str):
        """Log access event"""
        self.blockchain.add_transaction({
            'action': action,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'user_id': user_id,
            'tenant_id': tenant_id,
            'details': {
                'event': f'{action.capitalize()} {resource_type}'
            }
        })

    def commit_logs(self):
        """
        Commit pending transactions to blockchain

        Should be called periodically (e.g., every 5 minutes or when 100 transactions accumulated)
        """
        if self.blockchain.pending_transactions:
            block = self.blockchain.mine_pending_transactions()
            if block:
                print(f"Mined block {block.index} with {len(block.transactions)} transactions")
                return block
        return None

    def verify_audit_trail(self, resource_type: str, resource_id: int) -> Dict:
        """
        Verify complete audit trail for a resource

        Returns:
            Verification result with history and chain validity
        """
        history = self.blockchain.get_resource_history(resource_type, resource_id)
        chain_valid = self.blockchain.is_chain_valid()

        return {
            'resource_type': resource_type,
            'resource_id': resource_id,
            'chain_valid': chain_valid,
            'history_count': len(history),
            'history': history,
            'verified_at': datetime.utcnow().isoformat()
        }


# ============================================================================
# Flask Integration
# ============================================================================

def init_blockchain_service(app):
    """
    Initialize blockchain service for Flask app
    """
    from flask import request, jsonify, g
    from flask_login import login_required, current_user

    # Create blockchain instance (in production, this would be persistent)
    blockchain = Blockchain(difficulty=4)
    audit_logger = AuditLogger(blockchain)

    # Store in app context
    app.blockchain = blockchain
    app.audit_logger = audit_logger

    # Auto-commit every 5 minutes (in production, use Celery)
    import threading
    import time

    def auto_commit():
        while True:
            time.sleep(300)  # 5 minutes
            audit_logger.commit_logs()

    # Start auto-commit thread
    commit_thread = threading.Thread(target=auto_commit, daemon=True)
    commit_thread.start()

    # API Routes
    @app.route('/api/blockchain/summary', methods=['GET'])
    @login_required
    def blockchain_summary():
        """Get blockchain summary"""
        return jsonify(blockchain.get_chain_summary())

    @app.route('/api/blockchain/verify', methods=['GET'])
    @login_required
    def verify_blockchain():
        """Verify blockchain integrity"""
        valid = blockchain.is_chain_valid()
        return jsonify({
            'valid': valid,
            'chain_length': len(blockchain.chain),
            'verified_at': datetime.utcnow().isoformat()
        })

    @app.route('/api/blockchain/resource/<resource_type>/<int:resource_id>/history', methods=['GET'])
    @login_required
    def resource_history(resource_type, resource_id):
        """Get audit history for a resource"""
        verification = audit_logger.verify_audit_trail(resource_type, resource_id)
        return jsonify(verification)

    @app.route('/api/blockchain/transaction/<transaction_id>/proof', methods=['GET'])
    @login_required
    def transaction_proof(transaction_id):
        """Get cryptographic proof of transaction"""
        proof = blockchain.get_transaction_proof(transaction_id)

        if not proof:
            return jsonify({'error': 'Transaction not found'}), 404

        return jsonify(proof)

    @app.route('/api/blockchain/commit', methods=['POST'])
    @login_required
    def commit_blockchain():
        """Manually commit pending transactions"""
        block = audit_logger.commit_logs()

        if not block:
            return jsonify({'message': 'No pending transactions to commit'})

        return jsonify({
            'message': 'Transactions committed',
            'block': block.to_dict()
        })

    @app.route('/api/blockchain/export', methods=['GET'])
    @login_required
    def export_blockchain():
        """Export entire blockchain (admin only)"""
        if not hasattr(current_user, 'role') or current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403

        chain_data = blockchain.export_chain()

        return jsonify({
            'chain': chain_data,
            'summary': blockchain.get_chain_summary(),
            'exported_at': datetime.utcnow().isoformat()
        })

    print("✅ Blockchain Audit Trail Service initialized")


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == '__main__':
    # Create blockchain
    blockchain = Blockchain(difficulty=2)  # Lower difficulty for demo
    audit_logger = AuditLogger(blockchain)

    # Log some events
    print("\n=== Logging Audit Events ===")
    audit_logger.log_item_created(1, 'Laptop Dell', 1, 'tenant-123')
    audit_logger.log_item_updated(1, 1, 'tenant-123', {'location': 'Office A'})
    audit_logger.log_loan_created(1, 1, 2, 1, 'tenant-123')

    # Commit logs
    print("\n=== Committing to Blockchain ===")
    audit_logger.commit_logs()

    # Verify chain
    print("\n=== Verifying Blockchain ===")
    print(f"Chain valid: {blockchain.is_chain_valid()}")

    # Get resource history
    print("\n=== Resource History ===")
    history = blockchain.get_resource_history('item', 1)
    for event in history:
        print(f"- {event['action']} at {event['timestamp']}")

    # Get summary
    print("\n=== Blockchain Summary ===")
    summary = blockchain.get_chain_summary()
    for key, value in summary.items():
        print(f"{key}: {value}")
