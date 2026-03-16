"""Compatibility wrapper: node.validators.tx_validator → tip_node.validators.tx_validator"""
from tip_node.validators.tx_validator import (
    validate_transaction, ValidationResult,
    _validate_structure, _validate_schema,
    _validate_business, _validate_dag_integrity, _validate_state,
)
__all__ = ["validate_transaction", "ValidationResult"]
