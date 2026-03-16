"""Compatibility wrapper: node.validators → tip_node.validators"""
from tip_node.validators import *
from tip_node.validators.tx_validator import validate_transaction, ValidationResult
