"""Compatibility wrapper: node.logger → tip_node.logger"""
from tip_node.logger import get_logger
__all__ = ["get_logger"]
