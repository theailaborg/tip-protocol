"""Compatibility wrapper: node.config → tip_node.config"""
from tip_node.config import load_config, _parse_list
__all__ = ["load_config", "_parse_list"]
