"""Compatibility wrapper: node.scheduler → tip_node.scheduler"""
from tip_node.scheduler import start_scheduled_tasks
__all__ = ["start_scheduled_tasks"]
