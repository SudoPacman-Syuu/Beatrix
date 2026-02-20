"""
BEATRIX AI Integration Module

Multi-model AI support for intelligent bug hunting:
- Anthropic Claude (Haiku for grunt work, Sonnet/Opus for complex analysis)
- AWS Bedrock integration
- OpenAI compatible endpoints

Architecture:
- Haiku: Fast recon, response parsing, bulk analysis, pattern matching
- Opus/Sonnet: Complex vulnerability analysis, exploit development, report writing
"""

from .assistant import AIAssistant, AIConfig, HaikuGrunt
from .ghost import GhostAgent, GhostCallback, GhostFinding, PrintCallback
from .tasks import Task, TaskPriority, TaskRouter

__all__ = [
    "AIAssistant",
    "HaikuGrunt",
    "AIConfig",
    "TaskRouter",
    "Task",
    "TaskPriority",
    "GhostAgent",
    "GhostCallback",
    "PrintCallback",
    "GhostFinding",
]
