"""Marlowe the AI analyst: a local LLM that explains computed results via read-only tools."""

from marlowe.assistant.agent import Analyst, Answer, Verification, verify_answer
from marlowe.assistant.ollama import ChatClient, OllamaClient, OllamaError
from marlowe.assistant.tools import AnalysisTools

__all__ = [
    "AnalysisTools",
    "Analyst",
    "Answer",
    "ChatClient",
    "OllamaClient",
    "OllamaError",
    "Verification",
    "verify_answer",
]
