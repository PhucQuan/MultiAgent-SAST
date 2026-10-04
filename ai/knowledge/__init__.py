"""Knowledge card layer (RAG tĩnh cho Auditor/Skeptic)."""

from .loader import KnowledgeLoader, knowledge_loader
from .schema import FewShotExample, KnowledgeCard

__all__ = ["KnowledgeLoader", "knowledge_loader", "FewShotExample", "KnowledgeCard"]
