"""Evidence ledger — sổ cái bằng chứng append-only cho mỗi finding.

Nguyên tắc: kết luận TP/FP phải truy ngược được tới file/dòng/commit cụ thể,
chứ không tới một đoạn văn do model viết ra. Vì vậy mọi thứ agent "biết" đều
phải tồn tại ở đây dưới dạng artifact có `content_hash` và `producer`.

Ledger là append-only có chủ đích: một tool chạy lại với tham số khác không
được ghi đè kết quả cũ, vì chuỗi bằng chứng dẫn tới verdict phải còn nguyên
để phản biện. Trùng lặp được khử bằng chính `content_hash`, nên chạy lại cùng
một tool với cùng tham số không làm ledger phình ra.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, Field

ArtifactType = Literal[
    "source_snippet",
    "dataflow_path",
    "backward_slice",
    "forward_slice",
    "call_graph",
    "cfg_context",
    "sanitizer_trace",
    "constant_propagation",
    "symbol_resolution",
    "config",
    "knowledge_card",
    "tool_result",
    "test_result",
]


def content_hash(payload: object) -> str:
    """Hash ổn định của nội dung artifact.

    `sort_keys` là bắt buộc: không có nó, cùng một dữ liệu serialize khác thứ
    tự sẽ cho hash khác nhau và cơ chế khử trùng lặp mất tác dụng.
    """
    blob = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()


class EvidenceReference(BaseModel):
    """Một mẩu bằng chứng có nguồn gốc rõ ràng."""

    artifact_id: str
    artifact_type: ArtifactType
    producer: str = Field(description="Module/tool đã sinh ra artifact này")
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    content_hash: str
    relevance: float = Field(default=1.0, ge=0.0, le=1.0)
    payload: dict = Field(default_factory=dict)

    @property
    def citation(self) -> str:
        """Dạng 'file:line' để đối chiếu với citation do LLM trích."""
        if self.file_path and self.line_start:
            return f"{self.file_path}:{self.line_start}"
        return self.artifact_id


class EvidenceLedger(BaseModel):
    """Tập artifact của một finding, giữ nguyên thứ tự thu thập."""

    artifacts: dict[str, EvidenceReference] = Field(default_factory=dict)
    order: list[str] = Field(default_factory=list)

    def add(
        self,
        *,
        artifact_type: ArtifactType,
        producer: str,
        payload: dict,
        file_path: str | None = None,
        line_start: int | None = None,
        line_end: int | None = None,
        relevance: float = 1.0,
    ) -> EvidenceReference:
        """Thêm artifact; trả artifact cũ nếu nội dung đã tồn tại."""
        digest = content_hash(payload)
        for existing in self.artifacts.values():
            if existing.content_hash == digest:
                return existing

        artifact_id = f"ev_{len(self.order) + 1:03d}"
        ref = EvidenceReference(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            producer=producer,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            content_hash=digest,
            relevance=relevance,
            payload=payload,
        )
        self.artifacts[artifact_id] = ref
        self.order.append(artifact_id)
        return ref

    def get(self, artifact_id: str) -> EvidenceReference | None:
        return self.artifacts.get(artifact_id)

    def ids(self) -> list[str]:
        return list(self.order)

    def citations(self) -> set[str]:
        """Mọi dạng 'file:line' hợp lệ, dùng để kiểm chứng citation của LLM."""
        return {a.citation for a in self.artifacts.values()}

    def by_type(self, artifact_type: ArtifactType) -> list[EvidenceReference]:
        return [a for a in self.artifacts.values() if a.artifact_type == artifact_type]

    def has_type(self, artifact_type: ArtifactType) -> bool:
        return any(a.artifact_type == artifact_type for a in self.artifacts.values())

    def __len__(self) -> int:
        return len(self.order)
