"""Casos de uso comunes: carga, normalizacion, estadisticas y exportacion."""
from __future__ import annotations
import json
import logging
import math
from collections import Counter as ByteCounter
from collections import Counter
from pathlib import Path
from .models import Finding
LOGGER = logging.getLogger(__name__)

HIGH_ENTROPY_THRESHOLD = 7.5

class Service:
    """Base reutilizable para adaptadores especificos de cada herramienta."""
    def inspect(self, target: Path) -> list[Finding]:
        if not target.exists(): raise FileNotFoundError(target)
        data = target.read_bytes()
        if not data:
            return [Finding(category="empty_file", value=str(target), source=str(target), severity="info")]
        counts = ByteCounter(data)
        length = len(data)
        entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
        severity = "high" if entropy >= HIGH_ENTROPY_THRESHOLD else ("medium" if entropy >= 6.0 else "info")
        category = "high_entropy_possible_packed_or_encrypted" if entropy >= HIGH_ENTROPY_THRESHOLD else "entropy_score"
        return [Finding(category=category, value=f"{entropy:.3f} bits/byte", source=str(target), severity=severity)]
    @staticmethod
    def export(findings: list[Finding], destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps([item.to_dict() for item in findings], indent=2) + "\n", encoding="utf-8")
    @staticmethod
    def stats(findings: list[Finding]) -> dict[str, object]:
        return {"total": len(findings), "by_category": dict(Counter(item.category for item in findings)), "by_severity": dict(Counter(item.severity for item in findings))}
