"""
pytest fixtures — isolate each test run from the operator's real data.

Every test gets a fresh temp workspace with its own copy of config.yaml,
its own SQLite file, and its own (stubbed) ChromaDB so nothing pollutes
the on-disk engagement state.
"""
from __future__ import annotations

import importlib
import os
import shutil
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Redirect PROJECT_ROOT, config.yaml, and storage paths into tmp."""
    # Copy config.yaml so tests can mutate it.
    shutil.copy(ROOT / "config.yaml", tmp_path / "config.yaml")
    (tmp_path / "logs").mkdir(exist_ok=True)
    (tmp_path / "storage").mkdir(exist_ok=True)

    # Make `llm_bridge` importable from its real source while overriding
    # its PROJECT_ROOT to point at the tmp workspace.
    monkeypatch.syspath_prepend(str(ROOT))

    # Ensure any cached config/DB/cache singletons are reset for each test.
    for mod in list(sys.modules):
        if mod.startswith("llm_bridge") or mod in {"storage.db", "storage"}:
            sys.modules.pop(mod, None)

    # SQLModel keeps a global metadata across module reloads, so clear it
    # before the next test's `class Finding(SQLModel, table=True)` registers
    # again. Otherwise create_all tries to re-create indexes that already
    # exist in the metadata's index set.
    try:
        from sqlmodel import SQLModel
        SQLModel.metadata.clear()
    except Exception:
        pass

    # Stub chromadb + sentence_transformers so tests don't need real models.
    class _NoopColl:
        def __init__(self):
            self._rows = []
        def add(self, ids, documents=None, embeddings=None, metadatas=None):
            for i, _id in enumerate(ids):
                self._rows.append((_id, metadatas[i] if metadatas else {}, embeddings[i] if embeddings else []))
        def query(self, query_embeddings=None, n_results=1, where=None):
            hits = [r for r in self._rows if not where or all(r[1].get(k) == v for k, v in where.items())]
            hits = hits[:n_results]
            return {
                "ids": [[r[0] for r in hits]],
                "documents": [[""] * len(hits)],
                "metadatas": [[r[1] for r in hits]],
                "distances": [[0.0] * len(hits)],  # always "identical" — exercises dedup
            }
        def count(self): return len(self._rows)
        def delete(self, where=None):
            if where is None:
                self._rows.clear()
                return
            self._rows = [r for r in self._rows if not all(r[1].get(k) == v for k, v in where.items())]

    class _NoopClient:
        def __init__(self, *a, **kw): pass
        def get_or_create_collection(self, *a, **kw): return _NoopColl()
        def delete_collection(self, *a, **kw): pass

    chromadb = types.ModuleType("chromadb")
    chromadb.PersistentClient = lambda *a, **kw: _NoopClient()
    cfg = types.ModuleType("chromadb.config")
    cfg.Settings = lambda **kw: None
    sys.modules["chromadb"] = chromadb
    sys.modules["chromadb.config"] = cfg

    sent = types.ModuleType("sentence_transformers")
    sent.SentenceTransformer = lambda *a, **kw: types.SimpleNamespace(
        encode=lambda texts, **kk: [[0.0] * 8 for _ in texts]
    )
    sys.modules["sentence_transformers"] = sent

    # Point llm_bridge.PROJECT_ROOT at tmp_path via monkeypatch on import.
    import llm_bridge
    importlib.reload(llm_bridge)
    monkeypatch.setattr(llm_bridge, "PROJECT_ROOT", tmp_path, raising=False)

    yield tmp_path


@pytest.fixture
def disable_auth(_isolate):
    """Turn off auth in the cloned config.yaml."""
    import yaml
    p = _isolate / "config.yaml"
    data = yaml.safe_load(p.read_text())
    data["auth"]["enabled"] = False
    p.write_text(yaml.safe_dump(data))
    return p
