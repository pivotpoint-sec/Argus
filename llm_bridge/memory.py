"""
ChromaDB-backed session memory with semantic dedup.

Security intent: give the LLM a local-only, persistent recollection of what
has already been found in this engagement so it can (a) correlate new
signals with old ones, (b) avoid re-raising duplicate findings (clustering),
and (c) surface follow-up opportunities that span multiple requests.
Nothing here ever leaves the machine.

Embeddings are generated via fastembed (ONNX runtime) instead of
sentence-transformers + torch. Same MiniLM model, ~800 MB smaller
install footprint, no CUDA wheels ever pulled.
"""
from __future__ import annotations

import uuid
from threading import Lock
from typing import Any, Optional

from .config import configure_logging, load_config, resolve_path

_log = configure_logging()

_client = None
_collection = None
_embedder = None
_lock = Lock()


def _get_embedder():
    global _embedder
    with _lock:
        if _embedder is None:
            from fastembed import TextEmbedding

            cfg = load_config()
            name = cfg.get("memory", {}).get(
                "embedding_model",
                "sentence-transformers/all-MiniLM-L6-v2",
            )
            cache_dir = cfg.get("memory", {}).get("embedding_cache_dir")
            _log.info("Loading local ONNX embedding model: %s", name)
            kwargs: dict[str, Any] = {"model_name": name}
            if cache_dir:
                kwargs["cache_dir"] = str(resolve_path(cache_dir))
            _embedder = TextEmbedding(**kwargs)
    return _embedder


def _embed(texts):
    """
    Return L2-normalised embeddings so cosine == dot product downstream.
    fastembed returns raw vectors (unlike sentence-transformers with
    normalize_embeddings=True), so we normalise here.
    """
    import numpy as np

    vecs = list(_get_embedder().embed(list(texts)))
    out = []
    for v in vecs:
        arr = np.asarray(v, dtype=float)
        n = float(np.linalg.norm(arr))
        if n > 0:
            arr = arr / n
        out.append([float(x) for x in arr])
    return out


def _get_collection():
    global _client, _collection
    with _lock:
        if _collection is None:
            import chromadb
            from chromadb.config import Settings

            cfg = load_config()
            persist = resolve_path(cfg.get("memory", {}).get("persist_dir", "storage/chroma"))
            persist.mkdir(parents=True, exist_ok=True)
            _client = chromadb.PersistentClient(
                path=str(persist),
                settings=Settings(anonymized_telemetry=False, allow_reset=True),
            )
            _collection = _client.get_or_create_collection(
                name="argus_findings",
                metadata={"description": "Argus session findings (local only)"},
            )
            _log.info("ChromaDB ready at %s", persist)
    return _collection


def add_finding(*, url, parameter, finding_type, detail, embedding_text, session_id):
    cfg = load_config().get("memory", {})
    if not cfg.get("enabled", True):
        return ""
    collection = _get_collection()
    doc_id = str(uuid.uuid4())
    embeddings = _embed([embedding_text])
    collection.add(
        ids=[doc_id],
        documents=[embedding_text],
        embeddings=embeddings,
        metadatas=[{
            "url": url,
            "parameter": parameter or "",
            "finding_type": finding_type,
            "detail": detail,
            "session_id": session_id,
            "added_at": uuid.uuid1().time,
        }],
    )
    _enforce_cap(session_id=session_id,
                 cap=int(cfg.get("max_entries_per_session", 10000)),
                 evict=int(cfg.get("fifo_evict_batch", 1000)))
    _log.debug("memory: added %s for %s", finding_type, url)
    return doc_id


def _enforce_cap(*, session_id, cap, evict):
    try:
        collection = _get_collection()
        res = collection.get(where={"session_id": session_id}, limit=cap + 1)
        ids = res.get("ids") or []
        if len(ids) <= cap:
            return
        metas = res.get("metadatas") or []
        paired = list(zip(ids, metas))
        try:
            paired.sort(key=lambda p: (p[1] or {}).get("added_at", 0))
        except Exception:
            pass
        victims = [pid for pid, _ in paired[:evict]]
        if victims:
            collection.delete(ids=victims)
            _log.info("memory: FIFO-evicted %d entries from session %s", len(victims), session_id)
    except Exception as exc:  # pragma: no cover
        _log.debug("memory: cap enforcement skipped: %s", exc)


def dedup_or_add(*, url, parameter, finding_type, detail, embedding_text, session_id):
    """
    Return (True, existing_doc_id) if a near-duplicate exists within
    memory.dedup_distance; else insert and return (False, new_doc_id).
    """
    cfg = load_config().get("memory", {})
    if not cfg.get("enabled", True):
        return False, ""
    threshold = float(cfg.get("dedup_distance", 0.12))
    collection = _get_collection()
    try:
        res = collection.query(
            query_embeddings=_embed([embedding_text]),
            n_results=1,
            where={"session_id": session_id},
        )
        ids = (res.get("ids") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]
        if ids and dists and dists[0] is not None and float(dists[0]) <= threshold:
            return True, str(ids[0])
    except Exception as exc:  # pragma: no cover
        _log.warning("memory: dedup query failed: %s", exc)
    new_id = add_finding(
        url=url, parameter=parameter, finding_type=finding_type,
        detail=detail, embedding_text=embedding_text, session_id=session_id,
    )
    return False, new_id


def search_related(query_text, n=5, session_id=None):
    if not load_config().get("memory", {}).get("enabled", True):
        return []
    collection = _get_collection()
    where = {"session_id": session_id} if session_id else None
    try:
        res = collection.query(
            query_embeddings=_embed([query_text]),
            n_results=max(1, n),
            where=where,
        )
    except Exception as exc:  # pragma: no cover
        _log.warning("memory: query failed: %s", exc)
        return []

    out = []
    ids = (res.get("ids") or [[]])[0]
    docs = (res.get("documents") or [[]])[0]
    metas = (res.get("metadatas") or [[]])[0]
    dists = (res.get("distances") or [[]])[0]
    for i, doc_id in enumerate(ids):
        meta = metas[i] if i < len(metas) else {}
        out.append({
            "id": doc_id,
            "document": docs[i] if i < len(docs) else "",
            "distance": dists[i] if i < len(dists) else None,
            **(meta or {}),
        })
    return out


def get_session_context(url, session_id=None):
    cfg = load_config().get("memory", {})
    if not cfg.get("enabled", True):
        return ""
    top_k = int(cfg.get("top_k_context", 5))
    hits = search_related(query_text=url, n=top_k, session_id=session_id)
    if not hits:
        return ""
    lines = []
    for h in hits:
        lines.append(
            f"- [{h.get('finding_type', '?')}] {h.get('url', '?')}"
            f" param={h.get('parameter') or '-'}"
            f" :: {h.get('detail', '')}"
        )
    return "\n".join(lines)


def clear_session(session_id=None):
    collection = _get_collection()
    try:
        if session_id:
            collection.delete(where={"session_id": session_id})
            _log.info("memory: cleared session %s", session_id)
        else:
            global _collection
            _client.delete_collection("argus_findings")  # type: ignore[union-attr]
            _collection = _client.get_or_create_collection(  # type: ignore[union-attr]
                name="argus_findings",
                metadata={"description": "Argus session findings (local only)"},
            )
            _log.info("memory: cleared ALL findings")
    except Exception as exc:  # pragma: no cover
        _log.warning("memory: clear failed: %s", exc)


def ping():
    try:
        _get_collection().count()
        return True
    except Exception as exc:  # pragma: no cover
        _log.warning("ChromaDB ping failed: %s", exc)
        return False
