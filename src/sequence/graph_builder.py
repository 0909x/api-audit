from src.ingestion.models import RequestRecord
from src.sequence.chain_builder import ApiCallChain


def build_edges(chain: ApiCallChain) -> list[tuple[str, str]]:
    edges = []
    for i in range(len(chain.records) - 1):
        src = chain.records[i].normalized_endpoint()
        dst = chain.records[i + 1].normalized_endpoint()
        if src != dst:
            edges.append((src, dst))
    return edges


def serialize_edges(edges: list[tuple[str, str]]) -> str:
    parts = ", ".join(f"({src}, {dst})" for src, dst in edges)
    return f"({parts})" if parts else "()"


def build_acg(chain: ApiCallChain) -> str:
    edges = build_edges(chain)
    return serialize_edges(edges)
