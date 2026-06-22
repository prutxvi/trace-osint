"""TRACE OSINT - Investigation Graph Generator

Generates interactive network graphs showing entity relationships.
Uses NetworkX for graph construction and Pyvis for visualization.
"""

import json
from pathlib import Path
from typing import Optional

try:
    import networkx as nx
    from pyvis.network import Network
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

from src.models import Finding, Entity, EntityType
from src.config import PROJECT_ROOT


NODE_COLORS = {
    "email": "#ff6b6b",
    "username": "#4ecdc4",
    "domain": "#45b7d1",
    "url": "#96ceb4",
    "phone": "#ffeaa7",
    "ip_address": "#dfe6e9",
    "person": "#a29bfe",
    "organization": "#fd79a8",
    "unknown": "#b2bec3",
}

EDGE_COLORS = {
    "public_search": "#636e72",
    "public_social_profile": "#00b894",
    "public_api": "#0984e3",
    "public_registry": "#6c5ce7",
    "public_dns_record": "#00cec9",
    "public_certificate_transparency": "#fdcb6e",
    "public_whois_record": "#e17055",
    "public_archive": "#d63031",
}


def build_investigation_graph(
    findings: list[Finding],
    entities: list[Entity],
) -> Optional[object]:
    """Build a NetworkX graph from findings and entities."""
    if not NETWORKX_AVAILABLE:
        return None

    G = nx.DiGraph()

    for entity in entities:
        G.add_node(
            entity.value,
            type=entity.type.value,
            confidence=entity.confidence.score,
            label=entity.value[:30],
        )

    for finding in findings:
        source_node = finding.entity_value
        if source_node not in G:
            G.add_node(
                source_node,
                type=finding.entity_type.value,
                confidence=finding.confidence.score,
                label=source_node[:30],
            )

        details = finding.details or {}
        if "url" in details:
            target_node = details["url"]
            if target_node not in G:
                G.add_node(
                    target_node,
                    type="url",
                    confidence=0.5,
                    label=target_node[:30],
                )
            G.add_edge(
                source_node,
                target_node,
                source_type=finding.source.source_type,
                label=finding.label[:20],
            )

        if "platform" in details:
            platform_node = details["platform"]
            if platform_node not in G:
                G.add_node(
                    platform_node,
                    type="username",
                    confidence=0.8,
                    label=platform_node,
                )
            G.add_edge(
                source_node,
                platform_node,
                source_type="public_social_profile",
                label="found on",
            )

        if finding.entity_type == EntityType.ORGANIZATION:
            for officer in details.get("officers", []):
                officer_name = officer.get("name", "")
                if officer_name:
                    if officer_name not in G:
                        G.add_node(
                            officer_name,
                            type="person",
                            confidence=0.7,
                            label=officer_name[:30],
                        )
                    G.add_edge(
                        source_node,
                        officer_name,
                        source_type="public_registry",
                        label=officer.get("position", "officer"),
                    )

    return G


def generate_interactive_graph(
    findings: list[Finding],
    entities: list[Entity],
    case_id: str,
    output_dir: Optional[Path] = None,
) -> Optional[str]:
    """Generate an interactive HTML graph visualization."""
    if not NETWORKX_AVAILABLE:
        return None

    G = build_investigation_graph(findings, entities)
    if not G or len(G.nodes) == 0:
        return None

    net = Network(
        height="750px",
        width="100%",
        bgcolor="#0a0a0a",
        font_color="white",
        directed=True,
        notebook=False,
    )

    net.set_options("""
    {
        "physics": {
            "enabled": true,
            "forceAtlas2Based": {
                "gravitationalConstant": -100,
                "centralGravity": 0.01,
                "springLength": 100,
                "springConstant": 0.08
            },
            "solver": "forceAtlas2Based"
        },
        "interaction": {
            "hover": true,
            "navigationButtons": true,
            "keyboard": true
        }
    }
    """)

    for node, data in G.nodes(data=True):
        node_type = data.get("type", "unknown")
        color = NODE_COLORS.get(node_type, "#b2bec3")
        size = 10 + (data.get("confidence", 0.5) * 20)
        net.add_node(
            node,
            label=data.get("label", node[:20]),
            color=color,
            size=size,
            title=f"Type: {node_type}\nConfidence: {data.get('confidence', 0):.2f}",
            shape="dot" if node_type != "person" else "icon",
        )

    for source, target, data in G.edges(data=True):
        edge_color = EDGE_COLORS.get(data.get("source_type", ""), "#636e72")
        net.add_edge(
            source,
            target,
            color=edge_color,
            label=data.get("label", "")[:15],
            arrows="to",
        )

    if output_dir is None:
        output_dir = PROJECT_ROOT / "cases" / case_id / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / "investigation_graph.html"
    net.save_graph(str(output_path))

    return str(output_path)


def generate_graph_summary(findings: list[Finding], entities: list[Entity]) -> dict:
    """Generate a summary of the investigation graph."""
    if not NETWORKX_AVAILABLE:
        return {"error": "NetworkX not installed"}

    G = build_investigation_graph(findings, entities)
    if not G:
        return {"error": "No graph data"}

    node_types = {}
    for _, data in G.nodes(data=True):
        t = data.get("type", "unknown")
        node_types[t] = node_types.get(t, 0) + 1

    return {
        "total_nodes": len(G.nodes),
        "total_edges": len(G.edges),
        "node_types": node_types,
        "density": nx.density(G) if len(G.nodes) > 1 else 0,
        "connected_components": nx.number_weakly_connected_components(G),
    }
