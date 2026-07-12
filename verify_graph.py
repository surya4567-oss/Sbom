"""
Verification script for SBOM Analyzer Graph Analyzer
"""
import os
import sys
from data_loader import load_all_data, DataLoaderError
from graph_analyzer import SBOMDependencyGraph

def main():
    data_dir = os.path.join(os.path.dirname(__file__), "data", "sample")
    print(f"Data directory: {data_dir}")

    try:
        # 1. Load data
        (
            applications,
            sbom_dependencies,
            vulnerability_db,
            license_rules,
            dependency_labels
        ) = load_all_data(data_dir)

        # 2. Build graph
        sbom_graph = SBOMDependencyGraph()
        sbom_graph.build_graph(applications, sbom_dependencies)

        print("\n--- Graph Node & Edge Verification ---")
        num_nodes = sbom_graph.graph.number_of_nodes()
        num_edges = sbom_graph.graph.number_of_edges()
        print(f"Total Nodes in Graph: {num_nodes}")
        print(f"Total Edges in Graph: {num_edges}")

        # Check total nodes > 10 apps
        assert num_nodes > 10, "Graph should contain application and library nodes"

        # 3. Verify counts for APP-001 (PaymentGateway)
        print("\n--- APP-001 (PaymentGateway) Dependency Check ---")
        direct_deps = sbom_graph.get_direct_dependencies("APP-001")
        transitive_deps = sbom_graph.get_transitive_dependencies("APP-001")
        total_deps = len(direct_deps) + len(transitive_deps)

        print(f"Direct dependencies count:     {len(direct_deps)}")
        print(f"Transitive dependencies count: {len(transitive_deps)}")
        print(f"Total dependencies count:      {total_deps}")

        # Each app must have exactly 50 dependencies total in the dataset
        assert total_deps == 50, f"Expected 50 total dependencies, found {total_deps}"

        # 4. Path Finding Verification
        print("\n--- Paths to Vulnerable Libraries (APP-001) ---")
        paths_to_vulns = sbom_graph.find_paths_to_vulnerable_libraries("APP-001", vulnerability_db)
        print(f"Found {len(paths_to_vulns)} vulnerable libraries reachable from APP-001")

        # Let's show paths for log4j-core
        log4j_ref = "lib:log4j-core@2.14.1"
        if log4j_ref in paths_to_vulns:
            print(f"\nPaths leading to log4j-core (vulnerable to Log4Shell):")
            for idx, path in enumerate(paths_to_vulns[log4j_ref]):
                print(f"  Path {idx + 1}: {' -> '.join(path)}")

        # 5. Application-level vulnerabilities (Deduplicated CVEs)
        print("\n--- Application-level Risk Profile (Deduplicated CVEs) ---")
        app_vulns = sbom_graph.get_application_vulnerabilities("APP-001", vulnerability_db)
        print(f"Unique CVEs affecting APP-001: {len(app_vulns)}")

        severity_counts = {}
        for v in app_vulns:
            sev = v["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        print("Vulnerability count by severity:")
        for sev, count in sorted(severity_counts.items()):
            print(f"  {sev}: {count}")

        # 5b. Maintenance Risk Verification
        print("\n--- Maintenance Risk Verification (18-Month Threshold) ---")
        maint_risks = sbom_graph.get_maintenance_risks("APP-001", vulnerability_db)
        print(f"Stale libraries flagged (>= 18 months): {len(maint_risks)}")
        
        high_maint = [r for r in maint_risks if r["risk_level"] == "High"]
        low_maint = [r for r in maint_risks if r["risk_level"] == "Low"]
        print(f"  High Severity (Unmaintained + CVEs):   {len(high_maint)}")
        print(f"  Low Severity (Unmaintained + No CVEs): {len(low_maint)}")
        
        # Check a few unmaintained risks
        if maint_risks:
            print("\nSample Stale Libraries:")
            for idx, r in enumerate(maint_risks[:3]):
                print(f"  - {r['dependency_name']} @ {r['version']} ({r['last_updated']}) - Staleness: {r['months_stale']} months")
                print(f"    Risk Level:  {r['risk_level']}")
                print(f"    Explanation: {r['explanation']}")

        # Verify that unmaintained + no CVE exists and has Low severity
        # (e.g. xstream or joda-time in APP-001)
        stale_names = {r["dependency_name"]: r for r in maint_risks}
        if "joda-time" in stale_names:
            assert stale_names["joda-time"]["risk_level"] == "Low", "Expected joda-time to be Low risk"
        if "xstream" in stale_names:
            # xstream has CVE-2022-41966 in our seed, so it should be High risk!
            assert stale_names["xstream"]["risk_level"] == "High", "Expected xstream to be High risk due to existing CVE"

        # Verification asserts passed
        print("\nGraph Analyzer Verification successful! All checks passed.")

        # 6. Export the complete graph to GraphML
        graphml_path = os.path.join(data_dir, "sbom_dependency_graph.graphml")
        import networkx as nx
        # GraphML doesn't support list attributes out-of-the-box easily without conversion to strings.
        # Let's clean node attributes (convert list attributes to string representation)
        g_export = sbom_graph.graph.copy()
        # Since our nodes do not have list attributes (except technology_stack, but we didn't add it as list, we stored standard strings/floats), it should be fine.
        nx.write_graphml(g_export, graphml_path)
        print(f"\n[Export] Saved full graph in GraphML format to: {graphml_path}")
        print("-> You can open this file in graph software like Gephi, Cytoscape, or yEd.")

        # 7. Render a PNG visualization of APP-001 (PaymentGateway) Subgraph
        print("\n[Visualization] Generating visual dependency subgraph for PaymentGateway (APP-001)...")
        import matplotlib
        matplotlib.use('Agg')  # Headless backend to prevent window opening
        import matplotlib.pyplot as plt

        app_id = "APP-001"
        app_node_id = f"app:{app_id}"
        
        # Get induced subgraph of app node + all its descendants (50 libraries)
        descendants = nx.descendants(sbom_graph.graph, app_node_id)
        subgraph_nodes = descendants | {app_node_id}
        subgraph = sbom_graph.graph.subgraph(subgraph_nodes).copy()

        # Identify vulnerable nodes in this subgraph to highlight them
        # Build set of vulnerable library names and versions
        vuln_set = set()
        for vuln in vulnerability_db:
            dep_name = vuln["dependency_name"]
            for ver in vuln["affected_versions"]:
                vuln_set.add((dep_name, ver))

        node_colors = []
        node_sizes = []
        labels = {}

        for node in subgraph.nodes():
            node_data = subgraph.nodes[node]
            if node_data.get("node_type") == "Application":
                node_colors.append("#2ecc71")  # Green for Application
                node_sizes.append(1200)
                labels[node] = node_data["name"]
            else:
                name = node_data["name"]
                ver = node_data["version"]
                labels[node] = f"{name}\n@{ver}"
                
                # Check if vulnerable
                if (name, ver) in vuln_set:
                    node_colors.append("#e74c3c")  # Red for Vulnerable Libraries
                    node_sizes.append(600)
                else:
                    # Check edge type
                    edge_data = sbom_graph.graph.get_edge_data(app_node_id, node)
                    if edge_data and edge_data.get("dependency_type") == "Direct":
                        node_colors.append("#3498db")  # Blue for Direct Dependencies
                        node_sizes.append(500)
                    else:
                        node_colors.append("#bdc3c7")  # Gray for Transitive Dependencies
                        node_sizes.append(300)

        plt.figure(figsize=(16, 12))
        
        # Use spring layout with seed for deterministic positioning
        pos = nx.spring_layout(subgraph, k=0.15, iterations=50, seed=42)
        
        # Draw nodes and edges
        nx.draw_networkx_nodes(subgraph, pos, node_color=node_colors, node_size=node_sizes, alpha=0.9)
        
        # Style edges
        direct_edges = [(u, v) for u, v, d in subgraph.edges(data=True) if d.get("dependency_type") == "Direct"]
        transitive_edges = [(u, v) for u, v, d in subgraph.edges(data=True) if d.get("dependency_type") == "Transitive"]
        
        nx.draw_networkx_edges(subgraph, pos, edgelist=direct_edges, edge_color="#2980b9", width=2.0, arrowstyle="->", arrowsize=15)
        nx.draw_networkx_edges(subgraph, pos, edgelist=transitive_edges, edge_color="#7f8c8d", width=1.0, style="dashed", arrowstyle="->", arrowsize=10)

        # Draw labels with clean layout
        nx.draw_networkx_labels(subgraph, pos, labels=labels, font_size=8, font_family="sans-serif", font_weight="bold")

        # Custom Legend
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor="#2ecc71", label="Application (PaymentGateway)"),
            Patch(facecolor="#3498db", label="Direct Dependency"),
            Patch(facecolor="#bdc3c7", label="Transitive Dependency"),
            Patch(facecolor="#e74c3c", label="Vulnerable Library (Known CVEs)")
        ]
        plt.legend(handles=legend_elements, loc="upper right", fontsize=10)
        
        plt.title("PaymentGateway (APP-001) Dependency Subgraph Map", fontsize=16, fontweight="bold", pad=20)
        plt.axis("off")
        plt.tight_layout()

        output_viz_path = os.path.join(data_dir, "payment_gateway_graph_viz.png")
        plt.savefig(output_viz_path, dpi=150, bbox_inches="tight")
        plt.close()
        print(f"[Visualization] Saved dependency subgraph image to: {output_viz_path}")

    except DataLoaderError as e:
        print(f"\nDataLoaderError occurred: {e}", file=sys.stderr)
        sys.exit(1)
    except AssertionError as e:
        print(f"\nAssertion check failed: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
