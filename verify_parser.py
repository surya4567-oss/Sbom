"""
Verification script for CycloneDX SBOM Parser
"""
import os
import sys
from sbom_parser import CycloneDXParser, SBOMParserError

def main():
    sample_sbom_path = os.path.join(os.path.dirname(__file__), "data", "sample", "sample_cyclonedx.json")
    print(f"Loading sample SBOM from: {sample_sbom_path}")

    if not os.path.exists(sample_sbom_path):
        print(f"Error: Sample file does not exist at {sample_sbom_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(sample_sbom_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Parse content
        parser = CycloneDXParser(content)
        result = parser.parse()

        print("\n--- Application Metadata ---")
        app = result["application"]
        print(f"Name:      {app['name']}")
        print(f"Version:   {app['version']}")
        print(f"Type:      {app['type']}")
        print(f"Timestamp: {app['timestamp']}")
        print(f"Supplier:  {app['supplier']}")
        print(f"Bom Ref:   {app['bom_ref']}")

        print("\n--- Extracted Components ---")
        for comp in result["components"]:
            print(f"- {comp['group']}/{comp['name']} @ {comp['version']}")
            print(f"  Purl:     {comp['purl']}")
            print(f"  Type:     {comp['type']}")
            print(f"  Licenses: {', '.join(comp['licenses']) if comp['licenses'] else 'None'}")
            print(f"  Supplier: {comp['supplier']}")
            print(f"  Bom Ref:  {comp['bom_ref']}")

        print("\n--- Dependency Graph ---")
        dep_graph = result["dependency_graph"]
        print(f"Root Ref: {dep_graph['root_ref']}")
        print("Graph Adjacency List:")
        for ref, targets in dep_graph["graph"].items():
            print(f"  {ref} -> {targets}")

        print("\n--- Dependency Relationships (Direct vs Transitive) ---")
        for comp in result["components"]:
            ref = comp["bom_ref"]
            dep_type = dep_graph["dependency_types"].get(ref, "Unknown")
            print(f"  {comp['name']} ({ref}): {dep_type}")

        # Verification asserts
        assert app["name"] == "PaymentGateway"
        assert app["bom_ref"] == "payment-gateway-app"
        assert len(result["components"]) == 3
        
        # Verify direct vs transitive calculations
        # spring-core and hibernate-core are direct
        # log4j-core is transitive (child of spring-core)
        types = dep_graph["dependency_types"]
        assert types["pkg:maven/org.springframework/spring-core@5.3.18"] == "Direct"
        assert types["pkg:maven/org.hibernate/hibernate-core@5.6.10.Final"] == "Direct"
        assert types["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"] == "Transitive"

        print("\nVerification successful! All asserts passed.")

    except SBOMParserError as e:
        print(f"\nParser error occurred: {e}", file=sys.stderr)
        sys.exit(1)
    except AssertionError as e:
        print(f"\nAssertion check failed: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
