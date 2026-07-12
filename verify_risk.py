"""
Verification script for Weighted Risk Score Engine
"""
import os
import sys
from data_loader import load_all_data, DataLoaderError
from graph_analyzer import SBOMDependencyGraph
from license_engine import LicenseCompatibilityEngine
from risk_engine import WeightedRiskEngine, RiskEngineError

def main():
    data_dir = os.path.join(os.path.dirname(__file__), "data", "sample")
    print(f"Data directory: {data_dir}")

    try:
        # 1. Load datasets
        (
            applications,
            sbom_dependencies,
            vulnerability_db,
            license_rules,
            dependency_labels
        ) = load_all_data(data_dir)

        # 2. Build dependency graph
        sbom_graph = SBOMDependencyGraph()
        sbom_graph.build_graph(applications, sbom_dependencies)

        # 3. Initialize engines
        license_engine = LicenseCompatibilityEngine(license_rules)
        risk_engine = WeightedRiskEngine(license_engine)

        # Define Application Compliance Policy
        app_policy = {
            "is_proprietary": True,
            "linking_type": "dynamic",
            "distribution_type": "saas"
        }

        # 4. Evaluate Specific Dependency Risk (log4j-core)
        log4j_ref = "lib:log4j-core@2.14.1"
        print(f"\n=== EVALUATING DEPENDENCY RISK FOR '{log4j_ref}' (under APP-001) ===")
        dep_risk = risk_engine.calculate_dependency_risk(
            app_id="APP-001",
            lib_node_id=log4j_ref,
            sbom_graph=sbom_graph,
            vulnerability_db=vulnerability_db,
            app_policy=app_policy
        )
        print(f"Dependency Name: {dep_risk['dependency_name']}")
        print(f"Version:         {dep_risk['version']}")
        print(f"Calculated Score:{dep_risk['risk_score']}")
        print(f"Risk Category:   {dep_risk['risk_category']}")
        print("Breakdown Details:")
        for factor, details in dep_risk["breakdown"].items():
            print(f"  - {factor:<22}: Raw={details['raw']:>5}, Weighted={details['weighted']:>5.1f} ({details['detail']})")
        print(f"Explanation:\n  {dep_risk['explanation']}")

        assert 0.0 <= dep_risk["risk_score"] <= 100.0
        assert dep_risk["risk_category"] in ("Low", "Moderate", "Medium", "High", "Critical")

        # 5. Evaluate Application Aggregate Risk (APP-001 PaymentGateway)
        print("\n=== EVALUATING APPLICATION AGGREGATE RISK FOR APP-001 (PaymentGateway) ===")
        app1_risk = risk_engine.calculate_application_risk(
            app_id="APP-001",
            sbom_graph=sbom_graph,
            vulnerability_db=vulnerability_db,
            app_policy=app_policy
        )
        print(f"App Name:        {app1_risk['app_name']}")
        print(f"Calculated Score:{app1_risk['risk_score']}")
        print(f"Risk Category:   {app1_risk['risk_category']}")
        print("Breakdown Details:")
        for factor, details in app1_risk["breakdown"].items():
            print(f"  - {factor:<22}: Raw={details['raw']:>5.1f}, Weighted={details['weighted']:>5.1f} ({details['detail']})")
        print(f"Explanation:\n  {app1_risk['explanation']}")

        assert 0.0 <= app1_risk["risk_score"] <= 100.0

        # 6. Evaluate Application Aggregate Risk (APP-004 HRPlatform)
        print("\n=== EVALUATING APPLICATION AGGREGATE RISK FOR APP-004 (HRPlatform) ===")
        app4_risk = risk_engine.calculate_application_risk(
            app_id="APP-004",
            sbom_graph=sbom_graph,
            vulnerability_db=vulnerability_db,
            app_policy=app_policy
        )
        print(f"App Name:        {app4_risk['app_name']}")
        print(f"Calculated Score:{app4_risk['risk_score']}")
        print(f"Risk Category:   {app4_risk['risk_category']}")
        print("Breakdown Details:")
        for factor, details in app4_risk["breakdown"].items():
            print(f"  - {factor:<22}: Raw={details['raw']:>5.1f}, Weighted={details['weighted']:>5.1f} ({details['detail']})")
        print(f"Explanation:\n  {app4_risk['explanation']}")

        assert 0.0 <= app4_risk["risk_score"] <= 100.0

        print("\nWeighted Risk Score Engine Verification successful! All asserts passed.")

    except DataLoaderError as e:
        print(f"\nDataLoaderError occurred: {e}", file=sys.stderr)
        sys.exit(1)
    except RiskEngineError as e:
        print(f"\nRiskEngineError occurred: {e}", file=sys.stderr)
        sys.exit(1)
    except AssertionError as e:
        print(f"\nAssertion check failed: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
