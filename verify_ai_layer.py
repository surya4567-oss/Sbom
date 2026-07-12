"""
Verification script for the AI Intelligence Layer (Phases 9-14)
"""
import os
import sys

from data_loader import load_all_data, DataLoaderError
from graph_analyzer import SBOMDependencyGraph
from license_engine import LicenseCompatibilityEngine
from risk_engine import WeightedRiskEngine

from reports.report_generator import generate_full_report
from reports.json_export import export_json
from reports.html_export import export_html
from reports.pdf_export import export_pdf

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

        app_policy = {
            "is_proprietary": True,
            "linking_type": "dynamic",
            "distribution_type": "saas"
        }

        # 4. Generate the full report (incorporating AI Context and all services)
        print("\n=== GENERATING FULL AI REPORT ===")
        report = generate_full_report(
            applications,
            sbom_graph,
            vulnerability_db,
            app_policy,
            risk_engine
        )
        
        output_dir = os.path.join(os.path.dirname(__file__), "reports", "output")
        
        # 5. Export to different formats
        print("\n=== EXPORTING REPORTS ===")
        export_json(report, os.path.join(output_dir, "report.json"))
        export_html(report, os.path.join(output_dir, "report.html"))
        export_pdf(report, os.path.join(output_dir, "report.pdf"))

        print("\nAI Intelligence Layer Verification successful! Check reports/output/ directory.")

    except DataLoaderError as e:
        print(f"Failed to load data: {e}")
        print("Make sure you have run 'python generate_sample_data.py' first.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
