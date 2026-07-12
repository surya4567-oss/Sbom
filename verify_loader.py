"""
Verification script for SBOM Analyzer Data Loader
"""
import os
import sys
from data_loader import load_all_data, DataLoaderError

def main():
    data_dir = os.path.join(os.path.dirname(__file__), "data", "sample")
    print(f"Data directory: {data_dir}")

    try:
        (
            applications,
            sbom_dependencies,
            vulnerability_db,
            license_rules,
            dependency_labels
        ) = load_all_data(data_dir)

        print("\n--- Load Verification Successful! ---")
        print(f"Applications Loaded:        {len(applications)}")
        print(f"SBOM Dependencies Loaded:   {len(sbom_dependencies)}")
        print(f"Vulnerabilities Loaded:     {len(vulnerability_db)}")
        print(f"License Rules Loaded:       {len(license_rules)}")
        print(f"Dependency Labels Loaded:   {len(dependency_labels)}")
        print("--------------------------------------")
        
        # Verify types and structures
        assert isinstance(applications, list)
        assert isinstance(vulnerability_db, list)
        assert isinstance(license_rules, list)
        assert hasattr(sbom_dependencies, "columns")  # DataFrame check
        assert hasattr(dependency_labels, "columns")  # DataFrame check
        
        print("Types and DataFrame validations passed.")
        
    except DataLoaderError as e:
        print(f"\nDataLoaderError occurred: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
