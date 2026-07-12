"""
Verification script for SBOM License Compatibility Engine
"""
import os
import sys
from data_loader import load_license_rules, DataLoaderError
from license_engine import LicenseCompatibilityEngine

def main():
    rules_path = os.path.join(os.path.dirname(__file__), "data", "sample", "license_rules.json")
    print(f"Loading license rules from: {rules_path}")

    try:
        # 1. Load rules
        rules = load_license_rules(rules_path)
        engine = LicenseCompatibilityEngine(rules)

        # 2. Define App Policies
        proprietary_policy = {
            "is_proprietary": True,
            "linking_type": "dynamic",
            "distribution_type": "saas"
        }
        
        redistributed_proprietary_policy = {
            "is_proprietary": True,
            "linking_type": "static",
            "distribution_type": "redistributed"
        }

        open_source_policy = {
            "is_proprietary": False,
            "linking_type": "dynamic",
            "distribution_type": "saas"
        }

        print("\n=== RUNNING LICENSE COMPATIBILITY TESTS ===\n")

        # Test Case 1: MIT
        eval_mit = engine.evaluate_compatibility("MIT", proprietary_policy)
        print(f"MIT (Proprietary App):")
        print(f"  Status:      {eval_mit['status']}")
        print(f"  Risk Level:  {eval_mit['risk_level']}")
        print(f"  Explanation: {eval_mit['explanation']}")
        assert eval_mit["status"] == "Compatible"
        assert eval_mit["risk_level"] == "Low"

        # Test Case 2: GPL-3.0 on Proprietary App
        eval_gpl_prop = engine.evaluate_compatibility("GPL-3.0", proprietary_policy)
        print(f"\nGPL-3.0 (Proprietary App):")
        print(f"  Status:      {eval_gpl_prop['status']}")
        print(f"  Risk Level:  {eval_gpl_prop['risk_level']}")
        print(f"  Explanation: {eval_gpl_prop['explanation']}")
        assert eval_gpl_prop["status"] == "Incompatible"
        assert eval_gpl_prop["risk_level"] == "High"

        # Test Case 3: GPL-3.0 on Open-Source App
        eval_gpl_os = engine.evaluate_compatibility("GPL-3.0", open_source_policy)
        print(f"\nGPL-3.0 (Open Source App):")
        print(f"  Status:      {eval_gpl_os['status']}")
        print(f"  Risk Level:  {eval_gpl_os['risk_level']}")
        print(f"  Explanation: {eval_gpl_os['explanation']}")
        assert eval_gpl_os["status"] == "Needs Review"

        # Test Case 4: LGPL-2.1 with dynamic linking
        eval_lgpl_dyn = engine.evaluate_compatibility("LGPL-2.1", proprietary_policy)
        print(f"\nLGPL-2.1 (Dynamic Linking):")
        print(f"  Status:      {eval_lgpl_dyn['status']}")
        print(f"  Risk Level:  {eval_lgpl_dyn['risk_level']}")
        print(f"  Explanation: {eval_lgpl_dyn['explanation']}")
        assert eval_lgpl_dyn["status"] == "Compatible"

        # Test Case 5: LGPL-2.1 with static linking
        eval_lgpl_stat = engine.evaluate_compatibility("LGPL-2.1", redistributed_proprietary_policy)
        print(f"\nLGPL-2.1 (Static Linking):")
        print(f"  Status:      {eval_lgpl_stat['status']}")
        print(f"  Risk Level:  {eval_lgpl_stat['risk_level']}")
        print(f"  Explanation: {eval_lgpl_stat['explanation']}")
        assert eval_lgpl_stat["status"] == "Low Risk Review"

        # Test Case 6: EPL-2.0 in Redistributed context
        eval_epl_redist = engine.evaluate_compatibility("EPL-2.0", redistributed_proprietary_policy)
        print(f"\nEPL-2.0 (Redistributed App):")
        print(f"  Status:      {eval_epl_redist['status']}")
        print(f"  Risk Level:  {eval_epl_redist['risk_level']}")
        print(f"  Explanation: {eval_epl_redist['explanation']}")
        assert eval_epl_redist["status"] == "Needs Review"

        # Test Case 7: Dual license (GPL-2.0 OR MIT) - should pick MIT
        eval_dual = engine.evaluate_compatibility("GPL-2.0 OR MIT", proprietary_policy)
        print(f"\nDual license 'GPL-2.0 OR MIT' (Proprietary App):")
        print(f"  Status:      {eval_dual['status']}")
        print(f"  Risk Level:  {eval_dual['risk_level']}")
        print(f"  Explanation: {eval_dual['explanation']}")
        assert eval_dual["status"] == "Compatible"
        assert "Selected the more compatible option" in eval_dual["explanation"]

        # Test Case 8: Multi-license (Apache-2.0 AND GPL-3.0) - should select GPL-3.0
        eval_multi = engine.evaluate_compatibility("Apache-2.0 AND GPL-3.0", proprietary_policy)
        print(f"\nMulti-license 'Apache-2.0 AND GPL-3.0' (Proprietary App):")
        print(f"  Status:      {eval_multi['status']}")
        print(f"  Risk Level:  {eval_multi['risk_level']}")
        print(f"  Explanation: {eval_multi['explanation']}")
        assert eval_multi["status"] == "Incompatible"
        assert "Selected the limiting rule" in eval_multi["explanation"]

        # Test Case 9: Unknown License
        eval_unk = engine.evaluate_compatibility("UNKNOWN", proprietary_policy)
        print(f"\nUNKNOWN license:")
        print(f"  Status:      {eval_unk['status']}")
        print(f"  Risk Level:  {eval_unk['risk_level']}")
        print(f"  Explanation: {eval_unk['explanation']}")
        assert eval_unk["status"] == "Needs Review"

        # Test Case 10: Blank License
        eval_blank = engine.evaluate_compatibility("", proprietary_policy)
        print(f"\nBlank/No license:")
        print(f"  Status:      {eval_blank['status']}")
        print(f"  Risk Level:  {eval_blank['risk_level']}")
        print(f"  Explanation: {eval_blank['explanation']}")
        assert eval_blank["status"] == "Unknown Legal Status"
        assert eval_blank["risk_level"] == "Critical"

        print("\nAll License Compatibility Engine tests passed successfully!")

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
