"""
Test runner script for IDPS test suite.
Executes all unit and integration tests using asyncio and reports results.
"""

import asyncio
import sys
import types
import traceback

# Shim pytest if not installed in local environment
if "pytest" not in sys.modules:
    pytest_mock = types.ModuleType("pytest")
    class MarkMock:
        @staticmethod
        def asyncio(fn):
            return fn
    pytest_mock.mark = MarkMock()
    sys.modules["pytest"] = pytest_mock

async def run():
    passed = 0
    failed = 0
    errors = []

    print("=" * 60)
    print("RUNNING IDPS TEST SUITE")
    print("=" * 60)

    # 1. test_engines.py
    try:
        from tests.unit.test_engines import (
            test_signature_engine_match,
            test_protocol_analyzer_dga_detection,
            test_behavior_analyzer_port_scan,
        )
        await test_signature_engine_match()
        passed += 1
        print("✓ test_signature_engine_match")

        await test_protocol_analyzer_dga_detection()
        passed += 1
        print("✓ test_protocol_analyzer_dga_detection")

        await test_behavior_analyzer_port_scan()
        passed += 1
        print("✓ test_behavior_analyzer_port_scan")
    except Exception as e:
        failed += 1
        errors.append(("test_engines", traceback.format_exc()))
        print("✗ test_engines failed:", e)

    # 2. test_decision.py
    try:
        from tests.unit.test_decision import (
            test_risk_scorer_and_enrichment,
            test_policy_engine_evaluation,
            test_threat_hunter_session,
        )
        await test_risk_scorer_and_enrichment()
        passed += 1
        print("✓ test_risk_scorer_and_enrichment")

        test_policy_engine_evaluation()
        passed += 1
        print("✓ test_policy_engine_evaluation")

        await test_threat_hunter_session()
        passed += 1
        print("✓ test_threat_hunter_session")
    except Exception as e:
        failed += 1
        errors.append(("test_decision", traceback.format_exc()))
        print("✗ test_decision failed:", e)

    # 3. test_enforcement.py
    try:
        from tests.unit.test_enforcement import (
            test_firewall_and_inline_execution,
            test_host_action_and_fail_mode,
        )
        await test_firewall_and_inline_execution()
        passed += 1
        print("✓ test_firewall_and_inline_execution")

        await test_host_action_and_fail_mode()
        passed += 1
        print("✓ test_host_action_and_fail_mode")
    except Exception as e:
        failed += 1
        errors.append(("test_enforcement", traceback.format_exc()))
        print("✗ test_enforcement failed:", e)

    # 4. test_deception.py
    try:
        from tests.unit.test_deception import (
            test_canary_tokens_lifecycle,
        )
        test_canary_tokens_lifecycle()
        passed += 1
        print("✓ test_canary_tokens_lifecycle")
    except Exception as e:
        failed += 1
        errors.append(("test_deception", traceback.format_exc()))
        print("✗ test_deception failed:", e)

    # 5. test_real_features.py
    try:
        from tests.unit.test_real_features import (
            test_suricata_eve_ingestion,
            test_firewall_allowlist_and_safeguards,
            test_network_sensor_capture_status,
            test_waf_real_inspection,
            test_pcap_offline_replay,
        )
        await test_suricata_eve_ingestion()
        passed += 1
        print("✓ test_suricata_eve_ingestion (Real EVE JSON & SID parsing)")

        await test_firewall_allowlist_and_safeguards()
        passed += 1
        print("✓ test_firewall_allowlist_and_safeguards (Real Safe Firewall)")

        await test_network_sensor_capture_status()
        passed += 1
        print("✓ test_network_sensor_capture_status (Honest Capture Status)")

        test_waf_real_inspection()
        passed += 1
        print("✓ test_waf_real_inspection (Real SQLi/Path Traversal checks)")

        test_pcap_offline_replay()
        passed += 1
        print("✓ test_pcap_offline_replay (Real PCAP Packet Normalization)")
    except Exception as e:
        failed += 1
        errors.append(("test_real_features", traceback.format_exc()))
        print("✗ test_real_features failed:", e)

    # 6. test_end_to_end.py
    try:
        from tests.integration.test_end_to_end import test_full_idps_pipeline_flow
        await test_full_idps_pipeline_flow()
        passed += 1
        print("✓ test_full_idps_pipeline_flow (End-to-End Pipeline)")
    except Exception as e:
        failed += 1
        errors.append(("test_end_to_end", traceback.format_exc()))
        print("✗ test_end_to_end failed:", e)

    print("=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)

    if errors:
        for name, err in errors:
            print(f"\n--- Error in {name} ---")
            print(err)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(run())
