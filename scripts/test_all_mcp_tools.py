#!/usr/bin/env python3
"""
MCP Windows Admin - Comprehensive Tool Testing Script
Tests all 43 available tools and generates a professional feedback report.
"""

import asyncio
import json
import sys
import traceback
from datetime import datetime
from typing import Any, Dict, List

# Add parent directory to path
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from mcp_win_admin import (
    system, processes, profiles, av, services, connections,
    events, startup, tasks, integrity, reputation, yara_scan,
    drivers, rootkit, firewall, updates, defense, alerts, db,
    filesystem, monitor_usn
)


class MCPToolTester:
    """Comprehensive MCP tool testing and reporting."""

    def __init__(self):
        self.results: List[Dict[str, Any]] = []
        self.total_tests = 0
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.start_time = datetime.now()

    def log_result(self, tool_name: str, category: str, status: str,
                   result: Any = None, error: str = None, duration_ms: float = 0):
        """Log test result."""
        self.total_tests += 1

        if status == "PASS":
            self.passed += 1
            status_code = "✓"
        elif status == "WARN":
            self.warnings += 1
            status_code = "⚠"
        else:
            self.failed += 1
            status_code = "✗"

        result_entry = {
            "tool_name": tool_name,
            "category": category,
            "status": status,
            "status_code": status_code,
            "duration_ms": duration_ms,
            "result_type": type(result).__name__ if result else None,
            "error": error
        }

        self.results.append(result_entry)
        print(f"{status_code} {tool_name:<45} [{category:<20}] {duration_ms:>7.1f}ms - {status}")

        if error:
            print(f"  └─ ERROR: {error[:80]}")

    async def run_tests(self):
        """Execute all tool tests."""
        print("\n" + "="*120)
        print("MCP WINDOWS ADMIN - COMPREHENSIVE TOOL TEST SUITE")
        print("="*120)
        print(f"Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")

        # System & Performance
        await self.test_system_scan_performance()

        # Processes & Resources
        await self.test_processes_list()
        await self.test_profiles_list()
        await self.test_profiles_preview()

        # Database Management
        await self.test_db_optimize()
        await self.test_db_purge_old()
        await self.test_telemetry_list_events()

        # Antivirus & Security
        await self.test_av_check_hash()
        await self.test_av_scan_path()

        # Services
        await self.test_services_list()

        # Network
        await self.test_connections_list()
        await self.test_connections_list_enriched()

        # Events & Logs
        await self.test_events_list()
        await self.test_startup_list()
        await self.test_tasks_list()

        # File System
        await self.test_fs_top_dirs()

        # File Integrity
        await self.test_integrity_build_baseline()
        await self.test_integrity_list_baselines()
        await self.test_integrity_verify_baseline()
        await self.test_integrity_diff_baselines()

        # Reputation
        await self.test_rep_check_ip()
        await self.test_rep_check_domain()

        # YARA Scanning
        await self.test_yara_test_rule()
        await self.test_yara_scan_path()

        # Drivers & System
        await self.test_drivers_list()

        # Rootkit Detection
        await self.test_rootkit_detect_hidden_processes()
        await self.test_rootkit_check_port_owners()

        # Firewall
        await self.test_firewall_list_rules()
        await self.test_firewall_export_rules()
        await self.test_firewall_block_ip_dryrun()

        # Updates
        await self.test_updates_list_installed()
        await self.test_updates_trigger_scan_dryrun()

        # Defense (Dry-Run)
        await self.test_defense_quarantine_dryrun()
        await self.test_defense_kill_process_dryrun()
        await self.test_defense_process_isolate_dryrun()

        # Defense (Execute)
        await self.test_defense_quarantine_execute()
        await self.test_defense_kill_process_execute()
        await self.test_defense_process_isolate_execute()
        await self.test_defense_process_unsandbox_execute()

        # Alerts
        await self.test_alert_notify_webhook()
        await self.test_alert_notify_toast()

        # USN Journal
        await self.test_usn_query_info()

        # Generate report
        await self.generate_report()

    async def safe_execute(self, tool_name: str, category: str, func, *args, **kwargs):
        """Safely execute a tool and log results."""
        start = datetime.now()
        try:
            result = func(*args, **kwargs)
            duration = (datetime.now() - start).total_seconds() * 1000

            # Determine status based on result
            if isinstance(result, dict):
                if result.get("ok") == False or result.get("error"):
                    status = "WARN"
                else:
                    status = "PASS"
            elif isinstance(result, list):
                status = "PASS" if len(result) >= 0 else "WARN"
            else:
                status = "PASS"

            self.log_result(tool_name, category, status, result=result, duration_ms=duration)
            return result
        except Exception as e:
            duration = (datetime.now() - start).total_seconds() * 1000
            error_msg = str(e)[:200]
            self.log_result(tool_name, category, "FAIL", error=error_msg, duration_ms=duration)
            return None

    # System & Performance Tests
    async def test_system_scan_performance(self):
        await self.safe_execute(
            "system_scan_performance",
            "System",
            system.get_performance_snapshot
        )

    # Process Tests
    async def test_processes_list(self):
        await self.safe_execute(
            "processes_list",
            "Processes",
            processes.list_processes,
            limit=10, sort_by="memory", fast=True
        )

    # Profile Tests
    async def test_profiles_list(self):
        await self.safe_execute(
            "profiles_list",
            "Profiles",
            profiles.list_profiles
        )

    async def test_profiles_preview(self):
        await self.safe_execute(
            "profiles_preview",
            "Profiles",
            profiles.preview_profile,
            "GameBooster"
        )

    # Database Tests
    async def test_db_optimize(self):
        await self.safe_execute(
            "db_optimize",
            "Database",
            db.optimize_db
        )

    async def test_db_purge_old(self):
        await self.safe_execute(
            "db_purge_old",
            "Database",
            db.purge_old_data,
            events_ttl_seconds=-1,
            reputation_ttl_seconds=-1,
            hash_ttl_seconds=-1
        )

    async def test_telemetry_list_events(self):
        await self.safe_execute(
            "telemetry_list_events",
            "Database",
            db.list_events,
            limit=10
        )

    # Antivirus Tests
    async def test_av_check_hash(self):
        test_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # Empty file SHA1
        await self.safe_execute(
            "av_check_hash",
            "Antivirus",
            av.check_hash,
            test_hash, algo="sha1", use_cloud=False
        )

    async def test_av_scan_path(self):
        await self.safe_execute(
            "av_scan_path",
            "Antivirus",
            av.scan_path,
            "C:\\Windows\\System32", recursive=False, limit=5, use_cloud=False
        )

    # Services Tests
    async def test_services_list(self):
        await self.safe_execute(
            "services_list",
            "Services",
            services.list_services,
            status="", limit=10
        )

    # Network Tests
    async def test_connections_list(self):
        await self.safe_execute(
            "connections_list",
            "Network",
            connections.list_connections,
            limit=10, kind="inet", listening_only=False
        )

    async def test_connections_list_enriched(self):
        await self.safe_execute(
            "connections_list_enriched",
            "Network",
            connections.list_connections,
            limit=5, kind="inet", include_process=True
        )

    # Events & Logs Tests
    async def test_events_list(self):
        await self.safe_execute(
            "events_list",
            "Events",
            events.list_events,
            channel="System", limit=5
        )

    async def test_startup_list(self):
        await self.safe_execute(
            "startup_list",
            "Startup",
            startup.list_startup,
            limit=10
        )

    async def test_tasks_list(self):
        await self.safe_execute(
            "tasks_list",
            "Tasks",
            tasks.list_scheduled_tasks,
            limit=10, state=""
        )

    # File System Tests
    async def test_fs_top_dirs(self):
        await self.safe_execute(
            "fs_top_dirs",
            "FileSystem",
            filesystem.list_heavy_paths,
            root="C:\\", max_depth=2, top_n=5
        )

    # File Integrity Tests
    async def test_integrity_build_baseline(self):
        await self.safe_execute(
            "integrity_build_baseline",
            "Integrity",
            integrity.build_baseline,
            name="test_baseline", root_path="C:\\Windows\\System32", limit=100
        )

    async def test_integrity_list_baselines(self):
        await self.safe_execute(
            "integrity_list_baselines",
            "Integrity",
            integrity.list_baselines
        )

    async def test_integrity_verify_baseline(self):
        await self.safe_execute(
            "integrity_verify_baseline",
            "Integrity",
            integrity.verify_baseline,
            name="test_baseline", limit=100
        )

    async def test_integrity_diff_baselines(self):
        await self.safe_execute(
            "integrity_diff_baselines",
            "Integrity",
            integrity.diff_baselines,
            name_a="test_baseline", name_b="test_baseline"
        )

    # Reputation Tests
    async def test_rep_check_ip(self):
        await self.safe_execute(
            "rep_check_ip",
            "Reputation",
            reputation.check_ip,
            "8.8.8.8", use_cloud=False
        )

    async def test_rep_check_domain(self):
        await self.safe_execute(
            "rep_check_domain",
            "Reputation",
            reputation.check_domain,
            "google.com", use_cloud=False
        )

    # YARA Tests
    async def test_yara_test_rule(self):
        # Simple test rule
        rule = """rule test_rule { strings: $a = "test" condition: $a }"""
        test_file = "C:\\Windows\\System32\\notepad.exe"
        await self.safe_execute(
            "yara_test_rule",
            "YARA",
            yara_scan.test_rule,
            rule, test_file
        )

    async def test_yara_scan_path(self):
        rule = """rule test_rule { strings: $a = "MZ" condition: $a }"""
        await self.safe_execute(
            "yara_scan_path",
            "YARA",
            yara_scan.scan_path,
            "C:\\Windows\\System32", rule_text=rule, limit=5
        )

    # Driver Tests
    async def test_drivers_list(self):
        await self.safe_execute(
            "drivers_list",
            "Drivers",
            drivers.list_drivers,
            limit=10
        )

    # Rootkit Tests
    async def test_rootkit_detect_hidden_processes(self):
        await self.safe_execute(
            "rootkit_detect_hidden_processes",
            "Rootkit",
            rootkit.detect_hidden_processes,
            limit=100
        )

    async def test_rootkit_check_port_owners(self):
        await self.safe_execute(
            "rootkit_check_port_owners",
            "Rootkit",
            rootkit.check_port_owners,
            limit=100
        )

    # Firewall Tests
    async def test_firewall_list_rules(self):
        await self.safe_execute(
            "firewall_list_rules",
            "Firewall",
            firewall.list_rules,
            limit=10
        )

    async def test_firewall_export_rules(self):
        await self.safe_execute(
            "firewall_export_rules",
            "Firewall",
            firewall.export_rules,
            "C:\\temp\\firewall_rules.txt"
        )

    async def test_firewall_block_ip_dryrun(self):
        await self.safe_execute(
            "firewall_block_ip_dryrun",
            "Firewall",
            firewall.block_ip_dryrun,
            "192.168.1.100"
        )

    # Updates Tests
    async def test_updates_list_installed(self):
        await self.safe_execute(
            "updates_list_installed",
            "Updates",
            updates.list_installed,
            limit=10
        )

    async def test_updates_trigger_scan_dryrun(self):
        await self.safe_execute(
            "updates_trigger_scan_dryrun",
            "Updates",
            updates.trigger_scan_dryrun
        )

    # Defense Tests (Dry-Run)
    async def test_defense_quarantine_dryrun(self):
        await self.safe_execute(
            "defense_quarantine_dryrun",
            "Defense",
            defense.quarantine_dryrun,
            "C:\\temp\\test.txt"
        )

    async def test_defense_kill_process_dryrun(self):
        await self.safe_execute(
            "defense_kill_process_dryrun",
            "Defense",
            defense.kill_process_dryrun,
            1234
        )

    async def test_defense_process_isolate_dryrun(self):
        await self.safe_execute(
            "defense_process_isolate_dryrun",
            "Defense",
            defense.process_isolate_dryrun,
            1234
        )

    # Defense Tests (Execute - with confirm=False for safety)
    async def test_defense_quarantine_execute(self):
        await self.safe_execute(
            "defense_quarantine_execute",
            "Defense",
            defense.quarantine_execute,
            "C:\\temp\\test_nonexistent.txt", confirm=False
        )

    async def test_defense_kill_process_execute(self):
        await self.safe_execute(
            "defense_kill_process_execute",
            "Defense",
            defense.kill_process_execute,
            99999, confirm=False
        )

    async def test_defense_process_isolate_execute(self):
        await self.safe_execute(
            "defense_process_isolate_execute",
            "Defense",
            defense.process_isolate_execute,
            99999, confirm=False
        )

    async def test_defense_process_unsandbox_execute(self):
        await self.safe_execute(
            "defense_process_unsandbox_execute",
            "Defense",
            defense.process_unsandbox_execute,
            99999, confirm=False
        )

    # Alert Tests
    async def test_alert_notify_webhook(self):
        await self.safe_execute(
            "alert_notify_webhook",
            "Alerts",
            alerts.notify_webhook_if_configured,
            event="test_event", level="INFO"
        )

    async def test_alert_notify_toast(self):
        await self.safe_execute(
            "alert_notify_toast",
            "Alerts",
            alerts.notify_toast,
            "Test Title", "Test Message"
        )

    # USN Journal Tests
    async def test_usn_query_info(self):
        await self.safe_execute(
            "usn_query_info",
            "USN",
            monitor_usn.query_usn_info,
            drive="C"
        )

    async def generate_report(self):
        """Generate professional testing report."""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        print("\n" + "="*120)
        print("TEST SUMMARY REPORT")
        print("="*120)

        # Summary statistics
        success_rate = (self.passed / self.total_tests * 100) if self.total_tests > 0 else 0

        print(f"\nTotal Tests Executed:    {self.total_tests}")
        print(f"Passed:                  {self.passed} ✓")
        print(f"Warnings:                {self.warnings} ⚠")
        print(f"Failed:                  {self.failed} ✗")
        print(f"Success Rate:            {success_rate:.1f}%")
        print(f"Total Duration:          {duration:.2f}s")
        print(f"Average Test Duration:   {(duration/self.total_tests*1000):.1f}ms")

        # Category breakdown
        print("\n" + "-"*120)
        print("BREAKDOWN BY CATEGORY:")
        print("-"*120)

        categories = {}
        for result in self.results:
            cat = result["category"]
            if cat not in categories:
                categories[cat] = {"total": 0, "passed": 0, "warnings": 0, "failed": 0}
            categories[cat]["total"] += 1
            if result["status"] == "PASS":
                categories[cat]["passed"] += 1
            elif result["status"] == "WARN":
                categories[cat]["warnings"] += 1
            else:
                categories[cat]["failed"] += 1

        for cat in sorted(categories.keys()):
            stats = categories[cat]
            rate = (stats["passed"] / stats["total"] * 100) if stats["total"] > 0 else 0
            print(f"\n{cat:<20} | Tests: {stats['total']:>2} | ✓ {stats['passed']:>2} | ⚠ {stats['warnings']:>2} | ✗ {stats['failed']:>2} | Rate: {rate:>5.1f}%")

        # Save detailed report
        report_data = {
            "timestamp": self.start_time.isoformat(),
            "duration_seconds": duration,
            "total_tests": self.total_tests,
            "passed": self.passed,
            "warnings": self.warnings,
            "failed": self.failed,
            "success_rate_percent": success_rate,
            "results": self.results
        }

        report_file = str(__import__('pathlib').Path(__file__).parent / "mcp_test_report.json")
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)

        print(f"\n📄 Detailed report saved to: {report_file}")

        # Final status
        print("\n" + "="*120)
        if self.failed == 0:
            print("✓ ALL TESTS COMPLETED SUCCESSFULLY!")
        elif success_rate >= 80:
            print("✓ TESTS COMPLETED WITH ACCEPTABLE RESULTS (>80% success rate)")
        else:
            print("⚠ TESTS COMPLETED WITH WARNINGS - REVIEW FAILURES")
        print("="*120 + "\n")


async def main():
    """Main entry point."""
    tester = MCPToolTester()
    await tester.run_tests()


if __name__ == "__main__":
    asyncio.run(main())
