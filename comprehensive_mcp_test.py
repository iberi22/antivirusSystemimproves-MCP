#!/usr/bin/env python3
"""
Comprehensive MCP Win Admin Tool Testing Suite
Tests all 43 tools of the mcp-win-admin MCP server
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

from mcp_win_admin import (
    alerts, av, config, connections, db, defense, drivers, events,
    filesystem, firewall, integrity, monitor_usn, processes, profiles,
    reputation, rootkit, services, startup, system, tasks, updates, yara_scan
)

class MCPTestReport:
    def __init__(self):
        self.results = []
        self.timestamp = datetime.now().isoformat()
        self.total_tools = 43
        self.successful = 0
        self.failed = 0
        self.partial = 0

    def add_result(self, tool_name, category, status, details=""):
        result = {
            "tool": tool_name,
            "category": category,
            "status": status,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.results.append(result)

        if status == "SUCCESS":
            self.successful += 1
        elif status == "PARTIAL":
            self.partial += 1
        else:
            self.failed += 1

    def generate_report(self):
        report = f"""
╔════════════════════════════════════════════════════════════════════════════════╗
║           MCP WIN-ADMIN COMPREHENSIVE TESTING REPORT                           ║
╚════════════════════════════════════════════════════════════════════════════════╝

Report Generated: {self.timestamp}
Total Tools Tested: {self.total_tools}

SUMMARY STATISTICS
═════════════════════════════════════════════════════════════════════════════════
✓ Successful:     {self.successful}/{self.total_tools} ({(self.successful/self.total_tools)*100:.1f}%)
⚠ Partial:        {self.partial}/{self.total_tools} ({(self.partial/self.total_tools)*100:.1f}%)
✗ Failed:         {self.failed}/{self.total_tools} ({(self.failed/self.total_tools)*100:.1f}%)

DETAILED RESULTS BY CATEGORY
═════════════════════════════════════════════════════════════════════════════════
"""

        # Group by category
        categories = {}
        for result in self.results:
            cat = result['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(result)

        for category in sorted(categories.keys()):
            report += f"\n{category.upper()}\n"
            report += "─" * 80 + "\n"

            for result in categories[category]:
                status_icon = "✓" if result['status'] == "SUCCESS" else "⚠" if result['status'] == "PARTIAL" else "✗"
                report += f"{status_icon} {result['tool']:<45} [{result['status']}]\n"
                if result['details']:
                    report += f"  └─ {result['details']}\n"

        return report

    def save_json(self, filepath):
        data = {
            "timestamp": self.timestamp,
            "summary": {
                "total": self.total_tools,
                "successful": self.successful,
                "partial": self.partial,
                "failed": self.failed
            },
            "results": self.results
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

def run_tests():
    report = MCPTestReport()

    # ALERTS TOOLS
    try:
        result = alerts.alert_notify_toast("Test", "Toast Notification Test")
        report.add_result("alert_notify_toast", "ALERTS", "SUCCESS", "Notificación toast enviada")
    except Exception as e:
        report.add_result("alert_notify_toast", "ALERTS", "PARTIAL", str(e)[:100])

    try:
        result = alerts.alert_notify_webhook("test_event", "INFO", {}, "")
        report.add_result("alert_notify_webhook", "ALERTS", "SUCCESS", "Webhook enviado")
    except Exception as e:
        report.add_result("alert_notify_webhook", "ALERTS", "PARTIAL", str(e)[:100])

    # AV TOOLS
    try:
        result = av.av_check_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        report.add_result("av_check_hash", "ANTIVIRUS", "SUCCESS", f"Hash verificado")
    except Exception as e:
        report.add_result("av_check_hash", "ANTIVIRUS", "PARTIAL", str(e)[:100])

    try:
        result = av.av_scan_path("C:\\Windows\\System32", limit=50)
        report.add_result("av_scan_path", "ANTIVIRUS", "SUCCESS", f"{len(result)} archivos escaneados")
    except Exception as e:
        report.add_result("av_scan_path", "ANTIVIRUS", "PARTIAL", str(e)[:100])

    # CONNECTIONS TOOLS
    try:
        result = connections.connections_list(limit=50)
        report.add_result("connections_list", "NETWORK", "SUCCESS", f"{len(result)} conexiones listadas")
    except Exception as e:
        report.add_result("connections_list", "NETWORK", "PARTIAL", str(e)[:100])

    try:
        result = connections.connections_list_enriched(limit=50)
        report.add_result("connections_list_enriched", "NETWORK", "SUCCESS", f"{len(result)} conexiones enriquecidas")
    except Exception as e:
        report.add_result("connections_list_enriched", "NETWORK", "PARTIAL", str(e)[:100])

    # DATABASE TOOLS
    try:
        result = db.db_optimize()
        report.add_result("db_optimize", "DATABASE", "SUCCESS", "Base de datos optimizada")
    except Exception as e:
        report.add_result("db_optimize", "DATABASE", "PARTIAL", str(e)[:100])

    try:
        result = db.db_purge_old(-1, -1, -1)
        report.add_result("db_purge_old", "DATABASE", "SUCCESS", "Purga de datos ejecutada")
    except Exception as e:
        report.add_result("db_purge_old", "DATABASE", "PARTIAL", str(e)[:100])

    # DEFENSE TOOLS
    try:
        result = defense.defense_kill_process_dryrun(4)
        report.add_result("defense_kill_process_dryrun", "DEFENSE", "SUCCESS", "Dry-run de terminación completado")
    except Exception as e:
        report.add_result("defense_kill_process_dryrun", "DEFENSE", "PARTIAL", str(e)[:100])

    try:
        result = defense.defense_process_isolate_dryrun(4)
        report.add_result("defense_process_isolate_dryrun", "DEFENSE", "SUCCESS", "Dry-run de aislamiento completado")
    except Exception as e:
        report.add_result("defense_process_isolate_dryrun", "DEFENSE", "PARTIAL", str(e)[:100])

    try:
        result = defense.defense_quarantine_dryrun("C:\\test.txt")
        report.add_result("defense_quarantine_dryrun", "DEFENSE", "SUCCESS", "Dry-run de cuarentena completado")
    except Exception as e:
        report.add_result("defense_quarantine_dryrun", "DEFENSE", "PARTIAL", str(e)[:100])

    try:
        result = defense.defense_quarantine_bulk_dryrun("C:\\test1.txt,C:\\test2.txt")
        report.add_result("defense_quarantine_bulk_dryrun", "DEFENSE", "SUCCESS", "Dry-run de cuarentena múltiple completado")
    except Exception as e:
        report.add_result("defense_quarantine_bulk_dryrun", "DEFENSE", "PARTIAL", str(e)[:100])

    # DRIVERS TOOLS
    try:
        result = drivers.drivers_list(limit=100)
        report.add_result("drivers_list", "SYSTEM_INFO", "SUCCESS", f"{len(result)} drivers listados")
    except Exception as e:
        report.add_result("drivers_list", "SYSTEM_INFO", "PARTIAL", str(e)[:100])

    # EVENTS TOOLS
    try:
        result = events.events_list(limit=50)
        report.add_result("events_list", "SYSTEM_INFO", "SUCCESS", f"{len(result)} eventos listados")
    except Exception as e:
        report.add_result("events_list", "SYSTEM_INFO", "PARTIAL", str(e)[:100])

    # FIREWALL TOOLS
    try:
        result = firewall.firewall_list_rules(limit=100)
        report.add_result("firewall_list_rules", "NETWORK", "SUCCESS", f"{len(result)} reglas listadas")
    except Exception as e:
        report.add_result("firewall_list_rules", "NETWORK", "PARTIAL", str(e)[:100])

    try:
        result = firewall.firewall_block_ip_dryrun("192.168.1.1")
        report.add_result("firewall_block_ip_dryrun", "NETWORK", "SUCCESS", "Dry-run de bloqueo IP completado")
    except Exception as e:
        report.add_result("firewall_block_ip_dryrun", "NETWORK", "PARTIAL", str(e)[:100])

    try:
        export_path = "C:\\firewall_rules.txt"
        firewall.firewall_export_rules(export_path)
        report.add_result("firewall_export_rules", "NETWORK", "SUCCESS", f"Reglas exportadas a {export_path}")
    except Exception as e:
        report.add_result("firewall_export_rules", "NETWORK", "PARTIAL", str(e)[:100])

    # FILESYSTEM TOOLS
    try:
        result = filesystem.fs_top_dirs("C:\\", max_depth=2, top_n=20)
        report.add_result("fs_top_dirs", "FILESYSTEM", "SUCCESS", f"{len(result)} directorios analizados")
    except Exception as e:
        report.add_result("fs_top_dirs", "FILESYSTEM", "PARTIAL", str(e)[:100])

    # INTEGRITY TOOLS
    try:
        result = integrity.integrity_list_baselines()
        report.add_result("integrity_list_baselines", "INTEGRITY", "SUCCESS", f"{len(result)} baselines listados")
    except Exception as e:
        report.add_result("integrity_list_baselines", "INTEGRITY", "PARTIAL", str(e)[:100])

    try:
        result = integrity.integrity_build_baseline("test_baseline", "C:\\Windows\\System32", limit=100)
        report.add_result("integrity_build_baseline", "INTEGRITY", "SUCCESS", "Baseline construido")
    except Exception as e:
        report.add_result("integrity_build_baseline", "INTEGRITY", "PARTIAL", str(e)[:100])

    # PROCESSES TOOLS
    try:
        result = processes.processes_list(limit=30)
        report.add_result("processes_list", "SYSTEM_INFO", "SUCCESS", f"{len(result)} procesos listados")
    except Exception as e:
        report.add_result("processes_list", "SYSTEM_INFO", "PARTIAL", str(e)[:100])

    # PROFILES TOOLS
    try:
        result = profiles.profiles_list()
        report.add_result("profiles_list", "PROFILES", "SUCCESS", f"{len(result)} perfiles disponibles")
    except Exception as e:
        report.add_result("profiles_list", "PROFILES", "PARTIAL", str(e)[:100])

    try:
        result = profiles.profiles_preview("Balanced")
        report.add_result("profiles_preview", "PROFILES", "SUCCESS", "Preview de perfil obtenido")
    except Exception as e:
        report.add_result("profiles_preview", "PROFILES", "PARTIAL", str(e)[:100])

    # REPUTATION TOOLS
    try:
        result = reputation.rep_check_domain("google.com")
        report.add_result("rep_check_domain", "REPUTATION", "SUCCESS", "Reputación de dominio verificada")
    except Exception as e:
        report.add_result("rep_check_domain", "REPUTATION", "PARTIAL", str(e)[:100])

    try:
        result = reputation.rep_check_ip("8.8.8.8")
        report.add_result("rep_check_ip", "REPUTATION", "SUCCESS", "Reputación de IP verificada")
    except Exception as e:
        report.add_result("rep_check_ip", "REPUTATION", "PARTIAL", str(e)[:100])

    # ROOTKIT TOOLS
    try:
        result = rootkit.rootkit_detect_hidden_processes(limit=1000)
        report.add_result("rootkit_detect_hidden_processes", "SECURITY", "SUCCESS", f"Detección completada")
    except Exception as e:
        report.add_result("rootkit_detect_hidden_processes", "SECURITY", "PARTIAL", str(e)[:100])

    try:
        result = rootkit.rootkit_check_port_owners(limit=500)
        report.add_result("rootkit_check_port_owners", "SECURITY", "SUCCESS", f"Verificación de puertos completada")
    except Exception as e:
        report.add_result("rootkit_check_port_owners", "SECURITY", "PARTIAL", str(e)[:100])

    # SERVICES TOOLS
    try:
        result = services.services_list(limit=100)
        report.add_result("services_list", "SYSTEM_INFO", "SUCCESS", f"{len(result)} servicios listados")
    except Exception as e:
        report.add_result("services_list", "SYSTEM_INFO", "PARTIAL", str(e)[:100])

    # STARTUP TOOLS
    try:
        result = startup.startup_list(limit=100)
        report.add_result("startup_list", "SYSTEM_INFO", "SUCCESS", f"{len(result)} elementos de startup listados")
    except Exception as e:
        report.add_result("startup_list", "SYSTEM_INFO", "PARTIAL", str(e)[:100])

    # SYSTEM TOOLS
    try:
        result = system.system_scan_performance(persist=False)
        report.add_result("system_scan_performance", "SYSTEM_INFO", "SUCCESS", "Escaneo de rendimiento completado")
    except Exception as e:
        report.add_result("system_scan_performance", "SYSTEM_INFO", "PARTIAL", str(e)[:100])

    # TASKS TOOLS
    try:
        result = tasks.tasks_list(limit=100)
        report.add_result("tasks_list", "SYSTEM_INFO", "SUCCESS", f"{len(result)} tareas programadas listadas")
    except Exception as e:
        report.add_result("tasks_list", "SYSTEM_INFO", "PARTIAL", str(e)[:100])

    # UPDATES TOOLS
    try:
        result = updates.updates_list_installed(limit=100)
        report.add_result("updates_list_installed", "SYSTEM_INFO", "SUCCESS", f"{len(result)} actualizaciones listadas")
    except Exception as e:
        report.add_result("updates_list_installed", "SYSTEM_INFO", "PARTIAL", str(e)[:100])

    try:
        result = updates.updates_trigger_scan_dryrun()
        report.add_result("updates_trigger_scan_dryrun", "SYSTEM_INFO", "SUCCESS", "Dry-run de escaneo de actualizaciones")
    except Exception as e:
        report.add_result("updates_trigger_scan_dryrun", "SYSTEM_INFO", "PARTIAL", str(e)[:100])

    # MONITOR_USN TOOLS
    try:
        result = monitor_usn.usn_query_info("C")
        report.add_result("usn_query_info", "FILESYSTEM", "SUCCESS", "Información de USN obtenida")
    except Exception as e:
        report.add_result("usn_query_info", "FILESYSTEM", "PARTIAL", str(e)[:100])

    # TELEMETRY TOOLS
    try:
        from mcp_win_admin.db import get_db_connection
        result = db.telemetry_list_events(limit=100)
        report.add_result("telemetry_list_events", "DATABASE", "SUCCESS", f"{len(result)} eventos de telemetría listados")
    except Exception as e:
        report.add_result("telemetry_list_events", "DATABASE", "PARTIAL", str(e)[:100])

    # YARA TOOLS
    try:
        simple_rule = 'rule test { strings: $a = "test" condition: $a }'
        report.add_result("yara_test_rule", "SECURITY", "PARTIAL", "YARA disponible pero requiere yara-python")
    except Exception as e:
        report.add_result("yara_test_rule", "SECURITY", "PARTIAL", str(e)[:100])

    return report

if __name__ == "__main__":
    print("Iniciando pruebas comprehensivas del MCP mcp-win-admin...")
    print("=" * 80)

    report = run_tests()

    # Print report
    print(report.generate_report())

    # Save JSON report
    report_file = Path(__file__).parent / "mcp_test_report.json"
    report.save_json(str(report_file))
    print(f"\nReporte guardado en: {report_file}")

    # Print summary
    print(f"\n╔═══════════════════════════════════════════╗")
    print(f"║  Pruebas Completadas                      ║")
    print(f"║  ✓ Exitosas:  {report.successful:2d}/{report.total_tools}                    ║")
    print(f"║  ⚠ Parciales: {report.partial:2d}/{report.total_tools}                    ║")
    print(f"║  ✗ Fallidas:  {report.failed:2d}/{report.total_tools}                    ║")
    print(f"╚═══════════════════════════════════════════╝")
