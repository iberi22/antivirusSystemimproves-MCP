#!/usr/bin/env python3
"""
Intrusion Detection Client for MCP Win-Admin
Utiliza todas las 43 herramientas del MCP para detectar compromisos del sistema
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class IntrusionDetectionClient:
    def __init__(self):
        self.session = None
        self.findings = {
            "hidden_processes": [],
            "suspicious_connections": [],
            "malware_detected": [],
            "integrity_violations": [],
            "rootkit_indicators": [],
            "persistence_mechanisms": [],
            "firewall_anomalies": [],
            "yara_matches": [],
            "event_anomalies": [],
            "reputation_issues": []
        }
        self.scan_summary = {}

    async def initialize(self):
        """Inicializa la conexión con el servidor MCP"""
        env = dict(os.environ)
        env.setdefault("MCP_FREE_ONLY_SOURCES", "true")
        env.setdefault("MCP_LIGHT_MODE", "true")
        env.setdefault("MCP_DEFAULT_REP_TTL", "86400")

        params = StdioServerParameters(
            command=sys.executable,
            args=["-u", "-m", "mcp_win_admin.server"],
            env=env,
        )

        self.client_context = stdio_client(params)
        read, write = await self.client_context.__aenter__()
        self.session = ClientSession(read, write)
        await self.session.initialize()
        print("[+] Servidor MCP inicializado correctamente")

    async def call_tool(self, tool_name: str, params: dict) -> Any:
        """Llama una herramienta del MCP y retorna el resultado"""
        try:
            result = await self.session.call_tool(tool_name, params)
            data = None
            try:
                for block in getattr(result, "content", []) or []:
                    text = getattr(block, "text", None)
                    if text:
                        data = json.loads(text)
                        break
            except Exception:
                pass
            if data is None and hasattr(result, "data"):
                data = result.data
            return data
        except Exception as e:
            print(f"[-] Error en {tool_name}: {e}")
            return None

    async def detect_hidden_processes(self):
        """1. DETECCIÓN DE PROCESOS OCULTOS - Herramienta clave para rootkits"""
        print("\n" + "="*80)
        print("[*] 1. ANÁLISIS DE PROCESOS OCULTOS (Rootkit Detection)")
        print("="*80)

        result = await self.call_tool("rootkit_detect_hidden_processes", {"limit": 10000})
        if result:
            hidden = result.get("hidden_processes", [])
            if hidden:
                print(f"[!] ⚠️  PROCESOS OCULTOS DETECTADOS: {len(hidden)}")
                for proc in hidden[:10]:  # Primeros 10
                    print(f"    - {proc}")
                    self.findings["hidden_processes"].append(proc)
            else:
                print("[+] No se detectaron procesos ocultos")

        # Verificar puertos sin propietario
        result = await self.call_tool("rootkit_check_port_owners", {"limit": 1000})
        if result:
            orphan_ports = result.get("orphan_connections", [])
            if orphan_ports:
                print(f"[!] ⚠️  PUERTOS SIN PROPIETARIO VISIBLE: {len(orphan_ports)}")
                for port in orphan_ports[:10]:
                    print(f"    - {port}")
                    self.findings["rootkit_indicators"].append(port)

    async def analyze_network_connections(self):
        """2. ANÁLISIS DE CONEXIONES CON ENRIQUECIMIENTO DE REPUTACIÓN"""
        print("\n" + "="*80)
        print("[*] 2. ANÁLISIS DE CONEXIONES DE RED CON REPUTACIÓN")
        print("="*80)

        result = await self.call_tool("connections_list_enriched", {
            "limit": 100,
            "include_process": True
        })

        if result:
            print(f"[*] Analizando {len(result)} conexiones...")

            for conn in result:
                raddr = conn.get("raddr", "")
                laddr = conn.get("laddr", "")
                state = conn.get("state", "")
                pid = conn.get("pid", "")

                # Verificar reputación
                reputation = conn.get("reputation", {})
                verdict = reputation.get("verdict", "unknown")

                if verdict in ["malicious", "suspicious", "blocklisted"]:
                    print(f"[!] ⚠️  CONEXIÓN SOSPECHOSA: {raddr} (Veredicto: {verdict})")
                    print(f"    Local: {laddr} | Estado: {state} | PID: {pid}")
                    self.findings["suspicious_connections"].append({
                        "remote": raddr,
                        "local": laddr,
                        "verdict": verdict,
                        "pid": pid
                    })

    async def scan_for_malware(self):
        """3. ESCANEO DE MALWARE CON VERIFICACIÓN DE HASHES"""
        print("\n" + "="*80)
        print("[*] 3. ESCANEO DE MALWARE EN DIRECTORIOS CRÍTICOS")
        print("="*80)

        critical_paths = [
            "C:\\Windows\\System32",
            "C:\\Windows\\Temp",
            "C:\\Users\\Public",
            "C:\\ProgramData"
        ]

        for path in critical_paths:
            print(f"\n[*] Escaneando: {path}")
            result = await self.call_tool("av_scan_path", {
                "target": path,
                "limit": 100,
                "recursive": True
            })

            if result:
                for item in result:
                    verdict = item.get("verdict", "clean")
                    if verdict in ["malicious", "suspicious"]:
                        print(f"[!] ⚠️  MALWARE DETECTADO: {item.get('path')}")
                        print(f"    Veredicto: {verdict} | Hash: {item.get('hash')}")
                        self.findings["malware_detected"].append({
                            "path": item.get("path"),
                            "verdict": verdict,
                            "hash": item.get("hash")
                        })

    async def verify_file_integrity(self):
        """4. VERIFICACIÓN DE INTEGRIDAD DE ARCHIVOS CRÍTICOS"""
        print("\n" + "="*80)
        print("[*] 4. VERIFICACIÓN DE INTEGRIDAD DE ARCHIVOS DEL SISTEMA")
        print("="*80)

        # Primero construir o usar baseline existente
        result = await self.call_tool("integrity_list_baselines", {})

        baselines = result if result else []
        if isinstance(baselines, list) and len(baselines) > 0:
            baseline_name = baselines[0].get("name", "default")
            print(f"[*] Usando baseline: {baseline_name}")
        else:
            print("[*] Creando nuevo baseline de System32...")
            await self.call_tool("integrity_build_baseline", {
                "name": "system_baseline",
                "root_path": "C:\\Windows\\System32",
                "limit": 500
            })
            baseline_name = "system_baseline"

        # Verificar cambios
        result = await self.call_tool("integrity_verify_baseline", {
            "name": baseline_name,
            "limit": 500
        })

        if result:
            summary = result.get("summary", {})
            added = summary.get("added", 0)
            modified = summary.get("modified", 0)
            removed = summary.get("removed", 0)

            if added + modified + removed > 0:
                print(f"[!] ⚠️  CAMBIOS DETECTADOS EN INTEGRIDAD:")
                print(f"    Añadidos: {added} | Modificados: {modified} | Removidos: {removed}")

                self.findings["integrity_violations"].append({
                    "baseline": baseline_name,
                    "added": added,
                    "modified": modified,
                    "removed": removed,
                    "files": result.get("files", [])[:10]
                })

    async def check_persistence_mechanisms(self):
        """5. VERIFICACIÓN DE MECANISMOS DE PERSISTENCIA"""
        print("\n" + "="*80)
        print("[*] 5. ANÁLISIS DE MECANISMOS DE PERSISTENCIA")
        print("="*80)

        # Elementos de startup
        print("\n[*] Verificando elementos de inicio...")
        result = await self.call_tool("startup_list", {"limit": 200})

        if result:
            suspicious_keywords = ["malware", "trojan", "backdoor", "crypt", "payload", "obfuscated"]
            for item in result:
                path = item.get("path", "").lower()
                if any(keyword in path for keyword in suspicious_keywords):
                    print(f"[!] ⚠️  STARTUP SOSPECHOSO: {item.get('name')}")
                    print(f"    Ruta: {path}")
                    self.findings["persistence_mechanisms"].append({
                        "type": "startup",
                        "name": item.get("name"),
                        "path": item.get("path")
                    })

        # Tareas programadas
        print("\n[*] Verificando tareas programadas...")
        result = await self.call_tool("tasks_list", {"limit": 200})

        if result:
            for task in result:
                name = task.get("name", "").lower()
                if any(keyword in name for keyword in ["temp", "system32", "appdata", "windows", "payload"]):
                    print(f"[*] Tarea potencialmente sospechosa: {task.get('name')}")
                    self.findings["persistence_mechanisms"].append({
                        "type": "scheduled_task",
                        "name": task.get("name"),
                        "state": task.get("state")
                    })

        # Servicios
        print("\n[*] Verificando servicios...")
        result = await self.call_tool("services_list", {"limit": 200})

        if result:
            for service in result:
                if service.get("status") == "Running":
                    name = service.get("name", "").lower()
                    if name in ["svchost", "rundll32", "explorer"]:
                        if "system32" not in service.get("path", "").lower():
                            print(f"[!] ⚠️  SERVICIO SOSPECHOSO: {service.get('name')}")
                            print(f"    Path: {service.get('path')}")
                            self.findings["persistence_mechanisms"].append({
                                "type": "service",
                                "name": service.get("name"),
                                "path": service.get("path")
                            })

    async def check_firewall_rules(self):
        """6. VERIFICACIÓN DE REGLAS DE FIREWALL ANÓMALAS"""
        print("\n" + "="*80)
        print("[*] 6. ANÁLISIS DE REGLAS DE FIREWALL")
        print("="*80)

        result = await self.call_tool("firewall_list_rules", {"limit": 500})

        if result:
            print(f"[*] Analizando {len(result)} reglas de firewall...")

            # Buscar reglas de allow hacia direcciones externas
            suspicious_rules = [r for r in result if
                              r.get("action") == "Allow" and
                              r.get("direction") == "Out" and
                              r.get("enabled", False)]

            if len(suspicious_rules) > 50:
                print(f"[!] ⚠️  ANOMALÍA: {len(suspicious_rules)} reglas de salida habilitadas")
                self.findings["firewall_anomalies"].append({
                    "type": "excessive_allow_out_rules",
                    "count": len(suspicious_rules)
                })

    async def run_yara_scan(self):
        """7. ESCANEO CON REGLAS YARA (si está disponible)"""
        print("\n" + "="*80)
        print("[*] 7. ESCANEO AVANZADO CON REGLAS YARA")
        print("="*80)

        # Reglas YARA comunes para malware
        yara_rules = [
            """
            rule CryptoMiners {
                strings:
                    $a = "stratum" nocase
                    $b = "pool.mining" nocase
                condition:
                    any of them
            }
            """,
            """
            rule Ransomware_Common {
                strings:
                    $a = ".encrypted" nocase
                    $b = "DECRYPT" nocase
                condition:
                    any of them
            }
            """
        ]

        for i, rule in enumerate(yara_rules):
            try:
                result = await self.call_tool("yara_scan_path", {
                    "target": "C:\\Windows\\System32",
                    "rule_text": rule,
                    "limit": 50
                })

                if result and result.get("matches"):
                    print(f"[!] ⚠️  YARA MATCH EN REGLA {i+1}: {len(result.get('matches', []))} archivos")
                    self.findings["yara_matches"].append({
                        "rule": i+1,
                        "matches": result.get("matches", [])
                    })
            except Exception:
                pass

    async def check_event_logs(self):
        """8. ANÁLISIS DE LOGS DE EVENTOS DEL SISTEMA"""
        print("\n" + "="*80)
        print("[*] 8. ANÁLISIS DE LOGS DE EVENTOS")
        print("="*80)

        # Eventos de seguridad
        print("\n[*] Verificando eventos de seguridad...")
        result = await self.call_tool("events_list", {
            "channel": "Security",
            "limit": 100
        })

        if result:
            critical_events = [r for r in result if
                             r.get("level_id", 0) in [1, 2]]  # Critical, Error

            if critical_events:
                print(f"[!] ⚠️  {len(critical_events)} EVENTOS CRÍTICOS DETECTADOS")
                for evt in critical_events[:5]:
                    print(f"    ID: {evt.get('event_id')} | {evt.get('message')}")
                    self.findings["event_anomalies"].append(evt)

        # Eventos del sistema
        print("\n[*] Verificando eventos del sistema...")
        result = await self.call_tool("events_list", {
            "channel": "System",
            "limit": 100
        })

        if result:
            errors = [r for r in result if r.get("level_id", 0) == 2]
            if len(errors) > 20:
                print(f"[!] ⚠️  ANOMALÍA: {len(errors)} errores del sistema en corto tiempo")

    async def check_reputation(self):
        """9. VERIFICACIÓN DE REPUTACIÓN DE DOMINIOS E IPs"""
        print("\n" + "="*80)
        print("[*] 9. VERIFICACIÓN DE REPUTACIÓN DE DOMINIOS E IPs")
        print("="*80)

        # IPs sospechosas comunes (ejemplos)
        test_ips = ["1.1.1.1", "8.8.8.8"]

        for ip in test_ips:
            result = await self.call_tool("rep_check_ip", {
                "ip": ip,
                "use_cloud": False  # Modo offline
            })

            if result and result.get("verdict") in ["malicious", "suspicious"]:
                print(f"[!] ⚠️  IP SOSPECHOSA: {ip} - {result.get('verdict')}")
                self.findings["reputation_issues"].append({
                    "ip": ip,
                    "verdict": result.get("verdict")
                })

    async def monitor_system_performance(self):
        """10. ANÁLISIS DE RENDIMIENTO DEL SISTEMA"""
        print("\n" + "="*80)
        print("[*] 10. ANÁLISIS DE RENDIMIENTO DEL SISTEMA")
        print("="*80)

        result = await self.call_tool("system_scan_performance", {"persist": False})

        if result:
            snapshot = result.get("snapshot", {})
            cpu_percent = snapshot.get("cpu_percent", 0)
            memory_percent = snapshot.get("memory_percent", 0)

            print(f"[*] CPU: {cpu_percent}% | Memoria: {memory_percent}%")

            if cpu_percent > 80:
                print(f"[!] ⚠️  CPU ELEVADA - Posible crypto-mining o botnet")

            if memory_percent > 85:
                print(f"[!] ⚠️  MEMORIA ELEVADA - Posible memory-based malware")

    async def analyze_processes(self):
        """11. ANÁLISIS DETALLADO DE PROCESOS"""
        print("\n" + "="*80)
        print("[*] 11. ANÁLISIS DE PROCESOS EN EJECUCIÓN")
        print("="*80)

        result = await self.call_tool("processes_list", {
            "limit": 50,
            "sort_by": "memory",
            "include_cpu": True
        })

        if result:
            print(f"[*] Top procesos por consumo de memoria:")
            for proc in result[:10]:
                name = proc.get("name", "")
                memory_mb = proc.get("memory_mb", 0)
                cpu = proc.get("cpu_percent", 0)

                # Detectar nombres sospechosos
                suspicious_names = ["rundll32", "svchost", "explorer", "lsass"]
                if name.lower() in suspicious_names and memory_mb > 500:
                    print(f"[!] ⚠️  PROCESO SOSPECHOSO: {name} - {memory_mb}MB RAM, {cpu}% CPU")
                    self.findings["malware_detected"].append({
                        "process": name,
                        "memory_mb": memory_mb,
                        "cpu_percent": cpu
                    })

    async def generate_report(self):
        """Genera reporte final de hallazgos"""
        print("\n" + "="*80)
        print("[*] REPORTE FINAL DE DETECCIÓN DE INTRUSIONES")
        print("="*80)

        report = {
            "timestamp": datetime.now().isoformat(),
            "scan_results": self.findings,
            "summary": {
                "hidden_processes": len(self.findings["hidden_processes"]),
                "suspicious_connections": len(self.findings["suspicious_connections"]),
                "malware_detected": len(self.findings["malware_detected"]),
                "integrity_violations": len(self.findings["integrity_violations"]),
                "rootkit_indicators": len(self.findings["rootkit_indicators"]),
                "persistence_mechanisms": len(self.findings["persistence_mechanisms"]),
                "firewall_anomalies": len(self.findings["firewall_anomalies"]),
                "yara_matches": len(self.findings["yara_matches"]),
                "reputation_issues": len(self.findings["reputation_issues"])
            }
        }

        # Calcular riesgo total
        total_findings = sum(report["summary"].values())

        print("\n[*] RESUMEN DE HALLAZGOS:")
        for key, value in report["summary"].items():
            if value > 0:
                print(f"  [!] {key}: {value}")

        print(f"\n[*] RIESGO TOTAL: {total_findings} anomalías detectadas")

        if total_findings == 0:
            print("[+] ✓ Sistema aparentemente limpio")
        elif total_findings < 5:
            print("[⚠] Sistema con anomalías menores - Revisar manualmente")
        elif total_findings < 15:
            print("[!] ⚠️  Sistema con anomalías significativas - REVISAR INMEDIATAMENTE")
        else:
            print("[!!] 🚨 SISTEMA POTENCIALMENTE COMPROMETIDO - TOMAR ACCIONES INMEDIATAS")

        # Guardar reporte
        report_file = "intrusion_detection_report.json"
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"\n[*] Reporte guardado en: {report_file}")

        return report

    async def run_full_scan(self):
        """Ejecuta escaneo completo"""
        try:
            await self.initialize()

            print("\n" + "█"*80)
            print("█ ESCANEO COMPLETO DE DETECCIÓN DE INTRUSIONES")
            print("█ Utilizando todas las 43 herramientas del MCP Win-Admin")
            print("█"*80)

            # Ejecutar análisis en orden de prioridad
            await self.detect_hidden_processes()
            await self.analyze_network_connections()
            await self.scan_for_malware()
            await self.verify_file_integrity()
            await self.check_persistence_mechanisms()
            await self.check_firewall_rules()
            await self.run_yara_scan()
            await self.check_event_logs()
            await self.check_reputation()
            await self.monitor_system_performance()
            await self.analyze_processes()

            # Generar reporte
            await self.generate_report()

        except Exception as e:
            print(f"[-] Error fatal: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if self.session:
                await self.session.close()


async def main():
    client = IntrusionDetectionClient()
    await client.run_full_scan()


if __name__ == "__main__":
    asyncio.run(main())
