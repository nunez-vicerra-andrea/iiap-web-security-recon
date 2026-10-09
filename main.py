"""
main.py
Punto de entrada principal para la herramienta iiap-web-security-recon.
Permite la ejecucion por consola interactiva o mediante argumentos de linea de comandos,
coordina el escaneo de seguridad y genera el informe institucional en PDF.
"""

import argparse
import os
import re
import sys
import time
from datetime import datetime

from scanner import WebScanner
from pdf_generator import PDFReport


def print_banner():
    """Muestra el banner de inicio de la herramienta."""
    banner = """
 ========================================================================
   IIAP WEB SECURITY RECON - FOOTPRINTING & AUDITORIA TECNICA
   Instituto de Investigaciones de la Amazonia Peruana (IIAP)
   Area de Ciberseguridad & DevSecOps
 ========================================================================
    """
    print(banner)


def sanitize_filename(name: str) -> str:
    """Limpia caracteres invalidos para nombres de archivo."""
    return re.sub(r'[\\/*?:"<>|]', "_", name)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Herramienta de footprinting y generacion de reportes de seguridad web para IIAP."
    )
    parser.add_argument(
        "-t", "--target",
        dest="target",
        help="URL o direccion IP del objetivo a auditar (ej. iiap.gob.pe o https://iiap.gob.pe)",
        default=None
    )
    parser.add_argument(
        "-o", "--output",
        dest="output",
        help="Ruta o nombre del archivo PDF de salida (opcional)",
        default=None
    )

    args = parser.parse_args()

    # Si no se pasó argumento por consola, solicitar de forma interactiva
    target = args.target
    if not target:
        try:
            target = input(" [?] Ingrese la URL o IP del objetivo (ej. iiap.gob.pe): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n [!] Operacion cancelada por el usuario.")
            sys.exit(0)

    if not target:
        print(" [X] Error: Debe ingresar un objetivo valido.")
        sys.exit(1)

    print(f"\n [*] Iniciando auditoria para: {target}")
    start_time = time.time()

    # 1. Inicialización y Reconocimiento
    print(" [*] [1/4] Inicializando motor de reconocimiento...")
    scanner = WebScanner(target=target)

    # 2. Resolución DNS
    print(" [*] [2/4] Resolviendo DNS y geolocalizacion logica...")
    ip = scanner.resolve_dns()
    if ip:
        print(f"     [+] Hostname: {scanner.hostname} -> IP: {ip}")
    else:
        print(f"     [!] Advertencia: No se pudo resolver la IP para {scanner.hostname}")

    # 3. Análisis de Cabeceras
    print(" [*] [3/4] Evaluando cabeceras HTTP de seguridad (OWASP)...")
    headers = scanner.analyze_headers()
    print(f"     [+] Se evaluaron {len(headers)} directivas de seguridad.")

    # 4. Escaneo de Puertos
    print(" [*] [4/4] Escaneando puertos principales (22, 80, 443, 8080)...")
    ports = scanner.scan_ports()
    open_ports = [p["port"] for p in ports if p.get("state") == "open"]
    if open_ports:
        print(f"     [!] Puertos abiertos detectados: {open_ports}")
    else:
        print("     [+] Ningun puerto de la lista basica respondio abierto.")

    # Consolidar resultados
    scanner.results["status"] = "Completado"
    recon_data = scanner.results

    # 5. Generación de PDF
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target = sanitize_filename(scanner.hostname or "target")
    output_pdf = args.output or f"reporte_recon_{clean_target}_{timestamp}.pdf"

    print(f"\n [*] Consolidando datos y generando reporte tecnico institucional...")
    try:
        report = PDFReport(scan_results=recon_data)
        final_pdf_path = report.build_report(output_pdf)
        print(f"     [+] Reporte generado exitosamente: {os.path.abspath(final_pdf_path)}")
    except Exception as e:
        print(f"     [X] Error durante la generacion del PDF: {str(e)}")

    # Medición de tiempo de ejecución
    elapsed_time = time.time() - start_time
    minutes = int(elapsed_time // 60)
    seconds = elapsed_time % 60

    print("\n ========================================================================")
    print(f"  [>] Auditoria completada en: {minutes:02d}m {seconds:05.2f}s ({elapsed_time:.2f} s)")
    print(f"  [>] Motor utilizado: {recon_data.get('scanner_engine')}")
    print(f"  [>] Cumplimiento de SLA: {'APROBADO (< 5 min)' if elapsed_time < 300 else 'EXCEDIDO'}")
    print(" ========================================================================\n")


if __name__ == "__main__":
    main()
