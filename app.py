"""
app.py
Servidor local en Flask para el Dashboard Web Interactivo de iiap-web-security-recon.
Expone la interfaz gráfica institucional y endpoints de API para escaneo pasivo
y generación/descarga de reportes técnicos en PDF.
"""

import os
import re
import tempfile
import time
from datetime import datetime
from typing import Any, Dict

from flask import Flask, jsonify, render_template, request, send_file

from pdf_generator import PDFReport
from scanner import WebScanner

app = Flask(__name__)

# Caché en memoria para el último escaneo realizado
_LATEST_SCAN_CACHE: Dict[str, Any] = {}


def sanitize_filename(name: str) -> str:
    """Limpia caracteres inválidos para nombres de archivos descargables."""
    return re.sub(r'[\\/*?:"<>|]', "_", name)


@app.route("/")
def index():
    """Sirve la vista principal del Dashboard Web interactivo."""
    return render_template("index.html")


@app.route("/api/health", methods=["GET"])
def health_check():
    """Endpoint de estado del servicio."""
    return jsonify({
        "status": "online",
        "service": "iiap-web-security-recon-dashboard",
        "timestamp": datetime.now().isoformat()
    })


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Endpoint principal para ejecutar el reconocimiento pasivo.
    Recibe un JSON con {'target': 'dominio_o_ip'}.
    Retorna los resultados procesados y métricas en formato JSON.
    """
    global _LATEST_SCAN_CACHE
    req_data = request.get_json(silent=True) or request.form

    target = req_data.get("target", "").strip() if req_data else ""
    if not target:
        return jsonify({
            "success": False,
            "error": "Debe proporcionar una URL o dirección IP objetivo."
        }), 400

    start_time = time.time()
    try:
        # Inicializar y ejecutar escáner
        scanner = WebScanner(target=target)
        scan_results = scanner.execute_recon()

        # Calcular tiempo transcurrido
        elapsed = time.time() - start_time
        scan_results["elapsed_time"] = round(elapsed, 2)

        # Actualizar caché en memoria
        _LATEST_SCAN_CACHE = scan_results

        return jsonify({
            "success": True,
            "data": scan_results
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Error interno durante la auditoría: {str(e)}"
        }), 500


@app.route("/api/export-pdf", methods=["POST"])
def api_export_pdf():
    """
    Endpoint para compilar y descargar el informe técnico maquetado en PDF.
    Acepta el objeto de resultados en el cuerpo del POST o utiliza la caché en memoria.
    """
    global _LATEST_SCAN_CACHE
    payload = request.get_json(silent=True) or {}
    scan_data = payload if payload and "headers_analysis" in payload else _LATEST_SCAN_CACHE

    if not scan_data:
        return jsonify({
            "success": False,
            "error": "No hay resultados de auditoría disponibles para generar el PDF."
        }), 400

    target_name = sanitize_filename(scan_data.get("hostname") or scan_data.get("target") or "target")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    download_filename = f"reporte_recon_iiap_{target_name}_{timestamp}.pdf"

    # Generar PDF en directorio temporal
    temp_dir = tempfile.gettempdir()
    temp_pdf_path = os.path.join(temp_dir, download_filename)

    try:
        reporter = PDFReport(scan_results=scan_data)
        reporter.build_report(temp_pdf_path)

        return send_file(
            temp_pdf_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=download_filename
        )
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Error al maquetar el reporte PDF: {str(e)}"
        }), 500


if __name__ == "__main__":
    print("""
 ========================================================================
   IIAP WEB SECURITY RECON - DASHBOARD WEB LOCALHOST
   Servidor iniciado en: http://127.0.0.1:5000
   Presione CTRL+C para detener el servidor
 ========================================================================
    """)
    app.run(host="127.0.0.1", port=5000, debug=True)
