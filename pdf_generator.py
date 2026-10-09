"""
pdf_generator.py
Módulo de generación de informes técnicos en formato PDF para el IIAP.
Consolida la información de footprinting, puertos y evaluación de cabeceras HTTP
siguiendo las directrices institucionales de ciberseguridad.
"""

import os
from datetime import datetime
from typing import Any, Dict
from fpdf import FPDF


def sanitize_text(text: Any) -> str:
    """
    Sanitiza cadenas de texto para compatibilidad con la codificación estándar (Latin-1) de FPDF.
    """
    if text is None:
        return ""
    text_str = str(text)
    # Reemplazos comunes para evitar errores de renderizado
    replacements = {
        "—": "-",
        "–": "-",
        "“": '"',
        "”": '"',
        "‘": "'",
        "’": "'",
        "…": "...",
        "\u2022": "*",
    }
    for k, v in replacements.items():
        text_str = text_str.replace(k, v)
    return text_str.encode("latin-1", "replace").decode("latin-1")


class IIAPPdfCanvas(FPDF):
    """
    Clase personalizada de FPDF que implementa el membrete institucional
    y pie de página para los reportes de seguridad del IIAP.
    """

    def header(self):
        # Franja institucional superior (Verde Selva IIAP: #145A32)
        self.set_fill_color(20, 90, 50)
        self.rect(0, 0, 210, 10, "F")

        self.set_y(14)
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(20, 90, 50)
        self.cell(0, 6, sanitize_text("INSTITUTO DE INVESTIGACIONES DE LA AMAZONÍA PERUANA - IIAP"), ln=True, align="C")

        self.set_font("Helvetica", "", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 4, sanitize_text("Oficina de Tecnologias de la Informacion y Comunicaciones | Area de Ciberseguridad"), ln=True, align="C")

        self.set_font("Helvetica", "B", 11)
        self.set_text_color(40, 40, 40)
        self.cell(0, 6, sanitize_text("REPORTE TECNICO DE AUDITORIA PASIVA Y FOOTPRINTING WEB"), ln=True, align="C")

        # Línea separadora
        self.set_draw_color(20, 90, 50)
        self.set_line_width(0.6)
        self.line(10, 33, 200, 33)
        self.ln(6)

    def footer(self):
        # Posicionar a 1.5 cm del final
        self.set_y(-15)
        self.set_draw_color(200, 200, 200)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), 200, self.get_y())

        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(120, 8, sanitize_text("IIAP Web Security Recon | Documento de Caracter Confidencial"), 0, 0, "L")
        self.cell(0, 8, sanitize_text(f"Pagina {self.page_no()}/{{nb}}"), 0, 0, "R")


class PDFReport:
    """
    Generador del informe técnico consolidado a partir de los resultados
    obtenidos por el escáner de seguridad.
    """

    def __init__(self, scan_results: Dict[str, Any]):
        self.data = scan_results
        self.pdf = IIAPPdfCanvas(orientation="P", unit="mm", format="A4")
        self.pdf.alias_nb_pages()
        self.pdf.set_auto_page_break(auto=True, margin=18)

    def build_report(self, output_path: str) -> str:
        """
        Construye y compila el documento PDF con todos sus módulos.
        """
        self.pdf.add_page()
        
        self._add_target_metadata()
        self._add_ports_table()
        self._add_headers_matrix()
        self._add_devsecops_recommendations()

        # Asegurar directorio de destino si se especificó una ruta con carpetas
        dirname = os.path.dirname(output_path)
        if dirname and not os.path.exists(dirname):
            os.makedirs(dirname, exist_ok=True)

        self.pdf.output(output_path, "F")
        return output_path

    def _add_target_metadata(self):
        """Sección 1: Ficha técnica del objetivo evaluado."""
        self.pdf.set_y(36)
        self.pdf.set_font("Helvetica", "B", 10)
        self.pdf.set_fill_color(235, 245, 238)
        self.pdf.set_text_color(20, 90, 50)
        self.pdf.cell(0, 7, sanitize_text(" 1. INFORMACION GENERAL DEL OBJETIVO Y METADATOS"), fill=True, ln=True)
        self.pdf.ln(2)

        meta = [
            ("Objetivo ingresado:", self.data.get("target", "N/A")),
            ("Hostname / Dominio:", self.data.get("hostname", "N/A")),
            ("Direccion IP:", self.data.get("ip", "No resuelta")),
            ("URL Base Evaluada:", self.data.get("url", "N/A")),
            ("Estado HTTP:", str(self.data.get("http_status", "N/A"))),
            ("Motor de Reconocimiento:", self.data.get("scanner_engine", "python-nmap")),
            ("Fecha y Hora de Auditoria:", self.data.get("scan_date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        ]

        self.pdf.set_font("Helvetica", "", 9)
        for label, val in meta:
            self.pdf.set_text_color(60, 60, 60)
            self.pdf.set_font("Helvetica", "B", 8.5)
            self.pdf.cell(50, 5, sanitize_text(f"  {label}"), border=0)
            self.pdf.set_font("Helvetica", "", 8.5)
            self.pdf.set_text_color(20, 20, 20)
            self.pdf.cell(0, 5, sanitize_text(str(val)), ln=True)

        self.pdf.ln(4)

    def _add_ports_table(self):
        """Sección 2: Tabla de puertos principales y banners de servicios."""
        self.pdf.set_font("Helvetica", "B", 10)
        self.pdf.set_fill_color(235, 245, 238)
        self.pdf.set_text_color(20, 90, 50)
        self.pdf.cell(0, 7, sanitize_text(" 2. ESCANEO DE PUERTOS PRINCIPALES Y SERVICIOS EXPUESTOS"), fill=True, ln=True)
        self.pdf.ln(2)

        # Encabezado de la tabla
        self.pdf.set_fill_color(20, 90, 50)
        self.pdf.set_text_color(255, 255, 255)
        self.pdf.set_font("Helvetica", "B", 8.5)

        cols = [
            ("PUERTO", 22),
            ("PROTOCOLO", 24),
            ("ESTADO", 26),
            ("SERVICIO", 32),
            ("VERSION / BANNER DETECTADO", 86)
        ]

        for title, width in cols:
            self.pdf.cell(width, 6, sanitize_text(title), border=1, align="C", fill=True)
        self.pdf.ln()

        # Filas de datos
        ports = self.data.get("ports_info", [])
        self.pdf.set_font("Helvetica", "", 8)

        if not ports:
            self.pdf.set_text_color(100, 100, 100)
            self.pdf.cell(190, 6, sanitize_text("No se detectaron puertos o no se realizo escaneo."), border=1, align="C", ln=True)
        else:
            for i, p in enumerate(ports):
                bg = (245, 247, 248) if i % 2 == 0 else (255, 255, 255)
                self.pdf.set_fill_color(*bg)
                
                state = str(p.get("state", "N/A"))
                if state.lower() == "open":
                    self.pdf.set_text_color(180, 40, 20)  # Rojo para puertos abiertos
                else:
                    self.pdf.set_text_color(50, 120, 50)   # Verde / normal

                self.pdf.cell(22, 5.5, sanitize_text(str(p.get("port", ""))), border=1, align="C", fill=True)
                self.pdf.cell(24, 5.5, sanitize_text(str(p.get("protocol", "TCP"))), border=1, align="C", fill=True)
                self.pdf.cell(26, 5.5, sanitize_text(state), border=1, align="C", fill=True)
                
                self.pdf.set_text_color(30, 30, 30)
                self.pdf.cell(32, 5.5, sanitize_text(str(p.get("service", "unknown"))), border=1, align="C", fill=True)
                
                banner_str = str(p.get("banner", "N/A"))[:55]
                self.pdf.cell(86, 5.5, sanitize_text(banner_str), border=1, align="L", fill=True)
                self.pdf.ln()

        self.pdf.ln(4)

    def _add_headers_matrix(self):
        """Sección 3: Matriz de evaluación de cabeceras HTTP de seguridad."""
        self.pdf.set_font("Helvetica", "B", 10)
        self.pdf.set_fill_color(235, 245, 238)
        self.pdf.set_text_color(20, 90, 50)
        self.pdf.cell(0, 7, sanitize_text(" 3. MATRIZ DE EVALUACION DE CABECERAS HTTP DE SEGURIDAD (OWASP)"), fill=True, ln=True)
        self.pdf.ln(2)

        # Encabezado
        self.pdf.set_fill_color(20, 90, 50)
        self.pdf.set_text_color(255, 255, 255)
        self.pdf.set_font("Helvetica", "B", 8)

        cols = [
            ("CABECERA", 44),
            ("ESTADO", 22),
            ("RIESGO", 20),
            ("VALOR / OBSERVACION", 50),
            ("RECOMENDACION TECNICA", 54)
        ]

        for title, width in cols:
            self.pdf.cell(width, 6, sanitize_text(title), border=1, align="C", fill=True)
        self.pdf.ln()

        headers_data = self.data.get("headers_analysis", [])
        self.pdf.set_font("Helvetica", "", 7.5)

        for i, h in enumerate(headers_data):
            bg = (248, 250, 250) if i % 2 == 0 else (255, 255, 255)
            self.pdf.set_fill_color(*bg)

            # Color según riesgo
            risk = h.get("risk", "Bajo")
            status = h.get("status", "N/A")

            self.pdf.set_text_color(20, 20, 20)
            self.pdf.set_font("Helvetica", "B", 7.5)
            self.pdf.cell(44, 5.5, sanitize_text(h.get("header", "")), border=1, fill=True)

            # Estado
            self.pdf.set_font("Helvetica", "", 7.5)
            if status == "Presente":
                self.pdf.set_text_color(20, 120, 50)
            elif status in ("Ausente", "Expuesta"):
                self.pdf.set_text_color(180, 40, 20)
            else:
                self.pdf.set_text_color(50, 50, 50)
            self.pdf.cell(22, 5.5, sanitize_text(status), border=1, align="C", fill=True)

            # Riesgo
            if risk in ("Alto", "Medio"):
                self.pdf.set_text_color(180, 40, 20)
            elif risk == "Seguro":
                self.pdf.set_text_color(20, 120, 50)
            else:
                self.pdf.set_text_color(80, 80, 80)
            self.pdf.cell(20, 5.5, sanitize_text(risk), border=1, align="C", fill=True)

            # Valor
            self.pdf.set_text_color(40, 40, 40)
            val_short = str(h.get("value", ""))[:32]
            self.pdf.cell(50, 5.5, sanitize_text(val_short), border=1, fill=True)

            # Recomendación
            rec_short = str(h.get("recommendation", ""))[:36]
            self.pdf.cell(54, 5.5, sanitize_text(rec_short), border=1, fill=True)
            self.pdf.ln()

        self.pdf.ln(4)

    def _add_devsecops_recommendations(self):
        """Sección 4: Buenas prácticas y recomendaciones técnicas."""
        self.pdf.set_font("Helvetica", "B", 10)
        self.pdf.set_fill_color(235, 245, 238)
        self.pdf.set_text_color(20, 90, 50)
        self.pdf.cell(0, 7, sanitize_text(" 4. ACCIONES CORRECTIVAS Y RECOMENDACIONES DEVSECOPS"), fill=True, ln=True)
        self.pdf.ln(2)

        recs = [
            "1. Habilitar HSTS (HTTP Strict Transport Security) con directiva includeSubDomains para forzar cifrado TLS.",
            "2. Implementar Content-Security-Policy (CSP) estricta para mitigar vectores de Cross-Site Scripting (XSS).",
            "3. Enmascarar cabeceras 'Server' y deshabilitar 'X-Powered-By' en servidores Apache/Nginx para evitar banner grabbing.",
            "4. Cerrar o filtrar mediante firewall perimetral puertos de administracion no esenciales (como puerto 22 SSH o 8080)."
        ]

        self.pdf.set_font("Helvetica", "", 8)
        self.pdf.set_text_color(40, 40, 40)
        for rec in recs:
            self.pdf.cell(0, 4.5, sanitize_text(f"  {rec}"), ln=True)
