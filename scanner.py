"""
scanner.py
Módulo de escaneo y footprinting pasivo de seguridad web para IIAP.
Diseñado para la identificación de infraestructura, análisis de cabeceras HTTP
y verificación de puertos principales con nmap y fallback de sockets.
"""

import socket
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional
import requests
import urllib3

# Desactivar advertencias de certificados autofirmados durante auditoría
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


class WebScanner:
    """
    Clase principal para la recolección de información (footprinting)
    y auditoría pasiva de objetivos web del IIAP.
    """

    TARGET_PORTS = [22, 80, 443, 8080]
    USER_AGENT = "IIAP-Web-Security-Recon/1.0 (Auditoria Institucional IIAP)"

    # Especificación de cabeceras de seguridad a evaluar
    SECURITY_HEADERS_SPEC = {
        "X-Frame-Options": {
            "type": "protection",
            "desc": "Mitigación de ataques de Clickjacking.",
            "rec": "Configurar en 'DENY' o 'SAMEORIGIN'."
        },
        "Strict-Transport-Security": {
            "type": "protection",
            "desc": "Obliga a los navegadores a usar conexiones cifradas HTTPS (HSTS).",
            "rec": "Habilitar max-age=31536000; includeSubDomains."
        },
        "Content-Security-Policy": {
            "type": "protection",
            "desc": "Controla orígenes permitidos para mitigar XSS e inyección de datos.",
            "rec": "Definir directivas restrictivas (default-src 'self')."
        },
        "X-Content-Type-Options": {
            "type": "protection",
            "desc": "Previene que el navegador interprete archivos con tipos MIME incorrectos.",
            "rec": "Configurar con valor 'nosniff'."
        },
        "Server": {
            "type": "disclosure",
            "desc": "Divulgación de software y versión del servidor web.",
            "rec": "Ocultar o anonimizar la cabecera Server en producción."
        },
        "X-Powered-By": {
            "type": "disclosure",
            "desc": "Divulgación de tecnologías del backend (PHP, ASP.NET, Express, etc.).",
            "rec": "Eliminar esta cabecera para prevenir fingerprinting tecnológico."
        }
    }

    def __init__(self, target: str, timeout: int = 10):
        """
        Inicializa el escáner con el objetivo ingresado.
        
        :param target: URL o dirección IP objetivo.
        :param timeout: Tiempo máximo de espera por petición en segundos.
        """
        self.raw_target = target.strip()
        self.timeout = timeout
        self.hostname, self.url = self._normalize_target(self.raw_target)
        self.ip_address: Optional[str] = None
        self.results: Dict[str, Any] = {
            "target": self.raw_target,
            "hostname": self.hostname,
            "url": self.url,
            "ip": None,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "dns_info": {},
            "headers_analysis": [],
            "raw_headers": {},
            "ports_info": [],
            "scanner_engine": "python-nmap",
            "status": "Incompleto"
        }

    def _normalize_target(self, target: str) -> tuple[str, str]:
        """
        Normaliza la entrada del usuario en un hostname limpio y una URL HTTP(S) accesible.
        """
        candidate = target
        if not candidate.startswith(("http://", "https://")):
            candidate = f"https://{candidate}"
        
        parsed = urllib.parse.urlparse(candidate)
        netloc = parsed.netloc or parsed.path.split("/")[0]
        hostname = netloc.split(":")[0]  # Remover puerto si existiera
        
        # Validar si el hostname es válido
        if not hostname:
            hostname = target.split("/")[0].split(":")[0]

        # Mantener URL base para peticiones HTTP
        url = f"{parsed.scheme or 'https'}://{netloc}"
        return hostname, url

    def resolve_dns(self) -> Optional[str]:
        """
        Realiza la resolución DNS directa para obtener la dirección IP del objetivo.
        """
        try:
            self.ip_address = socket.gethostbyname(self.hostname)
            self.results["ip"] = self.ip_address
            self.results["dns_info"] = {
                "hostname": self.hostname,
                "ip": self.ip_address,
                "status": "Resuelto con éxito"
            }
            return self.ip_address
        except socket.gaierror as e:
            self.results["dns_info"] = {
                "hostname": self.hostname,
                "ip": "No resuelto",
                "status": f"Fallo de resolución DNS: {str(e)}"
            }
            return None

    def analyze_headers(self) -> List[Dict[str, Any]]:
        """
        Realiza un análisis pasivo de las cabeceras HTTP de seguridad del objetivo.
        Evalúa protección (HSTS, CSP, X-Frame-Options, X-Content-Type)
        y exposición de información (Server, X-Powered-By).
        """
        headers_eval = []
        response_headers = {}

        # Intentar conectar con la URL (primero HTTPS, fallback a HTTP si falla)
        urls_to_try = [self.url]
        if self.url.startswith("https://"):
            urls_to_try.append(self.url.replace("https://", "http://"))
        elif self.url.startswith("http://"):
            urls_to_try.append(self.url.replace("http://", "https://"))

        resp = None
        for test_url in urls_to_try:
            try:
                resp = requests.get(
                    test_url,
                    timeout=self.timeout,
                    headers={"User-Agent": self.USER_AGENT},
                    verify=False,
                    allow_redirects=True
                )
                self.results["url"] = test_url
                break
            except requests.RequestException:
                continue

        if resp is not None:
            response_headers = {k: v for k, v in resp.headers.items()}
            self.results["raw_headers"] = response_headers
            self.results["http_status"] = resp.status_code
        else:
            self.results["http_status"] = "No responde"

        # Comparar contra la matriz de seguridad
        for header_name, meta in self.SECURITY_HEADERS_SPEC.items():
            # Búsqueda insensible a mayúsculas/minúsculas
            detected_val = None
            for h_key, h_val in response_headers.items():
                if h_key.lower() == header_name.lower():
                    detected_val = h_val
                    break

            is_protection = (meta["type"] == "protection")
            if detected_val:
                if is_protection:
                    status = "Presente"
                    risk = "Bajo"
                    color = "GREEN"
                else:
                    status = "Expuesta"
                    risk = "Medio"
                    color = "AMBER"
                value_str = detected_val
            else:
                if is_protection:
                    status = "Ausente"
                    risk = "Medio" if header_name != "Strict-Transport-Security" else "Alto"
                    color = "RED"
                else:
                    status = "Oculta"
                    risk = "Seguro"
                    color = "GREEN"
                value_str = "No detectada"

            headers_eval.append({
                "header": header_name,
                "status": status,
                "value": value_str,
                "risk": risk,
                "color": color,
                "description": meta["desc"],
                "recommendation": meta["rec"]
            })

        self.results["headers_analysis"] = headers_eval
        return headers_eval

    def scan_ports(self) -> List[Dict[str, Any]]:
        """
        Escanea los puertos principales (80, 443, 8080, 22) usando python-nmap.
        Si Nmap no se encuentra en el sistema, ejecuta un fallback pasivo
        por sockets para garantizar la continuidad del reporte.
        """
        ports_list = []
        target_ip = self.ip_address or self.hostname
        ports_str = ",".join(str(p) for p in self.TARGET_PORTS)

        used_nmap = False
        if NMAP_AVAILABLE:
            try:
                nm = nmap.PortScanner()
                # -sV para detección de versión/banner, -T4 para rapidez, -Pn para evitar ping blocks
                nm.scan(hosts=target_ip, ports=ports_str, arguments="-sV -T4 -Pn --version-light")
                
                # Procesar resultados
                if target_ip in nm.all_hosts():
                    host_data = nm[target_ip]
                    for proto in host_data.all_protocols():
                        ports = host_data[proto].keys()
                        for port in sorted(ports):
                            port_info = host_data[proto][port]
                            service_name = port_info.get("name", "unknown")
                            product = port_info.get("product", "")
                            version = port_info.get("version", "")
                            banner = f"{product} {version}".strip() or "Sin banner detallado"
                            
                            ports_list.append({
                                "port": port,
                                "protocol": proto.upper(),
                                "state": port_info.get("state", "unknown"),
                                "service": service_name,
                                "banner": banner
                            })
                    used_nmap = True
                    self.results["scanner_engine"] = "Nmap CLI Engine"
            except (nmap.PortScannerError, FileNotFoundError):
                used_nmap = False
            except Exception:
                used_nmap = False

        # Fallback elegante usando sockets en caso Nmap binario no esté en PATH
        if not used_nmap:
            self.results["scanner_engine"] = "Python Socket Engine (Nmap CLI no disponible)"
            service_map = {22: "ssh", 80: "http", 443: "https", 8080: "http-proxy"}
            for port in self.TARGET_PORTS:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                try:
                    res = s.connect_ex((target_ip, port))
                    if res == 0:
                        banner = self._grab_socket_banner(s, port)
                        ports_list.append({
                            "port": port,
                            "protocol": "TCP",
                            "state": "open",
                            "service": service_map.get(port, "unknown"),
                            "banner": banner
                        })
                    else:
                        ports_list.append({
                            "port": port,
                            "protocol": "TCP",
                            "state": "closed/filtered",
                            "service": service_map.get(port, "unknown"),
                            "banner": "N/A"
                        })
                except Exception:
                    ports_list.append({
                        "port": port,
                        "protocol": "TCP",
                        "state": "error",
                        "service": service_map.get(port, "unknown"),
                        "banner": "Error al conectar"
                    })
                finally:
                    s.close()

        self.results["ports_info"] = ports_list
        return ports_list

    def _grab_socket_banner(self, sock: socket.socket, port: int) -> str:
        """
        Intenta capturar un banner preliminar a través del socket TCP.
        """
        try:
            if port in (80, 8080):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 22:
                pass  # SSH envía banner de bienvenida automáticamente
            banner_data = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            first_line = banner_data.split("\n")[0] if banner_data else "Servicio activo"
            return first_line[:60]
        except Exception:
            return "Servicio activo (Sin banner)"

    def execute_recon(self) -> Dict[str, Any]:
        """
        Ejecuta el flujo completo de reconocimiento y devuelve el informe consolidado.
        """
        self.resolve_dns()
        self.analyze_headers()
        self.scan_ports()
        self.results["status"] = "Completado"
        return self.results
