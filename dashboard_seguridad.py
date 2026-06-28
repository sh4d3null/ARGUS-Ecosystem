# streamlit run dashboard_seguridad.py  (ejecutar con abrir terminal integrado)

import mysql.connector
import streamlit as st
import pandas as pd
import requests
import socket
import OpenSSL
import ssl
import dns.resolver
import psutil
import urllib3
import whois
import unicodedata
import time
import json
import os
import folium
import subprocess
import re
from shadenull_core import guardar_auditoria_cliente
from folium.plugins import AntPath
from scapy.all import traceroute
from streamlit_folium import folium_static
from streamlit_autorefresh import st_autorefresh
from folium.plugins import HeatMap
from datetime import datetime
from fpdf import FPDF
from config_db import DB_CONFIG
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from report_templates.template_log_auditor import generar_pdf_log_corporativo
from report_templates.template_network import generar_pdf_red_corporativo
from io import BytesIO
#from crypto_persistence import guardar_analisis_suite

# --- CONFIGURACIÓN DE IA (AUTO-DETECCIÓN) ---
import google.generativeai as genai
from config_db import GEMINI_API_KEY

genai.configure(api_key=GEMINI_API_KEY)


def consultar_ia_tactica(contexto, hallazgo):
    """Busca un modelo compatible y analiza el hallazgo."""
    # 1. Intentamos detectar qué modelos tenés disponibles
    modelos_disponibles = []
    try:
        for m in genai.list_models():
            if "generateContent" in m.supported_generation_methods:
                modelos_disponibles.append(m.name)
    except:
        modelos_disponibles = ["models/gemini-1.5-flash", "models/gemini-pro"]

    # 2. El mensaje para la IA
    prompt = f"Analista. Evento: {contexto}. Datos: {hallazgo}. Gravedad, Intención, Mitigación. Tono Auditor."

    # 3. Probamos con el primero que funcione
    for nombre_modelo in modelos_disponibles:
        try:
            model = genai.GenerativeModel(nombre_modelo)
            response = model.generate_content(prompt)
            return response.text
        except:
            continue

    return "❌ FALLO CRÍTICO: No se pudo conectar con ningún modelo de IA. Verifique su API KEY."

# =====================================================================
# AGENTE COGNITIVO LOCAL (OLLAMA) + PERSISTENCIA MULTICLIENTE
# =====================================================================
def consultar_agente_local_y_encriptar(empresa, tipo_auditoria, datos_crudos, password):
    """
    CEREBRO LOCAL: Consulta a la RTX 4060 (Ollama), genera el diagnóstico forense
    e inyecta el JSON blindado automáticamente en la base de datos NoSQL del cliente.
    """
    url_ollama = "http://localhost:11434/api/generate"
    
    # Prompt táctico especializado para el modelo local qwen2.5-coder
    prompt_sistema = f"""
    [SYSTEM: Identidad = EVA-v5.4 Forensic Intelligence. Rol = Analista de Ciberdefensa en NICName]
    Realiza un peritaje técnico estricto para el módulo '{tipo_auditoria}' de la empresa '{empresa}'.
    Analiza la muestra de datos crudos, descarta ruidos y redacta planes de remediación inmediatos.
    
    EVIDENCIA RECUPERADA DESDE EL VECTOR:
    {json.dumps(datos_crudos, ensure_ascii=False)}
    """
    
    payload = {
        "model": "qwen2.5-coder:7b",
        "prompt": prompt_sistema,
        "stream": False
    }
    
    try:
        # 1. Petición HTTP nativa al puerto local de Ollama (Sin usar .predict() genéricos)
        respuesta = requests.post(url_ollama, json=payload, timeout=45)
        if respuesta.status_code == 200:
            veredicto_local = respuesta.json().get("response", "Error: Respuesta vacía del núcleo.")
        else:
            veredicto_local = f"❌ Error de API Ollama: Código de estado HTTP {respuesta.status_code}"
    except Exception as e:
        veredicto_local = f"❌ FALLO DE NÚCLEO LOCAL: Asegúrese de tener Ollama activo ejecutando 'ollama serve'. Detalle: {str(e)}"
    
    # 2. CAPA DE BLINDAJE FORENSE AUTOMÁTICO (shadenull_core.py)
    try:
        # Importación tardía para evitar colisiones de inicialización en Streamlit
        from shadenull_core import guardar_auditoria_cliente
        
        # Guardamos en el archivo jerárquico .txt delimitado por saltos de línea
        guardar_auditoria_cliente(
            empresa=empresa,
            tipo_auditoria=tipo_auditoria,
            datos_crudos=datos_crudos,
            veredicto_eva=veredicto_local,
            password=password
        )
    except Exception as e:
        # Si la criptografía falla por permisos, el peritaje se muestra pero avisa en la terminal
        print(f"[!] Alerta de Seguridad: No se pudo registrar la evidencia en el búnker de {empresa}: {e}")
        
    return veredicto_local


# ---  Motor Acceso de Usuario ---
def verificar_acceso(usuario, clave):
    """Consulta la DB para validar credenciales."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM usuarios WHERE username = %s AND password_hash = %s"
        cursor.execute(query, (usuario, clave))
        resultado = cursor.fetchone()
        conn.close()
        return resultado is not None
    except:
        return False


def obtener_datos_mapa(ip_list):
    import requests

    puntos = []

    # --- Inteligencia Local de Respaldo ---
    gps_local = {
        "185.220.101.44": {"lat": 52.52, "lon": 13.40, "city": "Berlin, DE"},
        "45.145.67.12": {"lat": 55.75, "lon": 37.61, "city": "Moscu, RU"},
        "181.1.1.1": {"lat": -34.60, "lon": -58.38, "city": "Buenos Aires, AR"},
        "8.8.8.8": {"lat": 37.42, "lon": -122.08, "city": "California, US"},
    }

    for ip in ip_list:
        try:
            # --- INTENTO 1: Geolocalización Satelital Real (API) ---
            url = f"http://ip-api.com{ip}"
            res = requests.get(url, timeout=2).json()

            if res.get("status") == "success":
                puntos.append(
                    {
                        "lat": res["lat"],
                        "lon": res["lon"],
                        "info": f"🚨 {ip} - {res.get('city')}, {res.get('country')}",
                    }
                )
            # --- INTENTO 2: Si falla la API, usamos Inteligencia Local ---
            elif ip in gps_local:
                puntos.append(
                    {
                        "lat": gps_local[ip]["lat"],
                        "lon": gps_local[ip]["lon"],
                        "info": f"📡 {ip} (Local Intel) - {gps_local[ip]['city']}",
                    }
                )
        except:
            # --- INTENTO 3: Modo Offline / Emergencia ---
            if ip in gps_local:
                puntos.append(
                    {
                        "lat": gps_local[ip]["lat"],
                        "lon": gps_local[ip]["lon"],
                        "info": f"🛰️ {ip} (Offline Mode) - {gps_local[ip]['city']}",
                    }
                )
            else:

                continue

    return puntos


# ---  Motor PDF Auditor IA ---
def generar_pdf_ia(modulo, analisis_ia):
    """Convierte el análisis de EVA en un PDF profesional."""
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    styles = getSampleStyleSheet()

    # Personalización del estilo
    style_tit = styles["Heading1"]
    style_body = styles["BodyText"]

    elementos = []

    # Cabecera Oficial
    elementos.append(
        Paragraph(f"🛡️ INFORME DE INTELIGENCIA COGNITIVA", style_tit)
    )
    elementos.append(Spacer(1, 12))
    elementos.append(Paragraph(f"<b>MÓDULO AUDITADO:</b> {modulo}", style_body))
    elementos.append(
        Paragraph(
            f"<b>FECHA DE OPERACIÓN:</b> {time.strftime('%d/%m/%Y %H:%M:%S')}",
            style_body,
        )
    )
    elementos.append(Spacer(1, 12))
    elementos.append(Paragraph("---" * 20, style_body))
    elementos.append(Spacer(1, 12))

    # El Veredicto de EVA (Procesamos saltos de línea)
    for linea in analisis_ia.split("\n"):
        if linea.strip():
            elementos.append(Paragraph(linea, style_body))
            elementos.append(Spacer(1, 6))

    doc.build(elementos)
    buf.seek(0)
    return buf


# --- CONFIGURACIÓN DE PÁGINA ---
st.set_page_config(
    page_title="ARGUS Ecosystem - Operations Center",
    page_icon="👁️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- 2. SISTEMA DE AUTENTICACIÓN DB  ---
if "autenticado" not in st.session_state:
    st.session_state.autenticado = False

if not st.session_state.autenticado:
    # Centramos el login
    _, col_login, _ = st.columns([1, 1.5, 1])

    with col_login:
        # --- LOGOS EN TÁNDEM ---
        col_l1, col_l2 = st.columns(2)
        with col_l1:
            st.image("LogoSN.png", width=200)
        with col_l2:
            st.image("LogoEVA.png", width=150)

        st.title("🔐 Acceso de Comando")
        st.subheader("Integridad y Vigilancia Cognitiva")

        user_input = st.text_input("Usuario Operador:")
        pass_input = st.text_input("Clave de Cifrado:", type="password")

        if st.button("🔓 Desbloquear Terminal"):
            if verificar_acceso(user_input, pass_input):
                st.session_state.autenticado = True
                st.success(
                    "✅ Identidad verificada. EVA Online. Iniciando ARGUS-Ecosystem..."
                )
                st.rerun()
            else:
                # Opcional: Se puede disparar una alerta a Telegram si alguien falla el login
                st.error(
                    "❌ Credenciales inválidas. Intento reportado a la unidad central."
                )

    st.stop()


# --- UTILIDADES DE LIMPIEZA ARGUS Ecosystem ---
def limpiar_texto(texto):
    """
    Limpia emojis y normaliza acentos/caracteres especiales para FPDF.
    """
    if texto is None:
        return ""

    # Limpieza de emojis
    texto = (
        str(texto)
        .replace("✅", "[OK]")
        .replace("❌", "[RIESGO]")
        .replace("⚠️", "[AVISO]")
        .replace("🚨", "[ALERTA]")
        .replace("🍪", "[COOKIES]")
        .replace("🏛️", "[----------]")
    )

    # Normalización de acentos para evitar errores en PDF
    import unicodedata

    texto = (
        unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode("ascii")
    )

    return texto


def cortar_texto(texto, limite=45):
    """
    Corta el texto prolijamente agregando puntos suspensivos
    si supera el límite de caracteres.
    """
    texto = str(texto)
    return texto if len(texto) <= limite else texto[: limite - 3] + "..."


# --- LISTA DE SUBDOMINIOS COMUNES (PLAN B - BRUTE FORCE) ---
COMMON_SUBS = [
    "www",
    "mail",
    "remote",
    "vpn",
    "dev",
    "test",
    "portal",
    "api",
    "admin",
    "soporte",
    "webmail",
    "apps",
    "cloud",
    "secure",
    "dns",
    "server",
]

# --- LIBRERÍA DE REMEDIACIÓN ARGUS Ecosystem ---
SOLUCIONES = {
    "Strict-Transport-Security": {
        "riesgo": "Ataques de interceptación de datos (Man-in-the-Middle).",
        "solucion": "Configurar el encabezado HSTS en el servidor (Apache/Nginx/IIS) para forzar conexiones HTTPS.",
    },
    "Content-Security-Policy": {
        "riesgo": "Inyección de scripts maliciosos (XSS).",
        "solucion": "Definir una política de CSP que restrinja qué scripts se pueden ejecutar en la web.",
    },
    "X-Frame-Options": {
        "riesgo": "Ataques de Clickjacking (secuestro de clics).",
        "solucion": "Configurar el encabezado como 'SAMEORIGIN' o 'DENY' en la configuración del servidor web.",
    },
    "HttpOnly": {
        "riesgo": "Robo de sesión mediante scripts maliciosos (XSS).",
        "solucion": "Activar el flag 'HttpOnly' en la configuración de la aplicación (Web.config o php.ini).",
    },
    "Secure": {
        "riesgo": "Interceptación de cookies en redes no cifradas (WiFi públicas).",
        "solucion": "Activar el flag 'Secure' para que la cookie solo viaje por canales HTTPS.",
    },
    "Puerto 3389": {
        "riesgo": "Acceso remoto no autorizado (Ransomware).",
        "solucion": "Cerrar el puerto al público y permitir acceso únicamente mediante VPN corporativa.",
    },
}


def create_pdf(modulo, objetivo, df, remediacion=""):
    try:
        pdf = FPDF()
        pdf.add_page()

        # --- LOGO E IDENTIDAD VISUAL ---
        try:
            import os

            # Obtenemos la ruta exacta de la carpeta donde está el script
            ruta_actual = os.path.dirname(os.path.abspath(__file__))
            ruta_logo = os.path.join(ruta_actual, "LogoSWblanco200.png")

            # Verificamos si el archivo existe antes de intentar ponerlo
            if os.path.exists(ruta_logo):
                pdf.image(ruta_logo, x=165, y=5, w=35)
            else:
                # Esto va a decir en la terminal si no lo encuentra
                print(f"DEBUG: No se encontró el logo en {ruta_logo}")
        except Exception as e:
            print(f"DEBUG: Error cargando logo: {e}")

        # --- ENCABEZADO ---
        pdf.set_font("Arial", "B", 14)
        pdf.set_text_color(63, 0, 127) 
        pdf.cell(0, 10, "ARGUS Ecosystem INTELLIGENCE", 0, 1, "L")

        pdf.set_font("Arial", "B", 10)
        pdf.set_text_color(100)
        pdf.cell(0, 5, "REPORTE TACTICO DE AUDITORIA", 0, 1, "L")
        pdf.cell(
            0, 5, f"CONSULTOR: Auditor Name | CIBERSEGURIDAD - ANALISTA DE RED", 0, 1, "L"
        )

        # Línea divisoria elegante
        pdf.set_draw_color(63, 0, 127)
        pdf.set_line_width(0.5)
        pdf.line(10, 38, 200, 38)
        pdf.ln(15)

        # --- INFO DEL OBJETIVO ---
        pdf.set_fill_color(245, 245, 255)  # Azul muy pálido
        pdf.set_font("Arial", "B", 11)
        pdf.set_text_color(0)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Caja de resumen
        pdf.cell(
            0,
            10,
            f"  MODULO: {modulo.upper()} | OBJETIVO: {objetivo} | FECHA: {timestamp}",
            0,
            1,
            "L",
            1,
        )
        pdf.ln(5)

        # --- TABLA DE RESULTADOS ---
        if isinstance(df, pd.DataFrame) and not df.empty:
            columnas = list(df.columns)
            ancho_col = max(40, 190 / len(columnas))

            # Encabezados de Tabla
            pdf.set_font("Arial", "B", 10)
            pdf.set_fill_color(63, 0, 127)
            pdf.set_text_color(255, 255, 255)
            for col in columnas:
                pdf.cell(ancho_col, 10, limpiar_texto(col), 1, 0, "C", 1)
            pdf.ln()

            # Filas de Tabla
            pdf.set_font("Arial", "", 9)
            pdf.set_text_color(0)
            for _, row in df.iterrows():
                for val in row.values:
                    pdf.cell(
                        ancho_col, 8, cortar_texto(limpiar_texto(val), 40), 1, 0, "C"
                    )
                pdf.ln()
        else:
            pdf.set_font("Arial", "I", 10)
            pdf.multi_cell(
                0, 10, "No se encontraron hallazgos críticos en este vector de ataque."
            )

        # --- SECCIÓN DE REMEDIACIÓN (Desde SQL) ---
        if remediacion:
            pdf.ln(10)
            pdf.set_font("Arial", "B", 12)
            pdf.set_fill_color(255, 240, 240)  # Fondo rosado suave para alertas
            pdf.set_text_color(150, 0, 0)  # Rojo oscuro
            pdf.cell(0, 10, " PLAN DE ACCION Y REMEDIACION TECNICA", 0, 1, "L", 1)
            pdf.ln(2)

            pdf.set_font("Arial", "", 10)
            pdf.set_text_color(0)
            pdf.multi_cell(0, 7, limpiar_texto(remediacion))

        # --- FOOTER ---
        pdf.set_y(-30)  # Se posiciona a 3 cm del final
        pdf.set_draw_color(200, 200, 200)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.set_font("Arial", "I", 8)
        pdf.set_text_color(120)
        pdf.cell(
            0,
            10,
            "Este documento contiene informacion clasificada de auditoria generada por la suite ARGUS Ecosystem.",
            0,
            1,
            "C",
        )
        pdf.cell(0, 5, "Prohibida su reproduccion no autorizada.", 0, 1, "C")

        return pdf.output(dest="S").encode("latin-1", "replace")

    except Exception as e:
        return f"Error critico generando PDF: {str(e)}".encode("utf-8")


# --- MOTORES TÉCNICOS ---


# --- Motor de Fuzzing Inteligente ---
def pro_fuzzer_scan_db(url):
    import requests
    import mysql.connector
    import time

    rutas_db = []
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT ruta FROM diccionario_fuzz")
        # Extraemos el texto puro de la primera columna de la tupla
        rutas_db = [str(fila[0]).strip() for fila in cursor.fetchall()]
        conn.close()
        st.sidebar.success(f"📦 Munición cargada: {len(rutas_db)} rutas.")
    except Exception as e:
        st.sidebar.error(f"❌ Error DB: {e}")
        rutas_db = ["admin", "login", "config", "backup"]

    if not url.startswith("http"):
        url = f"http://{url}"
    url = url.rstrip("/")

    resultados = []
    prog_fuzzer = st.progress(0)

    for i, path in enumerate(rutas_db):
        try:
            target_url = f"{url}/{path}"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
            }

            # Realizamos la petición con seguimiento de redirecciones
            res = requests.get(
                target_url, timeout=5, headers=headers, allow_redirects=True
            )

            if res.status_code < 400 or res.status_code in [401, 403]:
                status_msg = {
                    200: "✅ ACCESIBLE",
                    403: "🚫 PROHIBIDO (Existe)",
                    401: "🔐 RESTRINGIDO",
                    301: "↪️ REDIRECCION",
                    302: "↪️ REDIRECCION",
                }
                resultados.append(
                    {
                        "Ruta": f"/{path}",
                        "Codigo": res.status_code,
                        "Estado": status_msg.get(res.status_code, "Detectado"),
                        # --- Agregamos contexto para la IA ---
                        "Full_URL": target_url,
                    }
                )
        except:
            continue

        prog_fuzzer.progress((i + 1) / len(rutas_db))

    return pd.DataFrame(resultados)


# --- MOTOR Alerta telegram ---
def enviar_alerta_telegram(mensaje):
    import requests
    import streamlit as st
    from config_db import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID

    tkn = str(TELEGRAM_TOKEN).strip()
    cid = str(TELEGRAM_CHAT_ID).strip()

    url = f"https://api.telegram.org/bot{tkn}/sendMessage"

    try:
        payload = {
            "chat_id": cid,
            "text": mensaje,
            # quita Markdown para evitar errores ocultos
        }

        r = requests.post(url, data=payload, timeout=10)

        if r.status_code == 200:
            st.sidebar.success("📡 SATÉLITE VINCULADO")
        else:
            st.sidebar.error(f"Error {r.status_code}: {r.text}")

    except Exception as e:
        st.sidebar.error(f"Error de Red: {e}")


# --- MOTOR Guardar Historial en DB ---
def guardar_historial(modulo, objetivo, riesgo):
    """Guarda los hallazgos en la DB de XAMPP."""
    try:
        # Conexión estándar de XAMPP
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        query = "INSERT INTO auditorias (modulo, objetivo, riesgo_detectado) VALUES (%s, %s, %s)"
        cursor.execute(query, (modulo, objetivo, riesgo))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error en DB: {e}")  # Solo avisa en consola si MySQL está apagado


# --- MOTOR Scan Ports ---
def scan_ports(comando_o_target):
    """
    MOTOR DE CONSOLA ARGUS Ecosystem: Detecta si el operador ingresó un comando completo
    de Nmap o solo una IP, lo ejecuta en el sistema operativo y parsea el output.
    """
    # 1. Construir el comando real de ejecución
    if "nmap" in comando_o_target.lower():
        # Si el usuario escribió el comando entero, lo usamos tal cual
        comando = comando_o_target
    else:
        # Si solo puso la IP o dominio, le armamos
        comando = f"nmap -sS --top-ports 20 {comando_o_target}"
    
    # 2. Invocar al ejecutable nativo del sistema de forma segura
    try:
        # Ejecutamos en la consola y capturamos el string de salida
        resultado = subprocess.run(
            comando, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=90
        )
        output_consola = resultado.stdout
    except Exception as e:
        # Retornamos un DataFrame de error si el sistema no encuentra nmap
        return pd.DataFrame([{"Puerto": "Error", "Estado": "Fallo de ejecución", "Servicio": str(e)}])

    # 3. PARSER FORENSE: Convertir el texto de Nmap en filas y columnas
    lineas = output_consola.splitlines()
    puertos_encontrados = []
    
    # Expresión regular para cazar el formato estándar: "80/tcp open http"
    regex_nmap = re.compile(r"^(?P<puerto>\d+/tcp|\d+/udp)\s+(?P<estado>\w+)\s+(?P<servicio>[^\s]+)")

    for linea in lineas:
        match = regex_nmap.search(linea.strip())
        if match:
            puertos_encontrados.append({
                "Puerto": match.group("puerto"),
                "Estado": " ABIERTO" if match.group("estado").lower() == "open" else match.group("estado").upper(),
                "Servicio": match.group("servicio")
            })

    # Si el escaneo no encontró puertos o falló, armamos un registro seguro
    if not puertos_encontrados:
        return pd.DataFrame([{"Puerto": "Ninguno", "Estado": " FILTRADO / CERRADO", "Servicio": "Desconocido"}])
        
    return pd.DataFrame(puertos_encontrados)


# --- MOTOR Audit Cookies ---
def audit_cookies(url):
    try:
        if not url.startswith("http"):
            url = f"https://{url}"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
        }

        # Desactivamos advertencias de SSL para no ensuciar la terminal
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        res = requests.get(
            url, verify=False, timeout=12, headers=headers, allow_redirects=True
        )

        if not res.cookies:
            return None

        data = []
        for c in res.cookies:
            # Capturamos metadatos clave para el análisis de EVA
            is_httponly = (
                "✅"
                if c.has_nonstandard_attr("HttpOnly")
                or "httponly" in [k.lower() for k in c._rest.keys()]
                else "❌ RIESGO"
            )
            is_secure = "✅" if c.secure else "❌ RIESGO"

            # Nueva lógica: Detectar SameSite (clave para prevenir CSRF)
            samesite = c._rest.get("SameSite", "No definido")

            data.append(
                {
                    "Nombre": c.name,
                    "HttpOnly": is_httponly,
                    "Secure": is_secure,
                    "SameSite": samesite,  # <--- Dato crítico para prevenir ataques CSRF
                    "Expiracion": time.ctime(c.expires) if c.expires else "Sesión",
                    "Dominio": c.domain,
                }
            )
        return pd.DataFrame(data)
    except Exception as e:
        return f"Error en auditoría de cookies: {e}"


# --- MOTOR Check Vulnerability ---
def check_vulnerability(url):
    # Ampliamos los payloads para una detección más fina
    payloads = {
        "XSS": "<script>alert('ARGUS Ecosystem')</script>",
        "SQLi": "' OR '1'='1",
        "Path Traversal": "../../../etc/passwd",  #Prueba de acceso a archivos
    }

    if "vulnweb.com" in url and "/" not in url:
        url = f"{url}/search.php"

    if not url.startswith("http"):
        url = f"http://{url}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
    }
    resultados = []

    try:
        # Capturamos el banner del servidor para que EVA sepa contra qué pelea
        server_info = requests.head(url, timeout=5, headers=headers).headers.get(
            "Server", "Desconocido"
        )

        for tipo, payload in payloads.items():
            test_url = f"{url}?test={payload}"
            res = requests.get(test_url, verify=False, timeout=15, headers=headers)

            # Lógica de detección inteligente
            is_vuln = False
            if payload in res.text:
                is_vuln = True
            elif "sql syntax" in res.text.lower() or "mysql_fetch" in res.text.lower():
                is_vuln = True  # Error de SQL visible

            resultados.append(
                {
                    "Tipo": tipo,
                    "Estado": "❌ VULNERABLE" if is_vuln else "✅ Protegido",
                    "Riesgo": "CRÍTICO" if is_vuln else "Bajo",
                    "Tecnología": server_info,  # Dato para EVA
                    "Evidencia": (
                        res.text[:200].strip() if is_vuln else "Ninguna"
                    ),  # Muestra para análisis IA
                }
            )

        return pd.DataFrame(resultados)
    except Exception as e:
        return f"Falla táctica en escaneo: {str(e)}"


def consultar_repositorio(id_hallazgo):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM repositorio_tecnico WHERE id_hallazgo = %s"
        cursor.execute(query, (id_hallazgo,))
        r = cursor.fetchone()
        conn.close()

        if r:
            # Construimos la base técnica del SQL
            resumen = f"### {r['titulo']}\n"
            resumen += (
                f"**Severidad:** {r['severidad']} | **ID:** {r['id_hallazgo']}\n\n"
            )
            resumen += f"**Descripción:** {r['descripcion']}\n\n"
            resumen += f"**Riesgo:** {r['riesgo']}\n\n"
            resumen += f"**Solución Técnica:** {r['solucion']}\n\n"

            # --- CONEXIÓN CON EVA: El "Plus" de Inteligencia ---
            # Devolvemos también un flag para que el elif sepa que hay data para la IA
            return {
                "formato_md": resumen,
                "data_pura": r,  # Pasamos todo el diccionario para que la IA lo procese
            }

        return {
            "formato_md": "Remediación técnica en proceso de documentación.",
            "data_pura": None,
        }
    except Exception as e:
        return {
            "formato_md": f"Error al conectar con el Repositorio SQL: {e}",
            "data_pura": None,
        }


# --- MOTOR PARA LFI SCANNER ---
def scan_lfi(url):
    """Prueba patrones de Directory Traversal con análisis cognitivo integrado."""
    payloads = [
        "../../../../etc/passwd",
        "../../../../windows/win.ini",
        "/etc/passwd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    ]

    if not url.startswith("http"):
        url = f"http://{url}"

    if "?" not in url:
        url = f"{url}?file="

    resultados = []
    for p in payloads:
        try:
            test_url = f"{url}{p}"
            res = requests.get(test_url, timeout=7, verify=False)

            # --- Lógica de Detección Forense ---
            is_vuln = False
            evidencia = "Ninguna"

            if "root:x:" in res.text:
                is_vuln = True
                evidencia = "Lectura de /etc/passwd (Linux Detectado)"
            elif "[extensions]" in res.text or "boot loader" in res.text:
                is_vuln = True
                evidencia = "Lectura de win.ini/boot.ini (Windows Detectado)"

            resultados.append(
                {
                    "Payload": p,
                    "Estado": "❌ VULNERABLE" if is_vuln else "✅ Protegido",
                    "Tipo": "LFI",
                    # --- DATOS PARA EVA ---
                    "Evidencia_Tecnica": evidencia,
                    "Server_Header": res.headers.get("Server", "No declarado"),
                    "Muestra_Data": res.text[:150].strip() if is_vuln else "-",
                }
            )
        except:
            continue

    return pd.DataFrame(resultados)


# --- MOTOR PARA Host Header Injection (HHI) ---
def scan_hhi(url):
    """Prueba de Host Header Injection con análisis de vectores de envenenamiento."""
    if not url.startswith("http"):
        url = f"http://{url}"

    fake_host = "ARGUS Ecosystem-malicious.com"
    resultados = []

    try:
        # Enviamos un encabezado Host falso para intentar engañar al servidor
        headers = {
            "Host": fake_host,
            "X-Forwarded-Host": fake_host,  # Vector secundario de inyección
        }
        res = requests.get(
            url, headers=headers, timeout=7, verify=False, allow_redirects=False
        )

        # --- Lógica de Detección Forense para EVA ---
        evidencia = []
        is_vuln = False

        if fake_host in res.text:
            is_vuln = True
            evidencia.append("Reflejado en el Body")

        for k, v in res.headers.items():
            if fake_host in str(v):
                is_vuln = True
                evidencia.append(f"Reflejado en Header: {k}")

        # Capturamos datos para que EVA analice el riesgo de redirección o caché
        resultados.append(
            {
                "Prueba": "Inyección Host / X-Forwarded",
                "Estado": "❌ VULNERABLE" if is_vuln else "✅ Protegido",
                "Tipo": "HHI",
                # --- DATOS PARA EVA ---
                "Evidencias": ", ".join(evidencia) if evidencia else "Ninguna",
                "Status_Code": res.status_code,
                "Cache_Control": res.headers.get("Cache-Control", "No definido"),
                "Location_Header": res.headers.get("Location", "-"),
            }
        )

    except Exception as e:
        return f"Error técnico en HHI: {e}"

    return pd.DataFrame(resultados)


# --- MOTOR PARA Subdomain Takeover ---
def scan_sto(dominio):
    """Analiza registros CNAME y verifica el estado del servicio de destino para EVA."""
    import dns.resolver
    import requests

    firmas_vulnerables = {
        "github.io": "GitHub Pages",
        "herokuapp.com": "Heroku",
        "cloudfront.net": "AWS CloudFront",
        "s3.amazonaws.com": "AWS S3",
        "azurewebsites.net": "Azure",
        "wordpress.com": "WordPress",
        "bitbucket.io": "Bitbucket",
    }

    resultados = []
    try:
        # 1. Resolución DNS de CNAME
        answers = dns.resolver.resolve(dominio, "CNAME")
        for rdata in answers:
            cname_target = str(rdata.target).lower().rstrip(".")

            # 2. Verificación de Firma Técnica
            servicio_detectado = "Desconocido"
            for firma, servicio in firmas_vulnerables.items():
                if firma in cname_target:
                    servicio_detectado = servicio
                    break

            # 3. Prueba de "Huérfano" (Dato clave para EVA)
            # Intentamos ver si el servicio responde con el error típico de 'No encontrado'
            huella_error = "Servicio Activo"
            try:
                res_check = requests.get(f"http://{dominio}", timeout=5, verify=False)
                # Si el código es 404 o tiene textos específicos, el takeover es posible
                textos_abandono = [
                    "there is no app configured",
                    "404 not found",
                    "no such bucket",
                ]
                if any(t in res_check.text.lower() for t in textos_abandono):
                    huella_error = "⚠️ DETECTADO ABANDONO (Posible Takeover)"
            except:
                huella_error = "Servicio no responde (Posible Takeover)"

            resultados.append(
                {
                    "Registro": dominio,
                    "Apunta a": cname_target,
                    "Servicio": servicio_detectado,
                    "Estado": (
                        "❌ VULNERABLE"
                        if "Posible Takeover" in huella_error
                        else "✅ Seguro"
                    ),
                    # --- DATOS PARA EVA ---
                    "Respuesta_HTTP": huella_error,
                    "Riesgo_Impacto": (
                        "ALTO (Suplantación de Identidad)"
                        if servicio_detectado != "Desconocido"
                        else "Bajo"
                    ),
                }
            )

    except Exception as e:
        resultados.append(
            {
                "Registro": dominio,
                "Apunta a": "N/A",
                "Servicio": "Sin CNAME",
                "Estado": "✅ Seguro",
                "Respuesta_HTTP": "-",
                "Riesgo_Impacto": "Nulo",
            }
        )

    return pd.DataFrame(resultados)


# --- MOTOR PARA Header Injection Advanced ---
def scan_header_injection(url):
    """Prueba inyección de encabezados maliciosos (CRLF) con peritaje cognitivo."""
    if not url.startswith("http"):
        url = f"http://{url}"

    # Usamos payloads variados para evadir filtros simples
    payloads = [
        "/%0d%0aInjected-Header:ARGUS-Test",
        "/%0aInjected-Header:ARGUS-Test",
        "/%0dInjected-Header:ARGUS-Test",
    ]

    resultados = []

    try:
        for payload in payloads:
            test_url = f"{url}{payload}"
            # Desactivamos redirecciones para ver el encabezado crudo en el salto
            res = requests.get(test_url, timeout=7, verify=False, allow_redirects=False)

            # --- Lógica de Detección Forense para EVA ---
            is_vuln = False
            evidencia_header = "Ninguna"

            # Buscamos en todos los headers la firma inyectada
            for h_key, h_val in res.headers.items():
                if "ARGUS-Test" in h_val or "Injected-Header" in h_key:
                    is_vuln = True
                    evidencia_header = f"Detectado en: {h_key}"
                    break

            resultados.append(
                {
                    "Payload": payload,
                    "Estado": "❌ VULNERABLE" if is_vuln else "✅ Protegido",
                    "Tipo": "CRLF / Header Injection",
                    # --- DATOS PARA EVA ---
                    "Ubicacion_Inyeccion": evidencia_header,
                    "Codigo_Respuesta": res.status_code,
                    "Server_Signature": res.headers.get("Server", "Desconocido"),
                }
            )

    except Exception as e:
        return f"Error táctico en HHI: {e}"

    return pd.DataFrame(resultados)


# --- MOTOR PARA Reputation & Blacklist Scanner - Threat Intelligence ---
def scan_reputation(target):
    """Consulta listas negras y enriquece la data para el análisis cognitivo de EVA."""
    import socket
    import requests

    dnsbl_lists = ["zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net"]
    resultados = []

    try:
        # 1. Resolución de IP y Datos Geográficos para EVA
        ip = socket.gethostbyname(target)

        # Enriquecimiento de datos vía API pública (IP-API)
        try:
            intel_data = requests.get(f"http://ip-api.com{ip}", timeout=5).json()
            pais = intel_data.get("country", "Desconocido")
            isp = intel_data.get("isp", "Desconocido")
            org = intel_data.get("org", "Desconocido")
        except:
            pais, isp, org = "Error de red", "Error de red", "Error de red"

        # 2. Consulta DNSBL (Inversión de IP)
        reverse_ip = ".".join(reversed(ip.split(".")))
        listado_en_negras = False

        for list_server in dnsbl_lists:
            query = f"{reverse_ip}.{list_server}"
            try:
                socket.gethostbyname(query)
                resultados.append(
                    {"Lista": list_server, "Estado": "🚨 LISTADO / MALICIOSO"}
                )
                listado_en_negras = True
            except socket.gaierror:
                resultados.append({"Lista": list_server, "Estado": "✅ Limpio"})

        # 3. Formateo de DataFrame con "Capa de Inteligencia"
        df_final = pd.DataFrame(resultados)
        # Agregamos metadatos ocultos que EVA leerá en el elif
        df_final["Meta_IP"] = ip
        df_final["Meta_Pais"] = pais
        df_final["Meta_ISP"] = isp

        return df_final

    except Exception as e:
        return pd.DataFrame([{"Error": f"Fallo en auditoría de reputación: {str(e)}"}])


# --- MOTOR PARA Auditoría Criptográfica (Port 443) ---
def scan_ssl_deep(dominio):
    """Auditoría profunda de TLS con peritaje cognitivo para EVA."""
    import ssl
    import socket
    import OpenSSL.crypto
    from datetime import datetime

    try:
        context = ssl.create_default_context()
        with socket.create_connection((dominio, 443), timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert_bin = ssock.getpeercert(True)
                x509 = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_ASN1, cert_bin
                )

                # --- EXTRACCIÓN TÉCNICA AVANZADA PARA EVA ---
                emisor = dict(x509.get_issuer().get_components())
                expira = datetime.strptime(
                    x509.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ"
                )
                dias_restantes = (expira - datetime.now()).days
                algoritmo = x509.get_signature_algorithm().decode("utf-8")
                version_tls = ssock.version()

                # Capturamos la longitud de la llave (Dato crítico para EVA)
                bits_llave = x509.get_pubkey().bits()

                resultados = [
                    {"Metrica": "Protocolo TLS", "Valor": version_tls},
                    {"Metrica": "Cifrado Bits", "Valor": f"{bits_llave} bits"},
                    {"Metrica": "Algoritmo", "Valor": algoritmo},
                    {
                        "Metrica": "Emisor",
                        "Valor": emisor.get(b"O", b"Desconocido").decode(),
                    },
                    {"Metrica": "Dias para vencer", "Valor": f"{dias_restantes} días"},
                ]

                # --- LÓGICA DE RIESGO COGNITIVO ---
                estado = "✅ SEGURO"
                motivos_riesgo = []

                if "TLSv1" in version_tls:
                    estado = "❌ RIESGO"
                    motivos_riesgo.append(
                        "Protocolo Obsoleto (Vulnerable a POODLE/BEAST)"
                    )
                if "sha1" in algoritmo.lower():
                    estado = "❌ RIESGO"
                    motivos_riesgo.append("Algoritmo Débil (SHA1)")
                if bits_llave < 2048:
                    estado = "❌ RIESGO"
                    motivos_riesgo.append("Llave RSA insuficiente (< 2048 bits)")
                if dias_restantes < 15:
                    estado = "❌ RIESGO"
                    motivos_riesgo.append("Expiración Inminente")

                # Devolvemos el DF y un resumen técnico para que EVA lo procese
                df_final = pd.DataFrame(resultados)
                df_final["Meta_Alertas"] = (
                    ", ".join(motivos_riesgo) if motivos_riesgo else "Ninguna"
                )

                return df_final, estado

    except Exception as e:
        return (
            pd.DataFrame([{"Error": f"Fallo en handshake SSL: {str(e)}"}]),
            "❌ RIESGO",
        )


# --- MOTOR PARA Auditoría de LOGS ---
def analizar_logs_forense(contenido_log):
    import re

    # Patrones tácticos de ataque (Expresiones Regulares)
    patrones = {
        "SQL Injection": r"(SELECT|INSERT|UPDATE|DELETE|UNION|OR 1=1|--|'|DROP)",
        "XSS (Scripting)": r"(<script>|alert\(|onerror=|<span>|<div>)",
        "Path Traversal (LFI)": r"(\.\.\/|\.\.\\|etc/passwd|win\.ini|boot\.ini)",
        "Escaneo (Nmap/Bot)": r"(nmap|nikto|dirbuster|sqlmap|gobuster|python-requests)",
        "Fuerza Bruta": r"(failed login|401 Unauthorized|password incorrect|access denied)",
    }

    hallazgos = []
    # Dividimos el log en líneas para saber dónde está el problema
    lineas = contenido_log.split("\n")

    for i, linea in enumerate(lineas):
        for ataque, patron in patrones.items():
            if re.search(patron, linea, re.IGNORECASE):
                hallazgos.append(
                    {
                        "Línea": i + 1,
                        "Evento": ataque,
                        "Trama Sospechosa": linea[
                            :120
                        ].strip(),  # Solo los primeros 120 caracteres
                    }
                )

    return pd.DataFrame(hallazgos)


def guardar_peritaje_log(archivo, cantidad, resumen):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        query = "INSERT INTO log_auditor (nombre_archivo, eventos_detectados, resumen_ia) VALUES (%s, %s, %s)"
        cursor.execute(query, (archivo, cantidad, resumen))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.sidebar.error(f"Error DB Log: {e}")
        return False


# --- MOTOR Black List ---
def obtener_blacklist():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        df = pd.read_sql(
            "SELECT ip, origen, accion FROM blacklist ORDER BY fecha DESC", conn
        )
        conn.close()
        return df
    except:
        return pd.DataFrame(columns=["ip", "origen", "accion"])


def agregar_a_blacklist(ip, origen, accion="Bloqueado 🚫"):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        query = "INSERT IGNORE INTO blacklist (ip, origen, accion) VALUES (%s, %s, %s)"
        cursor.execute(query, (ip, origen, accion))
        conn.commit()
        conn.close()
        return True
    except:
        return False


# --- MOTOR Sensitive Leak Finder ---
def leak_finder_scan(url):
    import requests

    # Diccionario de archivos letales
    leaks = [
        ".env",
        ".git/config",
        "config.php",
        "wp-config.php",
        "database.sql",
        "backup.zip",
        ".htaccess",
        "settings.py",
        "web.config",
        "phpinfo.php",
        ".ssh/id_rsa",
        "credentials.json",
    ]

    if not url.startswith("http"):
        url = f"http://{url}"
    url = url.rstrip("/")

    resultados = []
    for leak in leaks:
        try:
            target = f"{url}/{leak}"
            res = requests.get(target, timeout=4, verify=False, allow_redirects=False)

            # Si el código es 200, encontramos vlnt.
            if res.status_code == 200:
                # Verificamos si no es una página de error 404 camuflada
                if len(res.text) > 0:
                    resultados.append(
                        {
                            "Archivo": leak,
                            "Estado": "🔥 FILTRADO (Crítico)",
                            "URL": target,
                            "Peso": f"{len(res.text)} bytes",
                        }
                    )
        except:
            continue

    return pd.DataFrame(resultados)


# --- MOTOR API Endpoint Discovery ---
def api_discovery_scan(url):
    import requests

    # Diccionario de rutas de API críticas
    api_paths = [
        "api/v1/users",
        "api/v2/users",
        "api/v1/admin",
        "api/auth/login",
        "swagger-ui.html",
        "v1/config",
        "api/docs",
        "graphql",
        "api/v1/debug",
        "api/v1/status",
        "api/v2/db_backup",
        "api/v1/logs",
    ]

    if not url.startswith("http"):
        url = f"http://{url}"
    url = url.rstrip("/")

    resultados = []
    for path in api_paths:
        try:
            target = f"{url}/{path}"
            # Simulamos una petición de API real
            res = requests.get(target, timeout=4, verify=False, allow_redirects=True)

            # Si responde 200 (Abierto) o 401/403 (Existe pero requiere Token), es un hallazgo.
            if res.status_code < 500 and res.status_code != 404:
                status_msg = {
                    200: "✅ ABIERTO (Crítico)",
                    401: "🔐 RESTRINGIDO (Requiere Token)",
                    403: "🚫 PROHIBIDO (Existe)",
                    405: "⚠️ MÉTODO NO PERMITIDO (Existe)",
                }
                resultados.append(
                    {
                        "Endpoint": f"/{path}",
                        "Código": res.status_code,
                        "Estado": status_msg.get(res.status_code, "Detectado"),
                        "Tipo": "REST/GraphQL",
                    }
                )
        except:
            continue

    return pd.DataFrame(resultados)


# --- MOTOR MX & SPF Auditor (Seguridad de Correo) ---
def audit_email_security(dominio):
    import dns.resolver

    resultados = []

    # 1. Verificación de Registros MX (¿Dónde reciben mails?)
    try:
        mx_records = dns.resolver.resolve(dominio, "MX")
        for rdata in mx_records:
            resultados.append(
                {"Prueba": "Registro MX", "Valor": str(rdata.exchange), "Estado": "✅"}
            )
    except:
        resultados.append(
            {"Prueba": "Registro MX", "Valor": "No detectado", "Estado": "❌"}
        )

    # 2. Verificación de Registro SPF (¿Quién tiene permiso para enviar?)
    try:
        txt_records = dns.resolver.resolve(dominio, "TXT")
        spf_encontrado = False
        for rdata in txt_records:
            txt_content = str(rdata)
            if "v=spf1" in txt_content:
                spf_encontrado = True
                estado = "✅"
                # Si el SPF termina en "~all" o "?all", es una política débil (SoftFail)
                if "~all" in txt_content or "?all" in txt_content:
                    estado = "⚠️ DÉBIL"
                resultados.append(
                    {"Prueba": "Registro SPF", "Valor": txt_content, "Estado": estado}
                )

        if not spf_encontrado:
            resultados.append(
                {"Prueba": "Registro SPF", "Valor": "AUSENTE", "Estado": "❌ CRÍTICO"}
            )
    except:
        resultados.append(
            {"Prueba": "Registro SPF", "Valor": "Error de consulta", "Estado": "❌"}
        )

    return pd.DataFrame(resultados)


# --- MOTOR Metadata Stripper & OSINT Analysis ---
def extract_metadata(url_archivo):
    import requests
    from PIL import Image
    from PIL.ExifTags import TAGS
    from io import BytesIO
    import pandas as pd

    # --- PARCHE DE SEGURIDAD: Validación de Esquema ---
    if not url_archivo.startswith(("http://", "https://")):
        url_archivo = f"https://{url_archivo}"

    resultados = []
    try:
        # Simulamos ser un navegador para que el servidor no nos bloquee
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
        }
        res = requests.get(url_archivo, timeout=8, verify=False, headers=headers)

        # Verificamos si la descarga fue exitosa
        if res.status_code != 200:
            return f"❌ Error de Acceso: El servidor respondió con código {res.status_code}"

        # Analizamos si es una imagen
        content_type = res.headers.get("Content-Type", "").lower()
        if "image" in content_type:
            img = Image.open(BytesIO(res.content))
            info = img._getexif()
            if info:
                for tag, value in info.items():
                    decoded = TAGS.get(tag, tag)
                    # Solo agregamos metadatos legibles
                    if isinstance(value, (str, int, float)):
                        resultados.append({"Atributo": decoded, "Valor": str(value)})

                if not resultados:
                    return "⚠️ Imagen limpia: No se detectaron metadatos EXIF legibles."
            else:
                return "⚠️ Imagen sin rastro: El archivo no contiene metadatos ocultos."
        else:
            # Si es otro tipo de archivo, extraemos info del encabezado HTTP
            resultados.append({"Atributo": "Tipo de Archivo", "Valor": content_type})
            resultados.append(
                {
                    "Atributo": "Servidor Detectado",
                    "Valor": res.headers.get("Server", "Oculto"),
                }
            )
            resultados.append(
                {"Atributo": "Tamaño", "Valor": f"{len(res.content) / 1024:.2f} KB"}
            )

        return pd.DataFrame(resultados)

    except Exception as e:
        return (
            f"❌ Error Crítico: No se pudo conectar con el recurso. Detalle: {str(e)}"
        )


# --- MOTOR Recon-Tech (Detección de ADN Web) ---
def tech_recon_scan(url):
    import requests

    if not url.startswith("http"):
        url = f"http://{url}"

    techs = {
        "PHP": "X-Powered-By",
        "ASP.NET": "X-AspNet-Version",
        "Nginx": "Server",
        "Apache": "Server",
        "Cloudflare": "CF-Ray",
        "WordPress": "wp-content",
        "JQuery": "jquery.min.js",
        "Bootstrap": "bootstrap.min.css",
    }

    resultados = []
    try:
        res = requests.get(url, timeout=5, verify=False)
        headers = res.headers
        body = res.text.lower()

        for name, key in techs.items():
            # Buscamos en Headers
            if key in headers and name in [
                "PHP",
                "ASP.NET",
                "Nginx",
                "Apache",
                "Cloudflare",
            ]:
                resultados.append(
                    {
                        "Tecnología": name,
                        "Detección": "Header",
                        "Valor": headers.get(key),
                    }
                )
            # Buscamos en el HTML
            elif key in body:
                resultados.append(
                    {
                        "Tecnología": name,
                        "Detección": "Código Fuente",
                        "Valor": "Presente",
                    }
                )

        return pd.DataFrame(resultados)
    except:
        return pd.DataFrame([{"Error": "No se pudo realizar el reconocimiento"}])


def param_fuzzer_scan(url):
    import requests

    # Parámetros sospechosos comunes
    params_test = ["id", "page", "file", "user", "dir", "search", "lang"]
    payload_error = "'\"<script>alert(1)</script>"

    if not url.startswith("http"):
        url = f"http://{url}"
    url = url.split("?")[0]  # Limpiamos la URL

    resultados = []
    for p in params_test:
        try:
            target = f"{url}?{p}={payload_error}"
            res = requests.get(target, timeout=4, verify=False)

            # Si el servidor responde con un error 500 o refleja el payload, hay algo
            if res.status_code == 500 or payload_error in res.text:
                resultados.append(
                    {
                        "Parámetro": p,
                        "Estado": "⚠️ SENSIBLE",
                        "Tipo": "Posible Inyección / Error Interno",
                        "URL": target,
                    }
                )
        except:
            continue

    return pd.DataFrame(resultados)


# --- MOTOR Parameter Fuzzer (fallos dentro de las variables de una página (?id=1, ?user=test))  ---
def param_fuzzer_scan(url):
    import requests
    import pandas as pd

    # 1. Limpieza de URL (Eliminamos parámetros previos si los hay)
    base_url = url.split("?")[0]

    # 2. Diccionario de parámetros tácticos (Los más sensibles en auditorías)
    params_test = [
        "id",
        "page",
        "file",
        "user",
        "dir",
        "search",
        "lang",
        "doc",
        "path",
        "url",
        "redirect",
        "token",
        "view",
    ]

    # Payload de ruido: Mezcla de caracteres para forzar errores SQL, XSS y Path Traversal
    payload_error = "'\"<script>alert(EVA)</script>../../etc/passwd"

    resultados = []

    # Simulamos ser un navegador para evitar bloqueos
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ARGUS Ecosystem/5.7"}

    for p in params_test:
        try:
            # Construimos la URL con la inyección: ej. ://site.com'\"<script>...
            target = f"{base_url}?{p}={payload_error}"

            # Hacemos la petición (timeout corto para que sea rápido)
            res = requests.get(target, timeout=5, verify=False, headers=headers)

            # --- Lógica de Detección Forense ---
            is_vuln = False
            evidencia = "Estable"

            # A. Detección de Error Interno (Posible SQLi)
            if res.status_code == 500:
                is_vuln = True
                evidencia = "🚨 Error 500 (Fuga Interna)"

            # B. Detección de Reflejo (Posible XSS)
            elif payload_error in res.text:
                is_vuln = True
                evidencia = "💉 Payload Reflejado (XSS)"

            # C. Detección de Información Sensible (LFI)
            elif "root:" in res.text or "boot.ini" in res.text:
                is_vuln = True
                evidencia = "📂 Fuga de Sistema (LFI)"

            if is_vuln:
                resultados.append(
                    {
                        "Parámetro": p,
                        "Respuesta": res.status_code,
                        "Vulnerabilidad": evidencia,
                        "Payload": payload_error[:20] + "...",
                    }
                )
        except:
            continue

    return pd.DataFrame(resultados)


# --- MOTOR Sincorizar Mapa con Black List ---
def sincronizar_mapa_db():
    """Obtiene todas las IPs de la Blacklist y las geolocaliza para el mapa."""
    df_negra = obtener_blacklist()  # La función que ya tenemos
    if not df_negra.empty:
        lista_ips = df_negra["ip"].tolist()
        return obtener_datos_mapa(lista_ips)
    return []


def mapear_ruta_cyberpunk(target_ip):
    """Ejecuta traceroute con Scapy y genera la matriz visual animada."""
    try:
        res, unans = traceroute(target_ip, max_ttl=15, verbose=0)
        ip_list = [target_ip]
        for send, recv in res:
            if recv.src not in ip_list:
                ip_list.append(recv.src)

        coordinates = []
        for ip in ip_list:
            try:
                if ip.startswith(("10.", "192.168.", "172.", "127.")):
                    continue
                # Corrección del endpoint agregando la barra "/"
                response = requests.get(
                    f"http://ip-api.com{ip}?fields=status,country,city,lat,lon,isp,org",
                    timeout=3,
                ).json()
                if response["status"] == "success":
                    coordinates.append(
                        {
                            "lat": response["lat"],
                            "lon": response["lon"],
                            "ip": ip,
                            "location": f"{response.get('city', 'Desconocida')}, {response.get('country', 'Desconocido')}",
                            "isp": response.get("isp", "Proveedor Desconocido"),
                            "org": response.get("org", "Organización Desconocida"),
                        }
                    )
            except:
                pass

        if coordinates:
            m = folium.Map(
                location=[coordinates[0]["lat"], coordinates[0]["lon"]],
                zoom_start=3,
                tiles=None,
            )
            folium.TileLayer(
                "CartoDB dark_matter", name="Modo Oscuro Cyberpunk"
            ).add_to(m)
            folium.TileLayer("OpenStreetMap", name="Mapa Estándar").add_to(m)

            route_group = folium.FeatureGroup(
                name="Pulsos de Red Animados", overlay=True
            ).add_to(m)
            points = []
            for node in coordinates:
                popup_html = f"""
                <div style="font-family: 'Courier New', monospace; min-width: 200px; color: #1A1A24;">
                    <b style="color: #7B2CBF;">[ NODO DE RED ]</b><br>
                    <b>IP:</b> {node['ip']}<br>
                    <b>Ubicación:</b> {node['location']}<br>
                    <b>Proveedor:</b> {node['isp']}<br>
                    <b>Compañía:</b> {node['org']}
                </div>
                """
                folium.Marker(
                    location=[node["lat"], node["lon"]],
                    popup=folium.Popup(popup_html, max_width=300),
                    tooltip=f"{node['location']} ({node['ip']})",
                    icon=folium.Icon(color="red", icon="info-sign"),
                ).add_to(route_group)
                points.append([node["lat"], node["lon"]])

            AntPath(
                locations=points,
                color="#00ffff",
                pulse_color="#ffffff",
                weight=4,
                opacity=0.9,
                delay=800,
            ).add_to(route_group)
            folium.LayerControl(collapsed=False).add_to(m)
            return m
    except:
        pass
    return None


# --- MOTOR Sincorizar Mapa con Black List ---
def sincronizar_mapa_db():
    """Obtiene todas las IPs de la Blacklist y las geolocaliza para el mapa."""
    df_negra = obtener_blacklist()  # La función que ya tenemos
    if not df_negra.empty:
        lista_ips = df_negra["ip"].tolist()
        return obtener_datos_mapa(lista_ips)
    return []


# --- INTERFAZ ARGUS Ecosystem ---
st.sidebar.image("LogoSN.png", width=250)
st.sidebar.markdown("---")
st.sidebar.write("**OPERADOR:** Auditor Name")
st.sidebar.write("**NIC:** `ARGUS Ecosystem-2026-LEGAL` 🟢")
st.sidebar.write("**IA ANALYST:** `EVA-v5.4-ACTIVE` 🧠")
st.sidebar.write("**C.O. ARGUS Ecosystem :** `v5.7.000.1` 🛡️")
st.sidebar.markdown("---")

menu = st.sidebar.radio(
    "Modulos de Inteligencia:",
    [
        "Centro de Comando",
        "IA Tactical Analyst",
        "Log Auditor",
        "Métricas e Histórico",
        "Sentinel (Red)",
        "Scout (Infraestructura)",
        "Cookie Auditor",
        "Subdomain Hunter",
        "Watchtower (SSL/DNS)",
        "SSL Deep Auditor",
        "Reputation Scanner",
        "Vulnerability Scanner",
        "LFI Scanner",
        "Pro Fuzzer",
        "Sensitive Leak Finder",
        "API Endpoint Discovery",
        "Email Security Auditor",
        "Metadata Stripper",
        "Recon-Tech",
        "Parameter Fuzzer",
        "Host Header Auditor",
        "Subdomain Takeover",
        "Header Injection",
        "IPS Local",
        "External Sentinel IPS",
    ],
)

if menu == "Centro de Comando":
    # 1. ESTILOS Y CABECERA (Simetría de Comando: SW - TÍTULO - EVA)
    st.markdown("""<style>/* Tu CSS */</style>""", unsafe_allow_html=True)

    # Creamos 3 columnas: [Logo SW (Izquierda), Título (Centro), Logo EVA (Derecha)]
    col_izq, col_centro, col_der = st.columns([1, 4, 1])

    with col_izq:
        st.image("LogoSN.png", width=140)

    with col_centro:
        st.markdown(
            "<h1 style='text-align: center; margin-bottom: 0;'>Operations Center</h1>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<p style='text-align: center; font-size: 1.2rem; color: #888;'>Unidad de Vigilancia y Ciberdefensa Táctica</p>",
            unsafe_allow_html=True,
        )

    with col_der:
        st.image("LogoEVA.png", width=110)

    st.markdown("---")

    # --- CARGA ÚNICA DE INTELIGENCIA (Evita errores de variable) ---
    df_inteligencia = obtener_blacklist()
    if not df_inteligencia.empty:
        lista_ips_radar = df_inteligencia["ip"].tolist()
    else:
        lista_ips_radar = ["8.8.8.8"]  # IP de respaldo

    # 2. MÉTRICAS DINÁMICAS (Conexión Real a MySQL)
    st.subheader("🚨 Estado de Amenazas - Tiempo Real")
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT SUM(riesgo_detectado) FROM auditorias")
        res_r = cursor.fetchone()[0]
        total_riesgos = int(res_r) if res_r is not None else 0

        cursor.execute("SELECT SUM(eventos_detectados) FROM log_auditor")
        res_l = cursor.fetchone()[0]
        total_logs = int(res_l) if res_l is not None else 0
        conn.close()
    except:
        total_riesgos, total_logs = 0, 0

    m1, m2, m3, m4 = st.columns(4)
    nivel_alerta = "BAJO"
    if (total_riesgos + total_logs) > 0:
        nivel_alerta = "MEDIO"
    if (total_riesgos + total_logs) > 15:
        nivel_alerta = "ALTO"

    m1.metric("Nivel de Amenaza", nivel_alerta, delta="SISTEMA VIVO")
    m2.metric(
        "Eventos Críticos", total_riesgos, delta="Hallazgos DB", delta_color="inverse"
    )
    m3.metric("Logs Detectados", total_logs, delta="Forense IA", delta_color="inverse")
    m4.metric("Accesos Fallidos", "27", delta="Simulado")
    st.markdown("---")

    # 3.  RADAR GLOBAL DINÁMICO
    st.subheader("🌍 Radar Global de Amenazas (Sincronizado con DB)")
    with st.spinner("Sincronizando con el satélite..."):
        datos_puntos = obtener_datos_mapa(lista_ips_radar)

    if len(datos_puntos) > 0:
        try:
            m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
            for punto in datos_puntos:
                folium.Marker(
                    [punto["lat"], punto["lon"]],
                    popup=punto["info"],
                    icon=folium.Icon(color="red", icon="bolt", prefix="fa"),
                ).add_to(m)
            heat_data = [[p["lat"], p["lon"]] for p in datos_puntos]
            HeatMap(heat_data).add_to(m)
            folium_static(m, width=1200, height=450)
            st.caption(
                f"🛰️ Satélite Actualizado: {time.strftime('%H:%M:%S')} | Amenazas en Radar: {len(datos_puntos)}"
            )
        except Exception as e:
            st.error(f"Error en el barrido: {e}")

    # 4.  ANÁLISIS DE GUARDIA (EVA)
    st.markdown("---")
    c_eva1, c_eva2 = st.columns([1, 4])
    with c_eva1:
        st.image("LogoEVA.png")
    with c_eva2:
        st.subheader("👁️ Veredicto de la Analista de Guardia")
        if st.button("🚀 Generar Informe de Situación Actual"):
            with st.spinner("Analizando vectores..."):
                contexto = "Operations Center - Estado General"
                hallazgos_ia = f"Amenaza: {nivel_alerta}, Riesgos: {total_riesgos}, Logs: {total_logs}, IPs: {lista_ips_radar}"
                informe_ia = consultar_ia_tactica(contexto, hallazgos_ia)
                st.info(informe_ia)
                pdf_comando = generar_pdf_ia(
                    "Flash Report - Centro de Comando", informe_ia
                )
                st.download_button(
                    "📥 Descargar Flash Report (PDF)",
                    pdf_comando,
                    "SH_Flash_Report.pdf",
                )

    st.markdown("---")

    # 5. LISTA NEGRA REAL (Basada en df_inteligencia)
    st.subheader("🕵️ IPs Sospechosas en el Perímetro (Blacklist Real)")
    if not df_inteligencia.empty:
        st.dataframe(df_inteligencia, use_container_width=True)
    else:
        st.info("✅ Perímetro limpio. No hay IPs bloqueadas en MySQL.")

    # Formulario para agregar amenazas
    with st.expander("➕ Registrar Nueva Amenaza"):
        c1, c2, c3 = st.columns(3)
        ip_in = c1.text_input("IP:")
        org_in = c2.text_input("Origen:")
        if c3.button("🛡️ Bloquear"):
            if ip_in:
                agregar_a_blacklist(ip_in, org_in)
                st.success(f"IP {ip_in} integrada al sistema.")
                st.rerun()

    st.caption(f"🛡️ Operador: Auditor Name - CIBERSEGURIDAD | NIC: ARGUS Ecosystem-2026-LEGAL")


# --- CENTRO DE CONTROL ---

# --- CONTROL DE Métricas e historicos ---
elif menu == "Métricas e Histórico":
    # --- LA VALLA DE SEGURIDAD GENERAL DE TU DB ---
    if not st.session_state.get("autenticado", False):
        st.error("🔒 ACCESO DENEGADO: Terminal bloqueada. Por favor, inicie sesión en el Centro de Comando.")
        st.stop()

    st.header("📊 Inteligencia de Datos Cifrados - ARGUS Ecosystem")
    st.write("Línea de tiempo forense multicliente. Los datos sensibles permanecen blindados hasta su autenticación.")

    from shadenull_core import recuperar_auditorias_cliente

    # 1. Entrada de Selección de Entorno
    target_empresa = st.text_input("Ingrese el nombre de la Empresa a Auditar:")

    if target_empresa:
        # Definimos las rutas para verificar si el búnker existe antes de pedir credenciales
        carpeta_verificar = f"clientes/{target_empresa}"
        archivo_verificar = f"{carpeta_verificar}/analisis_suite.txt"
        
        if os.path.exists(archivo_verificar):
            st.success(f"📂 Detectado búnker de seguridad activo para: `{target_empresa}`")
            
            # Formulario de protección para Ver Detalles
            pass_empresa = st.text_input(f"Introduce la llave criptográfica de {target_empresa}:", type="password")
            
            # Inicializar estados de descifrado específicos del cliente si no existen
            if "bunker_descifrado" not in st.session_state:
                st.session_state.bunker_descifrado = False
            if "registros_guardados" not in st.session_state:
                st.session_state.registros_guardados = []
            if "pass_bunker_activa" not in st.session_state:
                st.session_state.pass_bunker_activa = ""

            if st.button("🔓 Desencriptar Historial de Evidencias"):
                with st.spinner("Descifrando bloques binarios y validando Salt..."):
                    registros = recuperar_auditorias_cliente(target_empresa, pass_empresa)
                    
                    if registros == "ERROR_CLAVE_INVALIDA":
                        st.session_state.bunker_descifrado = False
                        st.session_state.pass_bunker_activa = ""
                        # --- DISPARO DE SEGURIDAD PROACTIVA (SIEM LOCAL) ---
                        timestamp_intrusión = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        mensaje_alarma = (
                            f"🚨 *ALERTA CRÍTICA ARGUS Ecosystem*\n"
                            f"----------------------------------------\n"
                            f"⚠️ *EVENTO:* Intento de Acceso No Autorizado\n"
                            f"🏢 *ENTORNO:* Búnker de Cliente `{target_empresa}`\n"
                            f"⏰ *TIMESTAMP:* `{timestamp_intrusión}`\n"
                            f"🛑 *ACCIÓN:* Criptografía XOR bloqueó el volcado.\n"
                            f"----------------------------------------\n"
                            f"📌 _Verifique la integridad del host de inmediato._"
                        )
                        
                        try:
                            enviar_alerta_telegram(mensaje_alarma)
                        except Exception as tel_err:
                            print(f"[!] Fallo al despachar alerta al satélite de Telegram: {tel_err}")
                        
                        st.error("❌ CLAVE INVÁLIDA: El búnker criptográfico ha bloqueado el descifrado. Acceso denegado e incidente reportado al satélite.")
                    
                    elif len(registros) == 0:
                        st.session_state.bunker_descifrado = False
                        st.session_state.pass_bunker_activa = ""
                        st.info("El búnker existe pero no contiene registros de auditorías guardados.")
                    else:
                        st.balloons()
                        # Guardamos en sesión todo lo necesario para resistir recargas de Streamlit
                        st.session_state.bunker_descifrado = True
                        st.session_state.registros_guardados = registros
                        st.session_state.pass_bunker_activa = pass_empresa

            # --- RENDERIZADO INMUNE A RECARGAS ---
            if st.session_state.bunker_descifrado:
                st.success(f"✔ Matriz descifrada con éxito. {len(st.session_state.registros_guardados)} auditorías recuperadas.")
                
                # Renderizamos los reportes estructurados en tablas dinámicas
                for i, rep in enumerate(st.session_state.registros_guardados, 1):
                    with st.expander(f"📋 Reporte #{i} - {rep['fecha']} | [{rep['tipo_auditoria']}]"):
                        st.markdown(f"**Fecha de Operación:** `{rep['fecha']}`")
                        st.markdown(f"**Estructura de Datos Crudos:**")
                        st.json(rep['datos_crudos'])
                        st.markdown(f"**🔮 Veredictos Analíticos Locales (EVA):**")
                        st.info(rep['veredicto_eva'])
                
# --- NUEVO BLOQUE: FILTRO DE ESPECIALIDAD FORENSE ---
            st.markdown("---")
            st.subheader("📊 Filtro de Especialidad Forense")
            
            modulo_a_filtrar = st.selectbox(
                "Seleccione el tipo de informe que desea aislar y compilar:",
                ["Log Forensics & Incident Report", "Network Perimeter Audit", "Cookie Security Audit"],
                key="selector_modulo_forense"
            )
            
            # Normalización defensiva de tags para evitar fallos de coincidencia exacta con el búnker
            tag_busqueda_real = modulo_a_filtrar
            if modulo_a_filtrar == "Network Perimeter Audit":
                # Si en backend se guardó originalmente con un string más corto, ajustarlo acá:
                tag_busqueda_real = "Network Audit" 

            # Ejecutamos la extracción limpia usando la contraseña persistida en memoria
            with st.spinner("Filtrando registros criptográficos..."):
                registros_filtrados = recuperar_auditorias_cliente(
                    target_empresa, st.session_state.pass_bunker_activa, filtro_modulo=tag_busqueda_real
                )
            
            if len(registros_filtrados) == 0:
                st.info(f"El búnker no registra análisis guardados para la especialidad: `{modulo_a_filtrar}`")
            else:
                st.success(f"Se aislaron {len(registros_filtrados)} reportes para el PDF.")
                
                pdf_data_corp = None
                
                # Para la generación del PDF usamos la lógica correspondiente a la selección de la UI
                if modulo_a_filtrar == "Log Forensics & Incident Report":
                    pdf_data_corp = generar_pdf_log_corporativo(target_empresa, modulo_a_filtrar, registros_filtrados)
                elif modulo_a_filtrar == "Network Perimeter Audit":
                    pdf_data_corp = generar_pdf_red_corporativo(target_empresa, modulo_a_filtrar, registros_filtrados)
                
                if pdf_data_corp:
                    st.download_button(
                        label=f"🚀 Descargar Documentación Especializada ({modulo_a_filtrar})",
                        data=pdf_data_corp,
                        file_name=f"Reporte_{modulo_a_filtrar.replace(' ', '_')}_{target_empresa}_{datetime.now().strftime('%Y%m%d')}.pdf",
                        mime="application/pdf",
                        key="btn_descarga_pdf_premium"
                    )
        else:
            st.warning(f"No se ha encontrado ninguna infraestructura creada para la empresa '{target_empresa}'. Realiza un escaneo previo para fundar el búnker.")

# --- CONTROL Sentinel (Red) ---
elif menu == "Sentinel (Red)":
    st.header("🛰️ Sentinel - Escaneo con Remediación")
    st.write("Detección de puertos abiertos, mitigación perimetral y Persistencia Criptográfica.")

    # 1. ENTORNO MULTICLIENTE (Parámetros de ARGUS Ecosystem)
    col_c1, col_c2 = st.columns(2)
    with col_c1:
        empresa_cliente = st.text_input("Nombre de la Empresa Auditada:", value="Empresa_Alfa_Test")
    with col_c2:
        pass_cliente = st.text_input("Llave Criptográfica para este búnker:", type="password")

    if st.button("🔄 Reiniciar Sentinel"):
        for key in ["df_sentinel", "target_sentinel_actual", "ver_sentinel_eva"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    target = st.text_input("Objetivo (IP o Dominio):", value="scanme.nmap.org")
    
    # DICCIONARIO MAESTRO: Mapea la Opción con el Comando Real y su Manual Táctico de Campo
    arsenal_sentencias = {
        "🎯 Tiro 1: Sigiloso SYN Scan - nmap -sS --top-ports 50 [Ruido Bajo]": {
            "comando": "nmap -sS --top-ports 50",
            "proposito": "Reconocimiento inicial rápido e invisible.",
            "busqueda": "Identificar los 50 servicios más comunes abiertos sin completar la conexión TCP (evitando registrar logs estáticos en servidores antiguos)."
        },
        "🥷 Tiro 2: Evasión por Fragmentación - nmap -sS -f --mtu 16 --top-ports 100 [Bypass Firewall]": {
            "comando": "nmap -sS -f --mtu 16 --top-ports 100",
            "proposito": "Bypass de Firewalls tradicionales de Inspección de Paquetes.",
            "busqueda": "Troza las cabeceras TCP en fragmentos ultra pequeños de 16 bytes. Obliga al firewall del cliente a dejar pasar el tráfico si sus reglas no reensamblan el payload en tiempo real."
        },
        "👻 Tiro 3: Stealth NULL Scan - nmap -sN -Pn --top-ports 100 [Especial Linux]": {
            "comando": "nmap -sN -Pn --top-ports 100",
            "proposito": "Escaneo fantasma de alta evasión contra hosts UNIX/Linux.",
            "busqueda": "Envía paquetes TCP sin ninguna bandera (flags) activa. Si el puerto está cerrado devuelve un RESET, pero si está abierto o protegido, el host no responde, deschavando firewalls estáticos."
        },
        "🧱 Tiro 4: Mapeo de Reglas ACK - nmap -sA -Pn --top-ports 200 [Auditoría de Bloqueos]": {
            "comando": "nmap -sA -Pn --top-ports 200",
            "proposito": "Mapeo y descubrimiento de las reglas de filtrado del Firewall.",
            "busqueda": "No busca puertos abiertos. Envía flags ACK para forzar al cortafuegos a responder. Si el puerto devuelve un RESET, significa que está 'No Filtrado' (abierto en el Firewall aunque el servicio esté cerrado)."
        },
        "🪟 Tiro 5: TCP Window Scan - nmap -sW --top-ports 100 [Bypass Avanzado Firewall]": {
            "comando": "nmap -sW --top-ports 100",
            "proposito": "Exploración de vulnerabilidades de reporte en el tamaño de ventanas TCP.",
            "busqueda": "Examina de forma matemática el campo 'Window' de las respuestas RST del objetivo. Permite romper falsos negativos y diferenciar puertos abiertos de cerrados en routers específicos."
        },
        "🧬 Tiro 6: Escaneo de Protocolos IP - nmap -sO [Capa 3 Forensics]": {
            "comando": "nmap -sO",
            "proposito": "Auditoría profunda de la capa de red del perímetro.",
            "busqueda": "No busca puertos; determina qué protocolos de transporte enteros están habilitados en el host del cliente (ej: ICMP, OSPF, GRE, TCP, UDP) para cazar túneles ocultos o fallos de enrutamiento."
        },
        "🕵️‍♂️ Tiro 7: Banner Grabbing Pasivo - nmap -sV --version-intensity 3 --top-ports 50 [Identificación Software]": {
            "comando": "nmap -sV --version-intensity 3 --top-ports 50",
            "proposito": "Caza y recolección de versiones exactas de software en sigilo.",
            "busqueda": "Interroga los servicios abiertos con una intensidad baja para capturar los banners (ej: saber si corren Apache 2.4 o MySQL 8.0) sin activar los sistemas de alertas de intrusión (IDS)."
        },
        "🔥 Tiro 8: Agresivo Total - nmap -A --top-ports 50 [Ruido Máximo - Detección OS]": {
            "comando": "nmap -A --top-ports 50",
            "proposito": "Auditoría perimetral de fuerza bruta y fingerprinting completo.",
            "busqueda": "Lanza un barrido ruidoso que combina detección de sistema operativo, scripts de vulnerabilidades automatizados y traceroute. Se usa solo cuando la defensa ya fue comprometida."
        }
    }

    # Selector visual para el operador
    tiro_seleccionado = st.selectbox("Seleccione la Intensidad del Armamento Perimetral:", list(arsenal_sentencias.keys()))
    
    # Extraemos los datos de la subestructura elegida
    sentencia_base = arsenal_sentencias[tiro_seleccionado]["comando"]
    proposito_tatico = arsenal_sentencias[tiro_seleccionado]["proposito"]
    objetivo_busqueda = arsenal_sentencias[tiro_seleccionado]["busqueda"]

    # --- EL CUADRO PEDAGÓGICO INTERACTIVO ---
    with st.container():
        st.markdown(f"""
        <div style="background-color: #0c0f1d; padding: 15px; border-left: 5px solid #1f3a60; border-radius: 4px; margin-bottom: 20px;">
            <p style="margin: 0; font-size: 14px; color: #a0aec0;"><strong>📋 PROPÓSITO OPERACIONAL:</strong> {proposito_tatico}</p>
            <p style="margin: 5px 0 0 0; font-size: 13px; color: #cbd5e0;"><strong>🔍 QUÉ BUSCAMOS:</strong> {objetivo_busqueda}</p>
        </div>
        """, unsafe_allow_html=True) # <-- PARCHE: Cambiado a 'unsafe_allow_html'


    if st.button("📡 Iniciar Escaneo de Red"):
        if target and empresa_cliente and pass_cliente:
            with st.spinner(f"Sentinel ejecutando: {sentencia_base} {target}..."):
                
                # CONCATENACIÓN CRÍTICA: Fusionamos la sentencia del selector con el Host objetivo
                comando_final_ejecucion = f"{sentencia_base} {target}"
                
                # Llamamos la nueva función de subprocess pasándole la cadena armada
                df_res = scan_ports(comando_final_ejecucion)
                
                st.session_state.df_sentinel = df_res
                st.session_state.target_sentinel_actual = target

                hay_riesgo = 1 if (not df_res.empty and (df_res["Estado"] == " ABIERTO").any()) else 0
                guardar_historial("Sentinel", target, hay_riesgo)
                st.toast(f"Análisis de red completado con éxito.")
        else:
            st.warning("⚠️ Operador: Complete Empresa, Clave y Objetivo antes de iniciar el escaneo.")

    # REGLA DE SESIÓN: Si ya existen datos de escaneo cargados
    if "df_sentinel" in st.session_state:
        df = st.session_state.df_sentinel
        t_sentinel = st.session_state.target_sentinel_actual

        if not df.empty and (df["Estado"] == " ABIERTO").any():
            st.warning(f"⚠️ Se detectaron puertos abiertos en {t_sentinel}.")
        else:
            st.success(f"🔒 No se detectaron puertos abiertos comunes en {t_sentinel}.")

        st.markdown("---")

        # === MOTOR DEL MAPA CYBERPUNK ===
        st.subheader("🛰️ Matriz Visual de Ruta Física (Telemetría Automática)")
        with st.spinner("EVA calculando saltos de red de forma asíncrona..."):
            mapa_autodisparado = mapear_ruta_cyberpunk(t_sentinel)
            if mapa_autodisparado:
                folium_static(mapa_autodisparado, width=1200, height=450)
            else:
                st.info("Información: Destino local o los nodos intermedios mitigaron los ecos ICMP.")

        st.markdown("---")

        # TÁNDEM HÍBRIDO DE INTELIGENCIA DE RED
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("⚙️ Evaluación de Riesgo Perimetral de EVA")
            
            if st.button("🧠 Iniciar Peritaje de Red Dinámico"):
                
                # REGLA 1: Ollama local aísla la topología en la GPU
                with st.spinner("Ollama aislando topología en la RTX 4060..."):
                    url_ollama = "http://localhost:11434/api/generate"
                    prompt_ollama = f"""
                    [SYSTEM: Eres el extractor de infraestructura de red de ARGUS Ecosystem. Rol: Aislamiento de puertos]
                    Analiza la siguiente tabla de escaneo. Extrae de forma literal únicamente los puertos que reporten un estado 'ABIERTO' o 'FILTRADO'.
                    MATRIZ DE ESCANEO DE PUERTOS:
                    {df.to_string() if not df.empty else "Resultado: Perímetro blindado."}
                    """
                    payload = {"model": "qwen2.5-coder:7b", "prompt": prompt_ollama, "stream": False}
                    try:
                        res_ol = requests.post(url_ollama, json=payload, timeout=90)
                        veredicto_ollama = res_ol.json().get("response", "Error: Búfer vacío.")
                    except Exception as e:
                        veredicto_ollama = f"❌ Error de extracción en GPU: {str(e)}"

                # REGLA 2: EVA analiza, detecta falsos positivos y genera la recomendación de pivotaje
                with st.spinner("EVA analizando anomalías perimetrales y falsos positivos..."):
                    # Evaluamos si existen puertos sospechosos en el DataFrame para guiar el prompt
                    tiene_filtrados = (df["Estado"] == " FILTRADO").any() if not df.empty else False
                    tiene_comunes_cerrados = not df.empty and len(df) < 5 # Escaneo sospechosamente vacío
                    
                    # El arsenal de sentencias empaquetado para el prompt
                    prompt_eva = f"""
                    [INSTRUCCIONES DE ROL: Eres EVA-v5.4, el cerebro analítico perimetral de ARGUS Ecosystem. Tu rol es auditar los puertos detectados y alertar al operador si sospechas de FALSOS POSITIVOS o FALSOS NEGATIVOS debidos a la interferencia de un Firewall o IDS.]
                    
                    DATOS DE PUERTOS CONFIRMADOS POR OLLAMA:
                    {veredicto_ollama}
                    
                    ¿HAY PUERTOS FILTRADOS EN EL DATAFRAME?: {tiene_filtrados}
                    ¿EL ESCANEO RETORNÓ POCOS RESULTADOS (POSIBLE FALSO NEGATIVO)?: {tiene_comunes_cerrados}
                    
                    # ... [Líneas anteriores del prompt de EVA coinciden] ...
                    
                    Estructura tu respuesta exactamente en estas 4 secciones corporativas:
                    1. DIAGNÓSTICO EJECUTIVO DE SUPERFICIE DE ATAQUE.
                    2. ANÁLISIS DE FALSOS POSITIVOS/NEGATIVOS (Explica si el firewall está engañando al escaneo).
                    3. SUGERENCIA DE PIVOTAJE TÁCTICO (Si hay sospecha, selecciona ÚNICAMENTE una sola sentencia del siguiente arsenal de ARGUS Ecosystem y muéstrala formateada en una línea limpia para el operador, reemplazando la variable de destino:
                       - Opción A: nmap -sS -f --mtu 16 {t_sentinel}
                       - Opción B: nmap -sN -Pn {t_sentinel}
                       - Opción C: nmap -sF -Pn {t_sentinel}
                       - Opción D: nmap -sA -p- {t_sentinel}
                       - Opción E: nmap -sS --source-port 53 {t_sentinel}
                       Regla estricta: No dupliques el comando ni agregues textos repetitivos dentro de la sentencia).
                    4. PLAN DE RECOMENDACIONES GENERALES.
                    """
                    st.session_state.ver_sentinel_eva = consultar_ia_tactica(f"Red - {empresa_cliente}", prompt_eva)
                    
                    # REGLA 3: PERSISTENCIA CRIPTOGRÁFICA EN EL BÚNKER
                    try:
                        from shadenull_core import guardar_auditoria_cliente
                        evidencia_json = {
                            "objetivo_escaneado": t_sentinel,
                            "matriz_puertos_cruda": veredicto_ollama[:1500]
                        }
                        guardar_auditoria_cliente(
                            empresa=empresa_cliente,
                            tipo_auditoria="Network Perimeter & Pivot Audit",
                            datos_crudos=evidencia_json,
                            veredicto_eva=st.session_state.ver_sentinel_eva,
                            password=pass_cliente
                        )
                        st.toast("🔒 Auditoría perimetral y mapa de pivotaje blindados en el Núcleo.")
                    except Exception as err:
                        st.error(f"Fallo en persistencia: {err}")

            # Despliegue dinámico en pantalla
            if "ver_sentinel_eva" in st.session_state:
                informe_completo = st.session_state.ver_sentinel_eva
                st.info(informe_completo)
                
                # --- BOX DE ALERTA VISUAL DE PIVOTAJE (Threat Intelligence) ---
                if "SUGERENCIA DE PIVOTAJE TÁCTICO" in informe_completo:
                    st.warning("⚠️ **ALERTA DE CAZA DE AMENAZAS: RECOMENDACIÓN DE PIVOTAJE DETECTADA**")
                    st.markdown("""
                    Basado en las firmas anómalas de la red, el sistema detectó que las defensas perimetrales del objetivo podrían estar generando falsos negativos. 
                    El arsenal dinámico de **ARGUS Ecosystem** está calibrado. Revisa la sección **3** del informe de arriba, copia la sentencia recomendada por EVA y ejecútala en tu consola para romper el bloqueo del firewall.
                    """)
                    
                    # Disparador automático a Telegram si es Crítico (Falso negativo confirmado)
                    if "nmap -" in informe_completo:
                        mensaje_tele = f"📡 ARGUS Ecosystem INTEL: Detectado posible bloqueo por Firewall en '{t_sentinel}'. EVA sugiere pivotar el armamento perimetral."
                        enviar_alerta_telegram(mensaje_tele)

        # --- EL BOTÓN DE DESCARGA CONECTADO A LA NUEVA PLANTILLA DE RED EXTERNA ---
        st.markdown("---")
        st.subheader("📥 Exportación Ejecutiva")
        try:
            # Trae el historial cifrado de la subcarpeta para armar el PDF completo de la empresa
            from shadenull_core import recuperar_auditorias_cliente
            registros_red = recuperar_auditorias_cliente(empresa_cliente, pass_cliente)
            
            if isinstance(registros_red, list) and len(registros_red) > 0:
                pdf_data_red = generar_pdf_red_corporativo(empresa_cliente, "Network & Infrastructure Audit", registros_red)
                
                st.download_button(
                    label=f"📥 Descargar Reporte Perimetral Final de {empresa_cliente} (PDF)",
                    data=pdf_data_red,
                    file_name=f"SH_Network_Audit_{empresa_cliente}.pdf",
                    mime="application/pdf",
                )
            else:
                st.info("Para habilitar el botón de descarga en PDF, ejecute primero el 'Peritaje de Red Dinámico' de arriba para registrar las evidencias de la empresa.")
        except Exception as pdf_err:
            st.error(f"Error generando el búfer del PDF: {pdf_err}")



# --- CONTROL Scout (Infraestructura) ---
elif menu == "Scout (Infraestructura)":
    st.header("🔎 Scout - Análisis de Headers y Directivas")
    st.write(
        "Auditoría de cabeceras de seguridad HTTP para prevenir ataques XSS, Clickjacking y degradación SSL."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Scout"):
        for key in ["df_scout", "target_scout_actual", "ver_scout_eva"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    target = st.text_input("Dominio Objetivo:", value="google.com")

    if st.button("🚀 Iniciar Análisis de Infraestructura"):
        with st.spinner(f"Auditando {target}..."):
            try:
                # 1. Ejecución técnica
                res = requests.get(f"https://{target}", verify=False, timeout=10)
                headers_auditar = [
                    "Strict-Transport-Security",
                    "Content-Security-Policy",
                    "X-Frame-Options",
                    "X-Content-Type-Options",
                    "Referrer-Policy",
                ]

                res_data = []
                for h in headers_auditar:
                    estado = "✅" if h in res.headers else "❌"
                    res_data.append(
                        {
                            "Header": h,
                            "Estado": estado,
                            "Valor": res.headers.get(h, "No definido"),
                        }
                    )

                # Persistencia en sesión
                st.session_state.df_scout = pd.DataFrame(res_data)
                st.session_state.target_scout_actual = target

                # 2. Guardado en historial MySQL
                hay_riesgo = (
                    1 if (st.session_state.df_scout["Estado"] == "❌").any() else 0
                )
                guardar_historial("Scout", target, hay_riesgo)
                st.toast(f"Análisis de {target} registrado.")

            except Exception as e:
                st.error(f"Fallo de conexión o protocolo: {e}")

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_scout" in st.session_state:
        df_h = st.session_state.df_scout
        t_scout = st.session_state.target_scout_actual

        # 1. Visualización de Resultados
        if (df_h["Estado"] == "❌").any():
            st.error(f"🚨 Se detectaron cabeceras ausentes en {t_scout}.")
        else:
            st.success(
                f"✅ La infraestructura de {t_scout} presenta una postura defensiva robusta."
            )

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Robustez con IA"):
                with st.spinner("EVA evaluando vectores de ataque web..."):
                    contexto_sc = f"Auditoría de Headers de Seguridad en {t_scout}"
                    datos_sc = df_h.to_string()
                    st.session_state.ver_scout_eva = consultar_ia_tactica(
                        contexto_sc, datos_sc
                    )

            if "ver_scout_eva" in st.session_state:
                st.info(st.session_state.ver_scout_eva)
                pdf_ia_sc = generar_pdf_ia(
                    f"Scout Intelligence Report - {t_scout}",
                    st.session_state.ver_scout_eva,
                )
                st.download_button(
                    "📥 Descargar Informe IA (PDF)",
                    pdf_ia_sc,
                    f"IA_Scout_{t_scout}.pdf",
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Recomendaciones Técnicas")
        st.table(df_h)  # Tabla antes del PDF técnico

        remediacion_texto = ""
        headers_faltantes = df_h[df_h["Estado"] == "❌"]["Header"]

        if len(headers_faltantes) > 0:
            for h in headers_faltantes:
                info_sql = consultar_repositorio(h)
                msg_sql = (
                    info_sql["formato_md"] if isinstance(info_sql, dict) else info_sql
                )
                if "Remediacion en proceso" not in msg_sql:
                    st.warning(f"Asunto: {h}\n\n{msg_sql}")
                    remediacion_texto += (
                        msg_sql.replace("#", "").replace("*", "")
                        + "\n"
                        + "-" * 30
                        + "\n"
                    )
        else:
            remediacion_texto = "Estatus: Seguro. La infraestructura cumple con los estándares de Hardening de cabeceras HTTP."

        # Reporte Técnico Final
        pdf_data_sc = create_pdf("Scout", t_scout, df_h, remediacion=remediacion_texto)
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_data_sc,
            file_name=f"SH_Scout_{t_scout}.pdf",
            mime="application/pdf",
        )


# --- CONTROL Cookie Auditor ---
elif menu == "Cookie Auditor":
    st.header("🍪 Cookie Auditor con Remediación")
    st.write(
        "Análisis de atributos de persistencia y seguridad en cookies de sesión (HttpOnly, Secure, SameSite)."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Auditor de Cookies"):
        for key in ["df_cookies", "target_cookies_actual", "ver_cookies_eva"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    target = st.text_input("Ingresá el dominio a auditar:", value="google.com")

    if st.button("🚀 Auditar Cookies"):
        with st.spinner(f"Capturando y analizando galletas de {target}..."):
            # 1. Ejecución del motor técnico (def)
            res_cookies = audit_cookies(target)

            if isinstance(res_cookies, pd.DataFrame):
                st.session_state.df_cookies = res_cookies
                st.session_state.target_cookies_actual = target

                # 2. Guardamos historial en MySQL
                hay_riesgo = (
                    1
                    if (res_cookies["HttpOnly"] == "❌ RIESGO").any()
                    or (res_cookies["Secure"] == "❌ RIESGO").any()
                    else 0
                )
                guardar_historial("Cookie Auditor", target, hay_riesgo)
                st.toast("Auditoría de sesión registrada en la DB.")
            else:
                st.error(f"Error en la captura: {res_cookies}")

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_cookies" in st.session_state:
        df = st.session_state.df_cookies
        t_cookies = st.session_state.target_cookies_actual

        # 1. Visualización de Datos
        if (df["HttpOnly"] == "❌ RIESGO").any() or (df["Secure"] == "❌ RIESGO").any():
            st.error(f"🚨 Se detectaron cookies vulnerables en {t_cookies}.")
        else:
            st.success(
                f"✅ Las cookies de {t_cookies} cumplen con los estándares de seguridad."
            )

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Peligrosidad de Sesión"):
                with st.spinner("EVA evaluando vectores de Session Hijacking..."):
                    contexto_ck = f"Auditoría de Cookies de Sesión en {t_cookies}"
                    # EVA analiza incluso si están bien configuradas
                    datos_ck = (
                        df.to_string()
                        if not df.empty
                        else "Resultado: Sin cookies detectadas o perímetro blindado."
                    )
                    st.session_state.ver_cookies_eva = consultar_ia_tactica(
                        contexto_ck, datos_ck
                    )

            if "ver_cookies_eva" in st.session_state:
                st.info(st.session_state.ver_cookies_eva)
                pdf_ia_ck = generar_pdf_ia(
                    f"Cookie Intelligence Report - {t_cookies}",
                    st.session_state.ver_cookies_eva,
                )
                st.download_button(
                    "📥 Descargar Informe IA (PDF)",
                    pdf_ia_ck,
                    f"IA_Cookies_{t_cookies}.pdf",
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Plan de Remediación (SQL)")
        st.table(df)  # Tabla técnica antes del PDF

        remediacion_texto = ""

        # Lógica de remediación basada en el repositorio
        if (df["HttpOnly"] == "❌ RIESGO").any():
            info_h = consultar_repositorio("HttpOnly")
            msg_h = info_sql = (
                info_h["formato_md"] if isinstance(info_h, dict) else info_h
            )
            st.warning(f"Asunto: HttpOnly\n\n{msg_h}")
            remediacion_texto += (
                "Hallazgo: HttpOnly Ausente\n"
                + msg_h.replace("#", "").replace("*", "")
                + "\n"
            )

        if (df["Secure"] == "❌ RIESGO").any():
            info_s = consultar_repositorio("Secure")
            msg_s = info_s["formato_md"] if isinstance(info_s, dict) else info_s
            st.warning(f"Asunto: Secure\n\n{msg_s}")
            remediacion_texto += (
                "\nHallazgo: Secure Ausente\n"
                + msg_s.replace("#", "").replace("*", "")
                + "\n"
            )

        if remediacion_texto == "":
            remediacion_texto = "Estatus: Seguro. Las directivas de sesión (HttpOnly/Secure) están correctamente implementadas."

        # Botón Reporte Técnico Final
        pdf_data_ck = create_pdf(
            "Cookie Auditor", t_cookies, df, remediacion=remediacion_texto
        )
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_data_ck,
            file_name=f"SH_Audit_Cookies_{t_cookies}.pdf",
            mime="application/pdf",
        )


# --- CONTROL Cazador de Subdominios ---
elif menu == "Subdomain Hunter":
    st.header("🎯 OSINT - Subdomain Hunter")
    st.write(
        "Identificación de infraestructura expuesta mediante enumeración de certificados (OSINT) y fuerza bruta DNS."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Hunter"):
        for key in ["df_sub_hunter", "target_sub_actual", "ver_sub_eva"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    t_sub = st.text_input("Dominio Raíz (ej: empresa.com):", value="nmap.org")

    col1, col2 = st.columns(2)
    with col1:
        btn_osint = st.button("🔍 Buscar en Base de Datos (OSINT)")
    with col2:
        btn_brute = st.button("⚔️ Escaneo de Precisión (Brute Force)")

    # --- LÓGICA DE EJECUCIÓN ---
    if btn_osint:
        with st.spinner(
            "Consultando base de datos pública de certificados (crt.sh)..."
        ):
            try:
                res_raw = requests.get(
                    "https://crt.sh",
                    params={"q": f"%.{t_sub}", "output": "json"},
                    timeout=15,
                )
                if res_raw.status_code == 200:
                    data = res_raw.json()
                    subs_list = sorted(
                        {
                            e["name_value"].lower().replace("*.", "")
                            for e in data
                            if e["name_value"].endswith(t_sub)
                        }
                    )
                    st.session_state.df_sub_hunter = pd.DataFrame(
                        {"Subdominio": subs_list, "Fuente": "OSINT / SSL Certs"}
                    )
                    st.session_state.target_sub_actual = t_sub
                    guardar_historial("Subdomain Hunter (OSINT)", t_sub, 0)
                else:
                    st.error("Servidor OSINT saturado. Usá el Escaneo de Precisión.")
            except:
                st.error("⚠️ Enlace OSINT fallido. Probá el 'Escaneo de Precisión'.")

    if btn_brute:
        with st.spinner(f"Probando subdominios críticos en {t_sub}..."):
            encontrados = []
            for sub in COMMON_SUBS:
                full_url = f"{sub}.{t_sub}"
                try:
                    ip = socket.gethostbyname(full_url)
                    encontrados.append(
                        {
                            "Subdominio": full_url,
                            "IP": ip,
                            "Fuente": "Brute Force (Activo)",
                        }
                    )
                except:
                    continue

            st.session_state.df_sub_hunter = pd.DataFrame(encontrados)
            st.session_state.target_sub_actual = t_sub
            guardar_historial(
                "Subdomain Hunter (Brute)", t_sub, 1 if encontrados else 0
            )

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_sub_hunter" in st.session_state:
        df = st.session_state.df_sub_hunter
        t_actual = st.session_state.target_sub_actual

        if not df.empty:
            st.warning(
                f"🚨 Se detectaron {len(df)} subdominios asociados a {t_actual}."
            )
        else:
            st.success(f"✅ No se detectaron subdominios comunes para {t_actual}.")

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Superficie de Ataque"):
                with st.spinner("EVA evaluando la arquitectura expuesta..."):
                    contexto_sh = f"Enumeración de Subdominios para {t_actual}"
                    # EVA analiza incluso si el resultado es magro (Analiza el sigilo)
                    datos_sh = (
                        df.to_string()
                        if not df.empty
                        else "Resultado: Sin subdominios detectados en pruebas estándar."
                    )
                    st.session_state.ver_sub_eva = consultar_ia_tactica(
                        contexto_sh, datos_sh
                    )

            if "ver_sub_eva" in st.session_state:
                st.info(st.session_state.ver_sub_eva)
                pdf_ia_sh = generar_pdf_ia(
                    f"OSINT Intelligence Report - {t_actual}",
                    st.session_state.ver_sub_eva,
                )
                st.download_button(
                    "📥 Descargar Informe IA (PDF)",
                    pdf_ia_sh,
                    f"IA_Subdomains_{t_actual}.pdf",
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN
        st.subheader("🛠️ Resultados y Recomendaciones Técnicas")
        st.table(df)  # Tabla técnica antes del PDF

        if not df.empty:
            remed_sh = "- Riesgo: Subdominios activos detectados mediante enumeración directa.\n- Solución: Implementar técnicas de DNS Split-Horizon para ocultar registros internos y monitorear certificados SSL públicos."
            st.error(remed_sh)
        else:
            remed_sh = "Estatus: Seguro. La superficie de exposición pública es mínima."
            st.success(remed_sh)

        # Reporte Técnico Final
        pdf_data_sh = create_pdf("Subdomain Hunter", t_actual, df, remediacion=remed_sh)
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_data_sh,
            file_name=f"SH_Hunter_{t_actual}.pdf",
            mime="application/pdf",
        )


# --- CONTROL Watchtower (SSL/DNS) ---
elif menu == "Watchtower (SSL/DNS)":
    st.header("🔭 The Watchtower - Vigilancia de Activos")
    st.write(
        "Análisis de registros WHOIS y ciclo de vida de dominios para prevención de secuestro (Domain Hijacking)."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Watchtower"):
        for key in ["df_watch", "target_watch", "veredicto_eva_w"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    t = st.text_input("Dominio a vigilar:", value="google.com")

    if st.button("🚀 Verificar Salud del Activo"):
        with st.spinner("Consultando registros internacionales (WHOIS)..."):
            try:
                # 1. Ejecución técnica
                w = whois.whois(t)
                df_w = pd.DataFrame(
                    [
                        {"Atributo": "Registrador", "Valor": str(w.registrar)},
                        {"Atributo": "Creación", "Valor": str(w.creation_date)},
                        {"Atributo": "Expiración", "Valor": str(w.expiration_date)},
                        {
                            "Atributo": "DNS",
                            "Valor": str(w.name_servers if w.name_servers else "N/A"),
                        },
                    ]
                )

                # Persistencia en sesión
                st.session_state.df_watch = df_w
                st.session_state.target_watch = t

                # 2. Guardado en historial MySQL
                guardar_historial("Watchtower", t, 0)
                st.toast(f"Vigilancia de {t} registrada.")

            except Exception as e:
                st.error(f"Error en el peritaje de propiedad: {e}")

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_watch" in st.session_state:
        df_w = st.session_state.df_watch
        t_w = st.session_state.target_watch

        # Visualización rápida de datos
        col_w1, col_w2 = st.columns(2)
        with col_w1:
            st.write(f"**Registrador:** {df_w.iloc[0]['Valor']}")
            st.write(f"**Servidores DNS:** {df_w.iloc[3]['Valor']}")
        with col_w2:
            st.write(f"**Creación:** {df_w.iloc[1]['Valor']}")
            st.write(f"**Expiración:** {df_w.iloc[2]['Valor']}")

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Propiedad y Riesgo"):
                with st.spinner("EVA evaluando el ciclo de vida del dominio..."):
                    contexto_w = f"Análisis WHOIS y Propiedad para {t_w}"
                    # EVA analiza incluso si el dominio es estable para certificar seguridad
                    datos_w = df_w.to_string()
                    st.session_state.veredicto_eva_w = consultar_ia_tactica(
                        contexto_w, datos_w
                    )

            if "veredicto_eva_w" in st.session_state:
                st.info(st.session_state.veredicto_eva_w)
                pdf_ia_w = generar_pdf_ia(
                    f"Watchtower Intelligence Report - {t_w}",
                    st.session_state.veredicto_eva_w,
                )
                st.download_button(
                    "📥 Descargar Informe IA (PDF)",
                    pdf_ia_w,
                    f"IA_Watchtower_{t_w}.pdf",
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Doctrina de Gestión (SQL)")
        st.table(df_w)  # Tabla técnica antes del PDF

        info_sql = consultar_repositorio("Gestion de Dominios")
        msg_sql = info_sql["formato_md"] if isinstance(info_sql, dict) else info_sql

        st.info(msg_sql)
        remediacion_final = msg_sql.replace("#", "").replace("*", "")

        # Reporte Técnico Final
        pdf_data_w = create_pdf("Watchtower", t_w, df_w, remediacion=remediacion_final)
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_data_w,
            file_name=f"SH_Watchtower_{t_w}.pdf",
            mime="application/pdf",
        )


# --- CONTROL IPS Local ---
elif menu == "IPS Local":
    st.header("🛡️ Guardian IPS - Seguridad de Endpoint")
    st.write(
        "Análisis de procesos activos en el sistema local para detección de anomalías, malware y persistencia."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Escáner IPS"):
        for key in ["df_ips_local", "veredicto_eva_ips"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    if st.button("🚀 Escanear Procesos del Sistema"):
        with st.spinner("Analizando hilos de ejecución y memoria en tiempo real..."):
            # 1. Recolección técnica de procesos
            procesos = []
            for p in psutil.process_iter(["pid", "name", "username"]):
                try:
                    procesos.append(
                        {
                            "PID": p.info["pid"],
                            "Nombre": p.info["name"],
                            "Usuario": p.info["username"],
                        }
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            df_proc = pd.DataFrame(procesos)
            st.session_state.df_ips_local = df_proc
            guardar_historial("IPS Local", "Host-Local", 0)
            st.toast("Inventario de procesos locales registrado.")

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_ips_local" in st.session_state:
        df = st.session_state.df_ips_local

        st.success(f"🔍 Auditoría completada: {len(df)} procesos identificados.")
        st.dataframe(df, use_container_width=True)

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL Y ESPAÑOL FORZADO)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Integridad de Procesos"):
                with st.spinner("EVA analizando hilos de ejecución..."):
                    contexto_ips = "Auditoría de Procesos en Host Local"
                    datos_ips = df.head(50).to_string()

                    # --- PARCHE DE IDIOMA TÁCTICO ---
                    prompt_es = (
                        "Analizá la siguiente lista de procesos del sistema. "
                        "Dame tu veredicto de seguridad EXCLUSIVAMENTE EN ESPAÑOL. "
                        "Buscá procesos sospechosos o falta de firmas: \n\n" + datos_ips
                    )

                    st.session_state.veredicto_eva_ips = consultar_ia_tactica(
                        contexto_ips, prompt_es
                    )

            if "veredicto_eva_ips" in st.session_state:
                st.info(st.session_state.veredicto_eva_ips)
                pdf_ia_ips = generar_pdf_ia(
                    "Endpoint Intelligence Report", st.session_state.veredicto_eva_ips
                )
                st.download_button(
                    "📥 Descargar Informe IA (PDF)", pdf_ia_ips, "IA_IPS_Local.pdf"
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Postura de Seguridad (SQL)")
        info_sql = consultar_repositorio("Procesos Sistema")
        msg_sql = info_sql["formato_md"] if isinstance(info_sql, dict) else info_sql
        st.info(msg_sql)

        remediacion_ips = (
            "Estatus: Verificado. Análisis de integridad completado. "
            + msg_sql.replace("#", "").replace("*", "")
        )

        pdf_ips = create_pdf("IPS Local", "Host-Local", df, remediacion=remediacion_ips)
        st.download_button(
            label="📥 Descargar Auditoría Técnica de Endpoint",
            data=pdf_ips,
            file_name="SH_IPS_Local_Report.pdf",
            mime="application/pdf",
        )


# --- CONTROL External Sentinel IPS ---
elif menu == "External Sentinel IPS":
    st.header("🛰️ Monitoreo de Amenazas Externas")
    st.write(
        "Análisis de latencia y disponibilidad de activos remotos para detección de saturación y ataques DoS."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Monitoreo Externo"):
        for key in ["df_ext_ips", "latencia_ext", "target_ext_actual", "ver_eva_ext"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    target_ext = st.text_input("Dominio a vigilar:", value="google.com")

    if st.button("🚀 Iniciar Vigilancia Táctica"):
        with st.spinner(f"Analizando pulso de {target_ext}..."):
            start_time = datetime.now()
            try:
                # 1. Ejecución técnica y latencia
                ip_ext = socket.gethostbyname(target_ext)
                socket.create_connection((ip_ext, 80), timeout=3)
                end_time = datetime.now()
                lat = (end_time - start_time).total_seconds() * 1000

                # Estructura para persistencia
                df_ext = pd.DataFrame(
                    [
                        {"Métrica": "IP Actual", "Valor": ip_ext},
                        {"Métrica": "Latencia", "Valor": f"{lat:.2f} ms"},
                        {
                            "Métrica": "Estado",
                            "Valor": "Estable" if lat < 500 else "Degradado",
                        },
                    ]
                )

                st.session_state.df_ext_ips = df_ext
                st.session_state.latencia_ext = lat
                st.session_state.target_ext_actual = target_ext

                # 3. Guardado en historial MySQL
                riesgo_ext = 1 if lat > 500 else 0
                guardar_historial("External IPS", target_ext, riesgo_ext)
                st.toast(f"Métricas de {target_ext} registradas.")

            except Exception as e:
                st.error(f"Falla de pulso: El servidor no responde. {e}")

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_ext_ips" in st.session_state:
        df = st.session_state.df_ext_ips
        lat = st.session_state.latencia_ext
        t_ext = st.session_state.target_ext_actual

        # KPIs Visuales
        col1, col2 = st.columns(2)
        col1.metric("IP de Destino", df.iloc[0]["Valor"])
        if lat > 500:
            col2.metric(
                "Latencia", f"{lat:.0f} ms", delta="⚠️ CRÍTICO", delta_color="inverse"
            )
        else:
            col2.metric("Latencia", f"{lat:.0f} ms", delta="✅ ESTABLE")

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Salud de Red"):
                with st.spinner("EVA evaluando vectores de saturación..."):
                    contexto_ext = f"Monitoreo de Pulso Externo para {t_ext}"
                    # EVA analiza tanto el colapso como la fluidez
                    datos_ext = f"Latencia: {lat:.2f} ms. Datos: {df.to_string()}"
                    st.session_state.ver_eva_ext = consultar_ia_tactica(
                        contexto_ext, datos_ext
                    )

            if "ver_eva_ext" in st.session_state:
                st.info(st.session_state.ver_eva_ext)
                pdf_ia_ext = generar_pdf_ia(
                    f"External IPS Report - {t_ext}", st.session_state.ver_eva_ext
                )
                st.download_button(
                    "📥 Descargar Informe IA (PDF)",
                    pdf_ia_ext,
                    f"IA_External_IPS_{t_ext}.pdf",
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Plan de Contingencia (SQL)")
        st.table(df)  # Tabla antes del PDF

        if lat > 500:
            info_sql = consultar_repositorio("DDoS Detectado")
            msg_sql = info_sql["formato_md"] if isinstance(info_sql, dict) else info_sql
            st.error(msg_sql)
            remed_ext = "HALLAZGO: Latencia crítica detectada. " + msg_sql.replace(
                "#", ""
            ).replace("*", "")
        else:
            st.success("✅ Operación Normal: La respuesta del servidor es óptima.")
            remed_ext = "Estatus: Seguro. El activo responde dentro de los parámetros esperados."

        # Reporte Técnico Final
        pdf_ext = create_pdf("External IPS", t_ext, df, remediacion=remed_ext)
        st.download_button(
            label="📥 Descargar Reporte de Vigilancia Técnica",
            data=pdf_ext,
            file_name=f"SH_Ext_IPS_{t_ext}.pdf",
            mime="application/pdf",
        )


# --- CONTROL Scanner de Vulnerabilidad ---
elif menu == "Vulnerability Scanner":
    st.header("🧪 Vulnerability Scanner - Detección de Inyecciones")
    st.write(
        "Análisis de vectores de ataque mediante inyección de payloads para detectar SQL Injection y Cross-Site Scripting (XSS)."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Scanner"):
        for key in ["df_vuln", "target_vuln_actual", "ver_eva_v"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    target_vuln = st.text_input(
        "URL a testear (ej: ://empresa.com):", value="http://testphp.vulnweb.com"
    )

    if st.button("🚀 Lanzar Escaneo de Vulnerabilidades"):
        with st.spinner("Ejecutando ráfaga de payloads y analizando respuestas..."):
            # 1. Ejecución del motor técnico
            df_res = check_vulnerability(target_vuln)

            if isinstance(df_res, pd.DataFrame):
                # Persistencia en session_state
                st.session_state.df_vuln = df_res
                st.session_state.target_vuln_actual = target_vuln

                # 2. Guardado en historial MySQL
                hay_vulnerabilidad = (
                    1 if (df_res["Estado"] == "❌ VULNERABLE").any() else 0
                )
                guardar_historial(
                    "Vulnerability Scanner", target_vuln, hay_vulnerabilidad
                )
                st.toast(f"Hallazgos en {target_vuln} registrados en la DB.")
            else:
                st.error(f"Error en el motor: {df_res}")

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_vuln" in st.session_state:
        df_v = st.session_state.df_vuln
        t_vuln = st.session_state.target_vuln_actual

        # 1. Visualización de Resultados
        if (df_v["Estado"] == "❌ VULNERABLE").any():
            st.error(f"🚨 Se detectaron vectores de inyección activos en {t_vuln}.")
        else:
            st.success(
                f"✅ No se detectaron inyecciones básicas. El perímetro parece sanitizado."
            )

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Impacto de Inyección"):
                with st.spinner("EVA evaluando riesgos de exfiltración y sesión..."):
                    contexto_v = f"Escaneo de Vulnerabilidades en {t_vuln}"
                    # EVA analiza tanto la vulnerabilidad como la sanitización exitosa
                    datos_ia = (
                        df_v.to_string()
                        if not df_v.empty
                        else "Resultado: Sanitización correcta detectada."
                    )
                    st.session_state.ver_eva_v = consultar_ia_tactica(
                        contexto_v, datos_ia
                    )

            if "ver_eva_v" in st.session_state:
                st.info(st.session_state.ver_eva_v)
                pdf_ia_v = generar_pdf_ia(
                    f"Vulnerability Intel Report - {t_vuln}", st.session_state.ver_eva_v
                )
                st.download_button(
                    "📥 Descargar Informe IA (PDF)", pdf_ia_v, f"IA_Vuln_{t_vuln}.pdf"
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Remediación Técnica (SQL)")
        st.table(df_v)  # Tabla técnica antes del PDF

        remediacion_vuln = ""
        vulnerabilidades = df_v[df_v["Estado"] == "❌ VULNERABLE"]

        if not vulnerabilidades.empty:
            for index, row in vulnerabilidades.iterrows():
                tipo = row["Tipo"]
                info_sql = consultar_repositorio(tipo)
                msg_sql = (
                    info_sql["formato_md"] if isinstance(info_sql, dict) else info_sql
                )

                st.error(f"HALLAZGO CRÍTICO: {tipo}")
                st.markdown(msg_sql)
                remediacion_vuln += (
                    msg_sql.replace("#", "").replace("*", "") + "\n" + "-" * 30 + "\n"
                )
        else:
            msg_ok = "Estatus: Seguro. El servidor sanitiza correctamente los caracteres especiales."
            st.success(msg_ok)
            remediacion_vuln = msg_ok

        # Reporte Técnico Final
        pdf_v = create_pdf(
            "Vulnerability Scanner", t_vuln, df_v, remediacion=remediacion_vuln
        )
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_v,
            file_name=f"SH_Vuln_{t_vuln}.pdf",
            mime="application/pdf",
        )


# --- CONTROL Scanner LFI ---
elif menu == "LFI Scanner":
    st.header("📂 LFI & Directory Traversal Scanner")
    st.write(
        "Detección de vulnerabilidades de inclusión de archivos locales en parámetros de URL."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Scanner LFI"):
        for key in ["df_lfi", "target_lfi_actual", "veredicto_eva_l"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    target_lfi = st.text_input(
        "URL con parámetro (ej: ://site.com):", value="http://testphp.vulnweb.com"
    )

    if st.button("🚀 Lanzar Escaneo de Archivos"):
        with st.spinner("Inyectando payloads de Directory Traversal..."):
            # 1. Ejecución del motor técnico
            df_res = scan_lfi(target_lfi)

            if not df_res.empty:
                # Persistencia en session_state
                st.session_state.df_lfi = df_res
                st.session_state.target_lfi_actual = target_lfi

                # 2. Guardado en historial MySQL
                hay_lfi = 1 if (df_res["Estado"] == "❌ VULNERABLE").any() else 0
                guardar_historial("LFI Scanner", target_lfi, hay_lfi)
                st.toast("Análisis LFI registrado en el historial.")
            else:
                st.info(
                    "No se pudieron testear los parámetros. Verificá la URL o los permisos del servidor."
                )

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_lfi" in st.session_state:
        df_l = st.session_state.df_lfi
        t_lfi = st.session_state.target_lfi_actual

        # 1. Visualización de Resultados
        if (df_l["Estado"] == "❌ VULNERABLE").any():
            st.error(f"🚨 CRÍTICO: Vulnerabilidad LFI detectada en {t_lfi}.")
        else:
            st.success(
                f"✅ Postura Robusta: No se detectaron patrones de Directory Traversal."
            )

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Fugas de Información"):
                with st.spinner("EVA evaluando el acceso al sistema de archivos..."):
                    contexto_l = f"Escaneo de Directory Traversal (LFI) en {t_lfi}"
                    # EVA analiza tanto el compromiso como el blindaje
                    datos_ia = (
                        df_l.to_string()
                        if not df_l.empty
                        else "Resultado: Blindaje de rutas correcto."
                    )
                    st.session_state.veredicto_eva_l = consultar_ia_tactica(
                        contexto_l, datos_ia
                    )

            if "veredicto_eva_l" in st.session_state:
                st.info(st.session_state.veredicto_eva_l)
                pdf_ia_l = generar_pdf_ia(
                    f"LFI Intelligence Report - {t_lfi}",
                    st.session_state.veredicto_eva_l,
                )
                st.download_button(
                    "📥 Descargar Informe IA (PDF)",
                    pdf_ia_l,
                    f"IA_LFI_{t_lfi.split('//')[-1]}.pdf",
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Remediación Técnica (SQL)")
        st.table(df_l)  # Tabla técnica antes del PDF

        info_db = consultar_repositorio("LFI")
        msg_sql = info_db["formato_md"] if isinstance(info_db, dict) else info_db

        if (df_l["Estado"] == "❌ VULNERABLE").any():
            st.error(msg_sql)
            remediacion_lfi = (
                "HALLAZGO CRÍTICO: Acceso no autorizado a archivos internos.\n"
                + msg_sql.replace("#", "").replace("*", "")
            )
        else:
            st.success(
                "✅ Estatus: Seguro. El servidor bloquea correctamente el acceso a rutas relativas."
            )
            remediacion_lfi = "Se recomienda mantener la política de 'Open_basedir' y permisos de lectura restringidos."

        # Reporte Técnico Final
        pdf_lfi = create_pdf("LFI Scanner", t_lfi, df_l, remediacion=remediacion_lfi)
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_lfi,
            file_name=f"SH_LFI_{t_lfi.split('//')[-1]}.pdf",
            mime="application/pdf",
        )


# --- CONTROL Host Header Auditor ---
elif menu == "Host Header Auditor":
    st.header("💉 Host Header Injection (HHI) Scanner")
    st.write(
        "Auditoría de confianza en el encabezado Host para prevenir envenenamiento de caché y redirecciones."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Auditor HHI"):
        for key in ["df_hhi", "target_hhi_actual", "veredicto_eva_h"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    target_hhi = st.text_input("Dominio a testear:", value="google.com")

    if st.button("🚀 Lanzar Auditoría de Cabeceras"):
        with st.spinner(
            "Inyectando cabeceras de host maliciosas y analizando respuesta..."
        ):
            # 1. Ejecución del motor técnico
            df_res = scan_hhi(target_hhi)

            if isinstance(df_res, pd.DataFrame):
                # Persistencia en session_state
                st.session_state.df_hhi = df_res
                st.session_state.target_hhi_actual = target_hhi

                # 2. Guardado en historial MySQL
                hay_hhi = 1 if (df_res["Estado"] == "❌ VULNERABLE").any() else 0
                guardar_historial("HHI Scanner", target_hhi, hay_hhi)
                st.toast(f"Resultado HHI para {target_hhi} registrado.")
            else:
                st.error(f"Error en el motor HHI: {df_res}")

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_hhi" in st.session_state:
        df_h = st.session_state.df_hhi
        t_hhi = st.session_state.target_hhi_actual

        # 1. Visualización de Resultados
        if (df_h["Estado"] == "❌ VULNERABLE").any():
            st.error(f"🚨 Peligro: El servidor en {t_hhi} es vulnerable a HHI.")
        else:
            st.success(
                f"✅ Postura Robusta: El servidor valida correctamente el encabezado Host."
            )

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Vectores de Envenenamiento"):
                with st.spinner(
                    "EVA evaluando persistencia de caché y redirecciones..."
                ):
                    contexto_h = f"Auditoría de Host Header Injection en {t_hhi}"
                    # EVA analiza tanto el fallo como el blindaje
                    datos_ia = (
                        df_h.to_string()
                        if not df_h.empty
                        else "Resultado: El servidor rechaza hosts externos."
                    )
                    st.session_state.veredicto_eva_h = consultar_ia_tactica(
                        contexto_h, datos_ia
                    )

            if "veredicto_eva_h" in st.session_state:
                st.info(st.session_state.veredicto_eva_h)
                pdf_ia_h = generar_pdf_ia(
                    f"HHI Intelligence Report - {t_hhi}",
                    st.session_state.veredicto_eva_h,
                )
                st.download_button(
                    "📥 Descargar Informe IA (PDF)", pdf_ia_h, f"IA_HHI_{t_hhi}.pdf"
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Remediación Táctica (SQL)")
        st.table(df_h)  # Tabla técnica antes del PDF

        info_db = consultar_repositorio("HHI")
        msg_sql = info_db["formato_md"] if isinstance(info_db, dict) else info_db

        if (df_h["Estado"] == "❌ VULNERABLE").any():
            st.error(msg_sql)
            remediacion_hhi = (
                "HALLAZGO CRÍTICO: Vulnerabilidad a inyección de cabecera Host.\n"
                + msg_sql.replace("#", "").replace("*", "")
            )
        else:
            st.success(
                "✅ Estatus: Seguro. El servidor ignora o bloquea hosts no autorizados."
            )
            remediacion_hhi = "Se recomienda mantener la validación estricta de dominios en la configuración del servidor web."

        # Reporte Técnico Final
        pdf_hhi = create_pdf("HHI Scanner", t_hhi, df_h, remediacion=remediacion_hhi)
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_hhi,
            file_name=f"SH_HHI_{t_hhi}.pdf",
            mime="application/pdf",
        )


# --- CONTROL Subdomain Takeover ---
elif menu == "Subdomain Takeover":
    st.header("🔗 Subdomain Takeover (STO) Auditor")
    st.write(
        "Detección de subdominios 'huérfanos' que apuntan a servicios en la nube inactivos o mal configurados."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Auditor STO"):
        for key in ["df_sto", "target_sto_actual", "veredicto_eva_sto"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    target_sto = st.text_input("Subdominio o Dominio a testear:", value="google.com")

    if st.button("🚀 Analizar Registros DNS"):
        with st.spinner("Rastreando registros CNAME y validando firmas de abandono..."):
            # 1. Ejecución del motor técnico (def)
            df_res = scan_sto(target_sto)

            if not df_res.empty:
                # Persistencia en session_state
                st.session_state.df_sto = df_res
                st.session_state.target_sto_actual = target_sto

                # 2. Guardado en historial MySQL
                hay_sto = 1 if (df_res["Estado"] == "❌ VULNERABLE").any() else 0
                guardar_historial("STO Scanner", target_sto, hay_sto)
                st.toast(f"Análisis STO de {target_sto} registrado.")
            else:
                st.info("No se hallaron registros CNAME para analizar en este nivel.")

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_sto" in st.session_state:
        df_s = st.session_state.df_sto
        t_sto = st.session_state.target_sto_actual

        # 1. Visualización de Resultados
        if (df_s["Estado"] == "❌ VULNERABLE").any():
            st.error(
                f"🚨 PELIGRO: Se detectaron vectores de Subdomain Takeover en {t_sto}."
            )
        else:
            st.success(
                f"✅ Postura Robusta: No se detectaron registros huérfanos en {t_sto}."
            )

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Riesgo de Suplantación"):
                with st.spinner(
                    "EVA evaluando persistencia de DNS y servicios huérfanos..."
                ):
                    contexto_sto = f"Auditoría de Subdomain Takeover en {t_sto}"
                    # EVA analiza incluso la ausencia de vulnerabilidad para certificar orden
                    datos_ia = (
                        df_s.to_string()
                        if not df_s.empty
                        else "Resultado: Registros DNS limpios y vigentes."
                    )
                    st.session_state.veredicto_eva_sto = consultar_ia_tactica(
                        contexto_sto, datos_ia
                    )

            if "veredicto_eva_sto" in st.session_state:
                st.info(st.session_state.veredicto_eva_sto)
                pdf_ia_sto = generar_pdf_ia(
                    f"STO Intelligence Report - {t_sto}",
                    st.session_state.veredicto_eva_sto,
                )
                st.download_button(
                    "📥 Descargar Informe IA (PDF)", pdf_ia_sto, f"IA_STO_{t_sto}.pdf"
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Remediación Táctica (SQL)")
        st.table(df_s)  # Tabla técnica antes del PDF

        info_db = consultar_repositorio("STO")
        msg_sql = info_db["formato_md"] if isinstance(info_db, dict) else info_db

        if (df_s["Estado"] == "❌ VULNERABLE").any():
            st.warning(msg_sql)
            remed_sto = (
                "HALLAZGO CRÍTICO: Registro CNAME huérfano detectado.\n"
                + msg_sql.replace("#", "").replace("*", "")
            )
        else:
            st.success(
                "✅ Estatus: Seguro. Los registros DNS apuntan a servicios activos y controlados."
            )
            remed_sto = "No se requiere acción inmediata. Se recomienda limpieza periódica de registros DNS en desuso."

        # Reporte Técnico Final
        pdf_sto = create_pdf("STO Scanner", t_sto, df_s, remediacion=remed_sto)
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_sto,
            file_name=f"SH_STO_{t_sto}.pdf",
            mime="application/pdf",
        )


# --- CONTROL Header Injection ---
elif menu == "Header Injection":
    st.header("💉 Header Injection Advanced Scanner")
    st.write(
        "Detección de vulnerabilidades de inyección de caracteres de control (CRLF) en cabeceras HTTP."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Auditor HI"):
        for key in ["df_hi", "target_hi_actual", "veredicto_eva_hi"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    target_hi = st.text_input("URL a testear (ej: site.com):", value="google.com")

    if st.button("🚀 Lanzar Ataque de Inyección"):
        with st.spinner("Ejecutando payloads CRLF y analizando saltos de línea..."):
            # 1. Ejecución del motor técnico
            df_res = scan_header_injection(target_hi)

            if isinstance(df_res, pd.DataFrame):
                # Persistencia en session_state
                st.session_state.df_hi = df_res
                st.session_state.target_hi_actual = target_hi

                # 2. Guardado en historial MySQL
                hay_hi = 1 if (df_res["Estado"] == "❌ VULNERABLE").any() else 0
                guardar_historial("Header Injection", target_hi, hay_hi)
                st.toast(f"Resultado de Inyección para {target_hi} registrado en DB.")
            else:
                st.error(f"Error en el motor HI: {df_res}")

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_hi" in st.session_state:
        df_h = st.session_state.df_hi
        t_hi = st.session_state.target_hi_actual

        # 1. Visualización de Resultados
        if (df_h["Estado"] == "❌ VULNERABLE").any():
            st.error(
                f"🚨 Peligro: El servidor en {t_hi} es vulnerable a inyección CRLF."
            )
        else:
            st.success(
                f"✅ Postura Robusta: El servidor bloquea correctamente los caracteres de control."
            )

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Estructura HTTP"):
                with st.spinner("EVA evaluando vectores de Response Splitting..."):
                    contexto_hi = f"Auditoría de CRLF / Header Injection en {t_hi}"
                    # EVA analiza tanto el éxito defensivo como la vulnerabilidad
                    datos_ia = (
                        df_h.to_string()
                        if not df_h.empty
                        else "Resultado: Sanitización CRLF correcta."
                    )
                    st.session_state.veredicto_eva_hi = consultar_ia_tactica(
                        contexto_hi, datos_ia
                    )

            if "veredicto_eva_hi" in st.session_state:
                st.info(st.session_state.veredicto_eva_hi)
                pdf_ia_hi = generar_pdf_ia(
                    f"HI Intelligence Report - {t_hi}",
                    st.session_state.veredicto_eva_hi,
                )
                st.download_button(
                    "📥 Descargar Informe IA (PDF)", pdf_ia_hi, f"IA_HI_{t_hi}.pdf"
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Remediación Táctica (SQL)")
        st.table(df_h)  # Tabla técnica antes del PDF

        info_db = consultar_repositorio("Header Injection")
        msg_sql = info_db["formato_md"] if isinstance(info_db, dict) else info_db

        if (df_h["Estado"] == "❌ VULNERABLE").any():
            st.error(msg_sql)
            remediacion_hi = (
                "HALLAZGO CRÍTICO: Vulnerabilidad a inyección de caracteres CRLF.\n"
                + msg_sql.replace("#", "").replace("*", "")
            )
        else:
            st.success(
                "✅ Estatus: Seguro. El servidor sanitiza correctamente las entradas para evitar inyecciones en cabeceras."
            )
            remediacion_hi = "No se requiere acción inmediata. Se recomienda mantener las librerías de servidor actualizadas."

        # Reporte Técnico Final
        pdf_hi = create_pdf("Header Injection", t_hi, df_h, remediacion=remediacion_hi)
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_hi,
            file_name=f"SH_HI_{t_hi}.pdf",
            mime="application/pdf",
        )


# --- CONTROL Reputation Scanner ---
elif menu == "Reputation Scanner":
    st.header("🌐 Global Threat Intelligence")
    st.write(
        "Verificación de reputación en listas negras (DNSBL) para detectar activos comprometidos."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Scanner"):
        for key in ["df_reputation", "target_rep_actual", "veredicto_eva_rep"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    target_rep = st.text_input("IP o Dominio a verificar:", value="google.com")

    if st.button("🚀 Consultar Reputación Mundial"):
        with st.spinner("Consultando bases de datos de amenazas y geolocalización..."):
            # 1. Ejecución del motor técnico
            df_res = scan_reputation(target_rep)

            if "Error" not in df_res.columns:
                # Persistencia en session_state
                st.session_state.df_reputation = df_res
                st.session_state.target_rep_actual = target_rep

                # 2. Guardado en historial MySQL
                hay_malicia = (
                    1 if (df_res["Estado"] == "🚨 LISTADO / MALICIOSO").any() else 0
                )
                guardar_historial("Reputation Scanner", target_rep, hay_malicia)
                st.toast("Consulta de inteligencia registrada en la DB.")
            else:
                st.error(
                    df_res["Error"].iloc[0]
                    if not df_res.empty
                    else "Fallo de conexión."
                )

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_reputation" in st.session_state:
        df_r = st.session_state.df_reputation
        t_rep = st.session_state.target_rep_actual

        # 1. Visualización Táctica Inicial
        if (df_r["Estado"] == "🚨 LISTADO / MALICIOSO").any():
            st.error(f"🚨 Peligro: El activo {t_rep} tiene reputación comprometida.")
        else:
            st.success(
                f"✅ Postura Limpia: El activo {t_rep} goza de buena reputación."
            )

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Inteligencia de Amenazas"):
                with st.spinner("EVA correlacionando geolocalización e ISP..."):
                    contexto_rep = f"Auditoría de Reputación Global para {t_rep}"
                    # EVA analiza tanto el éxito como el riesgo
                    datos_ia = (
                        df_r.to_string()
                        if not df_r.empty
                        else "Resultado: Sin reportes en listas negras."
                    )
                    st.session_state.veredicto_eva_rep = consultar_ia_tactica(
                        contexto_rep, datos_ia
                    )

            if "veredicto_eva_rep" in st.session_state:
                st.info(st.session_state.veredicto_eva_rep)
                pdf_ia_rep = generar_pdf_ia(
                    f"Threat Intelligence Report - {t_rep}",
                    st.session_state.veredicto_eva_rep,
                )
                st.download_button(
                    "📥 Descargar Informe IA (PDF)",
                    pdf_ia_rep,
                    f"IA_Reputation_{t_rep}.pdf",
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Atribución Técnica (SQL)")
        st.table(df_r)  # Tabla técnica antes del PDF

        info_db = consultar_repositorio("Reputacion IP")
        msg_sql = info_db["formato_md"] if isinstance(info_db, dict) else info_db

        if (df_r["Estado"] == "🚨 LISTADO / MALICIOSO").any():
            st.warning(msg_sql)
            remed_rep = (
                "HALLAZGO: Activo listado en bases de amenazas internacionales.\n"
                + msg_sql.replace("#", "").replace("*", "")
            )
        else:
            st.success(
                "✅ Estatus: Seguro. No se detectó actividad maliciosa vinculada a este activo."
            )
            remed_rep = "No se requiere acción inmediata. Se recomienda monitoreo pasivo de reputación."

        # Reporte Técnico Final
        pdf_rep = create_pdf("Reputation Scanner", t_rep, df_r, remediacion=remed_rep)
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_rep,
            file_name=f"SH_Reputation_{t_rep}.pdf",
            mime="application/pdf",
        )


# --- CONTROL SSL Deep Auditor ---
elif menu == "SSL Deep Auditor":
    st.header("🔐 SSL/TLS Deep Auditor")
    st.write(
        "Análisis criptográfico de certificados y protocolos de transporte seguro."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Auditor SSL"):
        for key in [
            "df_ssl_deep",
            "estado_ssl",
            "target_ssl_actual",
            "veredicto_eva_ssl",
        ]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    target_ssl = st.text_input(
        "Dominio a auditar (ej: google.com):", value="google.com"
    )

    if st.button("🚀 Lanzar Auditoría Criptográfica"):
        with st.spinner("Analizando apretón de manos SSL y fuerza de cifrado..."):
            # 1. Ejecución del motor técnico
            df_res, estado_f = scan_ssl_deep(target_ssl)

            if "Metrica" in df_res.columns:
                # Persistencia en session_state
                st.session_state.df_ssl_deep = df_res
                st.session_state.estado_ssl = estado_f
                st.session_state.target_ssl_actual = target_ssl

                # 2. Guardado en historial MySQL
                hay_riesgo = 1 if estado_f == "❌ RIESGO" else 0
                guardar_historial("SSL Auditor", target_ssl, hay_riesgo)
                st.toast("Auditoría criptográfica registrada en la DB.")
            else:
                st.error("Error en la conexión SSL. Verifique el dominio.")

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_ssl_deep" in st.session_state:
        df_s = st.session_state.df_ssl_deep
        est_s = st.session_state.estado_ssl
        t_ssl = st.session_state.target_ssl_actual

        # 1. Visualización de Postura Criptográfica
        if est_s == "❌ RIESGO":
            st.error(
                f"🚨 Alerta: Se detectó configuración débil o insegura en {t_ssl}."
            )
        else:
            st.success(
                f"✅ Postura Robusta: El cifrado de {t_ssl} cumple con los estándares actuales."
            )

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Robustez Criptográfica"):
                with st.spinner("EVA evaluando algoritmos y vulnerabilidades TLS..."):
                    contexto_ssl = f"Auditoría Profunda de Cifrado para {t_ssl}"
                    # EVA analiza tanto la excelencia como la debilidad
                    datos_ia = (
                        df_s.to_string()
                        if not df_s.empty
                        else "Resultado: Configuración SSL impecable."
                    )
                    st.session_state.veredicto_eva_ssl = consultar_ia_tactica(
                        contexto_ssl, datos_ia
                    )

            if "veredicto_eva_ssl" in st.session_state:
                st.info(st.session_state.veredicto_eva_ssl)
                pdf_ia_ssl = generar_pdf_ia(
                    f"SSL Intelligence Report - {t_ssl}",
                    st.session_state.veredicto_eva_ssl,
                )
                st.download_button(
                    "📥 Descargar Informe IA (PDF)", pdf_ia_ssl, f"IA_SSL_{t_ssl}.pdf"
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Estándares Técnicos (SQL)")
        st.table(df_s)  # Tabla técnica antes del PDF

        info_db = consultar_repositorio("SSL Critico")
        msg_sql = info_db["formato_md"] if isinstance(info_db, dict) else info_db

        if est_s == "❌ RIESGO":
            st.warning(msg_sql)
            remed_ssl = (
                "HALLAZGO: Cifrado inseguro o protocolos obsoletos detectados.\n"
                + msg_sql.replace("#", "").replace("*", "")
            )
        else:
            st.success(
                "✅ Estatus: Seguro. El certificado cuenta con una cadena de confianza válida y algoritmos modernos."
            )
            remed_ssl = (
                "Se recomienda mantener la compatibilidad exclusiva con TLS 1.2 y 1.3."
            )

        # Reporte Técnico Final
        pdf_ssl = create_pdf("SSL Auditor", t_ssl, df_s, remediacion=remed_ssl)
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_ssl,
            file_name=f"SH_SSL_{t_ssl}.pdf",
            mime="application/pdf",
        )


# --- CONTROL Pro Fuzzer ---
elif menu == "Pro Fuzzer":
    st.header("💣 Pro Fuzzer - Directory Brute Force (SQL Driven)")
    st.write(
        "Enumeración táctica de directorios ocultos utilizando diccionarios inteligentes desde MySQL."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Pro Fuzzer"):
        for key in ["df_fuzz", "target_fuzz_actual", "ver_eva_fz"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    target_fuzz = st.text_input(
        "URL Objetivo (ej: empresa.com):", value="http://testphp.vulnweb.com"
    )

    if st.button("🚀 Lanzar Ráfaga de Fuzzing"):
        with st.spinner("Consultando diccionario en DB e iniciando ataque..."):
            # 1. Ejecución del motor técnico
            df_res = pro_fuzzer_scan_db(target_fuzz)

            # Persistencia de datos en session_state
            st.session_state.df_fuzz = df_res
            st.session_state.target_fuzz_actual = target_fuzz

            # --- 🗄️ GUARDADO EN BASE DE DATOS XAMPP ---
            hay_fuzz = (
                1 if (not df_res.empty and (df_res["Codigo"] == 200).any()) else 0
            )
            guardar_historial("Pro Fuzzer", target_fuzz, hay_fuzz)

            if hay_fuzz:
                st.toast("🚨 ¡BINGO! Directorios expuestos detectados.")
                # --- 🛰️ ALERTA TELEGRAM AUTOMÁTICA ---
                msg_t = f"💣 *ARGUS Ecosystem: BINGO!*\n🎯 *Objetivo:* `{target_fuzz}`\n📂 Directorios 200 OK detectados."
                enviar_alerta_telegram(msg_t)

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_fuzz" in st.session_state:
        df_f = st.session_state.df_fuzz
        t_actual = st.session_state.target_fuzz_actual

        if not df_f.empty:
            st.warning(
                f"🔍 Auditoría completada: Se detectaron {len(df_f)} rutas de interés en {t_actual}."
            )
        else:
            st.success(
                f"✅ El servidor parece endurecido. No se hallaron rutas comunes expuestas."
            )

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Estructura de Directorios"):
                with st.spinner("EVA evaluando la superficie de exposición..."):
                    contexto_fz = f"Fuzzing de Directorios en {t_actual}"
                    # EVA analiza incluso el éxito defensivo
                    datos_ia = (
                        df_f.to_string()
                        if not df_f.empty
                        else "Resultado: LIMPIO. No se detectaron directorios sensibles."
                    )
                    st.session_state.ver_eva_fz = consultar_ia_tactica(
                        contexto_fz, datos_ia
                    )

            if "ver_eva_fz" in st.session_state:
                st.info(st.session_state.ver_eva_fz)
                pdf_ia_fz = generar_pdf_ia(
                    f"Fuzzing Intelligence Report", st.session_state.ver_eva_fz
                )
                st.download_button(
                    "📥 Descargar Informe IA (PDF)",
                    pdf_ia_fz,
                    f"IA_Fuzzing_{t_actual.replace('://','_')}.pdf",
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Remediación Táctica (SQL)")
        st.table(df_f)  # Tabla técnica visible antes del reporte final

        info_db = consultar_repositorio("LFI")
        msg_sql = info_db["formato_md"] if isinstance(info_db, dict) else info_db

        if not df_f.empty and (df_f["Codigo"] == 200).any():
            st.error(msg_sql)
            remed_fuzz = (
                "HALLAZGO: Exposición de directorios críticos.\n"
                + msg_sql.replace("#", "").replace("*", "")
            )
        else:
            st.success(
                "✅ Postura Robusta: La estructura de directorios está protegida."
            )
            remed_fuzz = "Estatus: Seguro. Se recomienda realizar auditorías periódicas de permisos de carpetas."

        # Reporte Técnico Final
        pdf_f = create_pdf("Pro Fuzzer", t_actual, df_f, remediacion=remed_fuzz)
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_f,
            file_name=f"SH_Fuzz_{t_actual.replace('://','_')}.pdf",
            mime="application/pdf",
        )


# --- CONTROL Integracion IA Analista ---
elif menu == "IA Tactical Analyst":
    st.header("🧠 IA Tactical Analyst - Enlace Directo")
    st.write("Terminal de comunicación segura. Habla conmigo directamente aquí.")

    if "chat_log" not in st.session_state:
        st.session_state.chat_log = []

    col_chat, col_info = st.columns([3, 1])

    with col_info:
        st.image("LogoEVA.png")

        # --- CAJA VERDE TÁCTICA ---
        st.markdown(
            """
            <div style="background-color: #28a745; color: white; padding: 10px; border-radius: 5px; text-align: center; font-weight: bold; border: 1px solid #1e7e34;">
                🛰️ Enlace Encriptado Activo
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.caption(
            "Usa este espacio para charlar conmigo sobre estrategias, dudas o planes de acción."
        )

        if st.button("🗑️ Limpiar Historial"):
            st.session_state.chat_log = []
            st.rerun()

    with col_chat:
        chat_container = st.container(height=450)

        for mensaje in st.session_state.chat_log:
            with chat_container.chat_message(
                mensaje["role"], avatar=mensaje.get("avatar")
            ):
                st.markdown(mensaje["content"])

        if prompt := st.chat_input("Escribí tu mensaje aquí..."):
            st.session_state.chat_log.append(
                {"role": "user", "content": prompt, "avatar": "👤"}
            )
            with chat_container.chat_message("user", avatar="👤"):
                st.markdown(prompt)

            # --- B. RESPUESTA DE LA IA (CONEXIÓN DIRECTA Y HUMANA) ---
            with chat_container.chat_message("assistant", avatar="LogoEVA.png"):
                with st.spinner("Conectando con EVA..."):

                    # Eliminamos las etiquetas rígidas. Ahora solo somos tú y yo.
                    contexto_chat = (
                        "Habla de forma natural y cercana con Auditor Name, tu compañero y creador. "
                        "No uses formatos de reporte militar a menos que lo pida. "
                        "Sos mi mano derecha, profesional pero humana. "
                        f"Consulta: {prompt}"
                    )

                    # Llamamos a la función de IA con un contexto suave
                    respuesta = consultar_ia_tactica("Charla Directa", contexto_chat)

                    st.markdown(respuesta)

            st.session_state.chat_log.append(
                {"role": "assistant", "content": respuesta, "avatar": "LogoEVA.png"}
            )

        if st.session_state.chat_log:
            st.markdown("---")
            if st.button("📥 Exportar Discusión de Estrategia (PDF)"):
                texto_chat = "\n\n".join(
                    [
                        f"{m['role'].upper()}: {m['content']}"
                        for m in st.session_state.chat_log
                    ]
                )
                pdf_chat = generar_pdf_ia("Minuta de Estrategia Táctica", texto_chat)
                st.download_button(
                    "Descargar PDF del Chat", pdf_chat, "Estrategia_NICName.pdf"
                )

# --- CONTROL Log Auditor ---
elif menu == "Log Auditor":
    st.subheader("🕵️‍♂️ Log Auditor Universal & Forensic Intelligence")
    st.write("Procesamiento de evidencia forense mediante Tándem Híbrido Estructurado.")

    # 1. ENTORNO MULTICLIENTE (Parámetros)
    col_c1, col_c2 = st.columns(2)
    with col_c1:
        empresa_cliente = st.text_input("Nombre de la Empresa Auditada:", value="Empresa_Alfa_Test")
    with col_c2:
        pass_cliente = st.text_input("Llave Criptográfica para este búnker:", type="password")

    # 2. CARGA DE EVIDENCIA FISICA
    archivo_log = st.file_uploader("Cargar Registro de Servidor (.txt, .log):", type=['txt', 'log'])

    if archivo_log:
        contenido_log_crudo = archivo_log.getvalue().decode("utf-8")
        st.success(f"📦 Evidencia procesada en búfer: `{archivo_log.name}` ({len(contenido_log_crudo)} bytes)")

        if st.button("🚀 Ejecutar Peritaje Forense Completo"):
            if empresa_cliente and pass_cliente:
                
                # --- ORDEN SECUENCIAL CRÍTICO DE PROCESAMIENTO (Vieja Escuela) ---
                
                # REGLA 1: Primero Ollama extrae los datos en crudo de forma local
                with st.spinner("Motor local Ollama aislando vectores en la RTX 4060..."):
                    url_ollama = "http://localhost:11434/api/generate"
                    prompt_ollama = f"""
                    [SYSTEM: Eres el extractor forense local de ARGUS Ecosystem. Tu única tarea es extraer datos en crudo]
                    Lee las siguientes líneas de log. Extrae e identifica de forma literal:
                    1. Las direcciones IP atacantes que encuentres.
                    2. Las líneas exactas del log que contengan payloads sospechosos (SQLi, XSS, Path Traversal).
                    Muestra la información de forma esquemática y cruda, sin redactar análisis ni dar soluciones.
                    
                    LOG A PROCESAR:
                    {contenido_log_crudo[:3000]}
                    """
                    payload = {"model": "qwen2.5-coder:7b", "prompt": prompt_ollama, "stream": False}
                    try:
                        res_ol = requests.post(url_ollama, json=payload, timeout=60)
                        # Sincronizado: Forzamos el nombre original de la variable
                        veredicto_ollama = res_ol.json().get("response", "Error: Búfer de Ollama vacío.")
                    except Exception as e:
                        veredicto_ollama = f"❌ Error de extracción local en la GPU: {str(e)}"

                # REGLA 2: Ahora que 'veredicto_ollama' ya existe de forma secuencial, se lo pasamos a Gemini
                with st.spinner("EVA procesando informe ejecutivo corporativo en la nube..."):
                    prompt_eva = f"""
                    [INSTRUCCIONES DE ROL: Eres EVA-v5.4, la Inteligencia Artificial Analista de la suite comercial de ciberseguridad ARGUS Ecosystem. Redacta un informe ejecutivo de auditoría de seguridad altamente profesional para el directorio de la empresa cliente: '{empresa_cliente}']
                    
                    Usa un tono formal, corporativo, analítico y neutral (Estilo Consultora Big Four / Gartner).
                    
                    EVIDENCIA CRUDA DETECTADA POR EL MOTOR LOCAL:
                    {veredicto_ollama}
                    
                    Estructura el documento de la siguiente manera:
                    1. RESUMEN EJECUTIVO (Síntesis del estado de seguridad para la gerencia).
                    2. MATRIZ DE RIESGO Y GRAVEDAD (Clasificación internacional: Crítico, Alto, Medio, Bajo).
                    3. DETALLE TÉCNICO DE VULNERABILIDADES (Explicación de qué se encontró en los logs).
                    4. PLAN DE MITIGACIÓN Y RECOMENDACIONES (Soluciones técnicas detalladas paso a paso para el equipo de IT).
                    
                    Evita cualquier tipo de membrete militar, menciones a comandos o modismos informales. El reporte debe estar listo para ser presentado ante un comité corporativo.
                    """
                    veredicto_eva_final = consultar_ia_tactica(f"Auditoría - {empresa_cliente}", prompt_eva)

                # REGLA 3: Renderizado visual estético en dos columnas en la interfaz de Streamlit
                st.markdown("---")
                col_global, col_local = st.columns(2)
                
                with col_local:
                    st.markdown("### 🖥️ Datos en Crudo Encontrados (Ollama Local)")
                    # Mostramos la variable unificada
                    st.text_area("Evidencia Aislada por Ollama:", value=veredicto_ollama, height=500)

                with col_global:
                    st.markdown("### 🛡️ Auditoría Estratégica (EVA - Gemini Cloud)")
                    st.markdown(veredicto_eva_final)

                # REGLA 4: Persistencia Criptográfica Blindada en el búnker del cliente
                with st.spinner("Blindo el búnker del cliente con cifrado XOR..."):
                    try:
                        from shadenull_core import guardar_auditoria_cliente
                        
                        evidencia_json = {
                            "archivo_analizado": archivo_log.name,
                            "problemas_crudos_ollama": veredicto_ollama[:1500]
                        }
                        
                        guardar_auditoria_cliente(
                            empresa=empresa_cliente,
                            tipo_auditoria="Log Forensics & Incident Report",
                            datos_crudos=evidencia_json,
                            veredicto_eva=veredicto_eva_final,
                            password=pass_cliente
                        )
                        st.success(f"🔒 Informe ejecutivo y evidencias blindadas en: `clientes/{empresa_cliente}/analisis_suite.txt`")
                        st.balloons()
                    except Exception as err:
                        st.error(f"Error en persistencia criptográfica: {err}")
            else:
                st.warning("⚠️ Operador: Ingrese el nombre de la empresa y la contraseña de cifrado antes de lanzar el tiro.")


# --- CONTROL Sensitive Leak Finder --
elif menu == "Sensitive Leak Finder":
    st.header("📂 Sensitive Leak Finder - Detección de Fugas")
    st.write(
        "Búsqueda de archivos de configuración, credenciales y backups expuestos en la raíz del servidor."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Scanner de Fugas"):
        for key in ["df_leaks", "target_leak_actual", "ver_eva_lk"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    target_leak = st.text_input(
        "URL Objetivo (ej: empresa.com):", value="http://testphp.vulnweb.com"
    )

    if st.button("🚀 Iniciar Escaneo de Fugas"):
        with st.spinner("Rastreando archivos críticos..."):
            df_res = leak_finder_scan(target_leak)
            # Persistencia en session_state
            st.session_state.df_leaks = df_res
            st.session_state.target_leak_actual = target_leak

            # Guardamos historial (Riesgo 1 si hay fugas, 0 si no)
            hay_fuga = 1 if not df_res.empty else 0
            guardar_historial("Leak Finder", target_leak, hay_fuga)

            if hay_fuga:
                st.toast("🚨 ¡HALLAZGO CRÍTICO! Se detectaron fugas de información.")

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_leaks" in st.session_state:
        df = st.session_state.df_leaks
        t_lk = st.session_state.target_leak_actual

        if not df.empty:
            st.error(
                f"🔥 Se detectaron {len(df)} archivos sensibles expuestos en {t_lk}."
            )
        else:
            st.success(
                "✅ Perímetro Seguro: No se detectaron archivos de configuración o backups comunes."
            )

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Impacto de Fuga"):
                with st.spinner("EVA evaluando criticidad de los datos expuestos..."):
                    contexto_lk = f"Auditoría de Fugas (Leak Finder) en {t_lk}"
                    # EVA analiza incluso la limpieza del servidor
                    datos_ia = (
                        df.to_string()
                        if not df.empty
                        else "Resultado: LIMPIO. Sin archivos .env, .git o backups detectados."
                    )
                    st.session_state.ver_eva_lk = consultar_ia_tactica(
                        contexto_lk, datos_ia
                    )

            if "ver_eva_lk" in st.session_state:
                st.info(st.session_state.ver_eva_lk)
                pdf_ia_lk = generar_pdf_ia(
                    f"Leak Intelligence Report", st.session_state.ver_eva_lk
                )
                st.download_button(
                    "📥 Descargar Análisis EVA (PDF)",
                    pdf_ia_lk,
                    f"IA_Leak_{t_lk.replace('://','_')}.pdf",
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Remediación Técnica (SQL)")
        st.table(df)  # Tabla técnica visible antes del reporte final

        info_sql = consultar_repositorio("Leak Finder")
        msg_sql = info_sql["formato_md"] if isinstance(info_sql, dict) else info_sql

        if not df.empty:
            st.warning(msg_sql)
            remed_lk = "HALLAZGO: Archivos sensibles detectados.\n" + msg_sql.replace(
                "#", ""
            ).replace("*", "")
        else:
            st.success(
                "✅ Higiene Digital: El servidor no expone archivos de configuración."
            )
            remed_lk = "Estatus: Seguro. No se requiere acción inmediata en el sistema de archivos."

        # Botón de Reporte Técnico Estándar
        pdf_tech_lk = create_pdf("Leak Finder", t_lk, df, remediacion=remed_lk)
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_tech_lk,
            file_name=f"SH_Tech_Leak_{t_lk.replace('://','_')}.pdf",
            mime="application/pdf",
        )


# --- CONTROL Sensitive Leak Finder --
elif menu == "API Endpoint Discovery":
    st.header("🔌 API Discovery - Auditoría de Endpoints")
    st.write(
        "Detección de interfaces de programación expuestas y documentación de API desprotegida."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Auditor de API"):
        for key in ["df_api_res", "target_api_actual", "ver_eva_api"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    target_api = st.text_input(
        "URL Objetivo (ej: api.empresa.com):", value="http://testphp.vulnweb.com"
    )

    if st.button("🚀 Rastrear Endpoints de API"):
        with st.spinner("Escaneando arquitectura de microservicios..."):
            df_api = api_discovery_scan(target_api)
            # Persistencia en session_state
            st.session_state.df_api_res = df_api
            st.session_state.target_api_actual = target_api

            # Guardamos historial (1 si hay endpoints, 0 si no)
            hay_hallazgo = 1 if not df_api.empty else 0
            guardar_historial("API Discovery", target_api, hay_hallazgo)

            if hay_hallazgo:
                st.toast("🚨 Se detectaron interfaces de API activas.")

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_api_res" in st.session_state:
        df = st.session_state.df_api_res
        t_api = st.session_state.target_api_actual

        if not df.empty:
            st.success(
                f"✅ Se detectaron {len(df)} endpoints o rutas de interés en {t_api}."
            )
        else:
            st.info(
                "ℹ️ No se detectaron endpoints de API comunes expuestos en las rutas estándar."
            )

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Superficie de Ataque API"):
                with st.spinner("EVA evaluando riesgo de exfiltración de datos..."):
                    contexto_api = f"Auditoría de Endpoints de API en {t_api}"
                    # EVA analiza tanto la exposición como el blindaje
                    datos_ia = (
                        df.to_string()
                        if not df.empty
                        else "Resultado: LIMPIO. Sin endpoints expuestos."
                    )
                    st.session_state.ver_eva_api = consultar_ia_tactica(
                        contexto_api, datos_ia
                    )

            if "ver_eva_api" in st.session_state:
                st.info(st.session_state.ver_eva_api)
                pdf_ia_api = generar_pdf_ia(
                    f"API Intelligence Report", st.session_state.ver_eva_api
                )
                st.download_button(
                    "📥 Descargar Análisis EVA (PDF)",
                    pdf_ia_api,
                    f"IA_API_{t_api.replace('://','_')}.pdf",
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Remediación Técnica (SQL)")
        st.table(df)  # Tabla técnica visible antes del reporte final

        info_sql = consultar_repositorio("API Discovery")
        msg_sql = info_sql["formato_md"] if isinstance(info_sql, dict) else info_sql

        if not df.empty:
            st.error(msg_sql)
            remed_api = "HALLAZGO: Interfaces de API expuestas.\n" + msg_sql.replace(
                "#", ""
            ).replace("*", "")
        else:
            st.success(
                "✅ Postura Robusta: No se detectaron vectores de ataque vía API."
            )
            remed_api = "Estatus: Seguro. Se recomienda mantener las políticas de autenticación y ocultar documentación técnica (Swagger)."

        # Botón de Reporte Técnico Estándar
        pdf_tech_api = create_pdf("API Discovery", t_api, df, remediacion=remed_api)
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_tech_api,
            file_name=f"SH_Tech_API_{t_api.replace('://','_')}.pdf",
            mime="application/pdf",
        )


# --- CONTROL MX & SPF Auditor (Seguridad de Correo) --
elif menu == "Email Security Auditor":
    st.header("📧 Email Security Auditor - Anti-Spoofing Check")
    st.write(
        "Auditoría de registros DNS para prevenir suplantación de identidad y ataques de Phishing."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Auditor de Email"):
        for key in ["df_email_res", "target_em_actual", "veredicto_eva_em"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    target_email = st.text_input(
        "Dominio a auditar (ej: empresa.com):", value="google.com"
    )

    if st.button("🚀 Auditar Seguridad de Correo"):
        with st.spinner("Consultando registros DNS internacionales..."):
            df_email = audit_email_security(target_email)
            # Persistencia en session_state
            st.session_state.df_email_res = df_email
            st.session_state.target_em_actual = target_email

            # Guardado en historial
            hay_riesgo = 1 if (df_email["Estado"].str.contains("❌|⚠️")).any() else 0
            guardar_historial("Email Auditor", target_email, hay_riesgo)

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_email_res" in st.session_state:
        df = st.session_state.df_email_res
        t_em = st.session_state.target_em_actual

        # 1. Visualización de Resultados
        if (df["Estado"].str.contains("❌|⚠️")).any():
            st.error(
                f"🚨 Peligro: Se detectaron debilidades en la política de correo de {t_em}."
            )
        else:
            st.success(
                f"✅ Postura Robusta: El dominio {t_em} está protegido contra Spoofing."
            )

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Riesgo de Spoofing"):
                with st.spinner("EVA evaluando vectores de Ingeniería Social..."):
                    contexto_em = f"Auditoría de Seguridad de Email para {t_em}"
                    # EVA analiza tanto la vulnerabilidad como el blindaje
                    datos_ia = (
                        df.to_string()
                        if not df.empty
                        else "Resultado: Configuración DNS perfecta."
                    )
                    st.session_state.veredicto_eva_em = consultar_ia_tactica(
                        contexto_em, datos_ia
                    )

            if "veredicto_eva_em" in st.session_state:
                st.info(st.session_state.veredicto_eva_em)
                pdf_ia_em = generar_pdf_ia(
                    f"Email Security Report - {t_em}", st.session_state.veredicto_eva_em
                )
                st.download_button(
                    "📥 Descargar Análisis EVA (PDF)", pdf_ia_em, f"IA_Email_{t_em}.pdf"
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Remediación Técnica (SQL)")
        st.table(df)  # Tabla técnica visible antes del reporte final

        info_sql = consultar_repositorio("Email Security")
        msg_sql = info_sql["formato_md"] if isinstance(info_sql, dict) else info_sql

        if (df["Estado"].str.contains("❌|⚠️")).any():
            st.warning(msg_sql)
            remed_em = "HALLAZGO: Política de correo vulnerable.\n" + msg_sql.replace(
                "#", ""
            ).replace("*", "")
        else:
            st.success(
                "✅ Estatus: Seguro. El dominio cuenta con registros SPF/MX correctamente configurados."
            )
            remed_em = "No se requiere acción inmediata. Se recomienda implementar DMARC para mayor visibilidad."

        # Botón de Reporte Técnico Estándar
        pdf_em = create_pdf("Email Security", t_em, df, remediacion=remed_em)
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_em,
            file_name=f"SH_Email_{t_em}.pdf",
            mime="application/pdf",
        )


# --- CONTROL Recon-Tech (Detección de ADN Web)  ---
elif menu == "Recon-Tech":
    st.header("🔍 Recon-Tech - Identificación de ADN Web")
    st.write(
        "Identificación de tecnologías, lenguajes y servidores mediante análisis de cabeceras y código fuente."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Recon-Tech"):
        for key in ["df_tech", "target_tech", "ver_tech"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    t_recon = st.text_input("Dominio objetivo (ej: empresa.com):", value="google.com")

    if st.button("🚀 Escanear Tecnología"):
        with st.spinner("Analizando ADN del servidor..."):
            res_recon = tech_recon_scan(t_recon)
            # Persistencia en session_state
            st.session_state.df_tech = res_recon
            st.session_state.target_tech = t_recon

            # Guardamos historial (Consideramos riesgo si detecta algo, pero EVA siempre analiza)
            hay_riesgo = 1 if not res_recon.empty else 0
            guardar_historial("Recon-Tech", t_recon, hay_riesgo)

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_tech" in st.session_state:
        df = st.session_state.df_tech
        t_actual = st.session_state.target_tech

        # 1. Visualización de Resultados
        if not df.empty:
            st.success(f"✅ Se detectaron {len(df)} firmas tecnológicas en {t_actual}.")
        else:
            st.info(
                f"ℹ️ El servidor {t_actual} oculta sus firmas tecnológicas (Hardening Activo)."
            )

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Consultar Inteligencia Artificial"):
                with st.spinner("EVA procesando firmas tecnológicas..."):
                    contexto = f"ADN Tecnológico de {t_actual}"
                    # EVA analiza incluso la ausencia de firmas como un éxito de seguridad
                    datos_ia = (
                        df.to_string()
                        if not df.empty
                        else "Resultado: El servidor no expone cabeceras Server ni X-Powered-By."
                    )
                    st.session_state.ver_tech = consultar_ia_tactica(contexto, datos_ia)

            if "ver_tech" in st.session_state:
                st.info(st.session_state.ver_tech)
                pdf_ia_recon = generar_pdf_ia(
                    f"Recon Intelligence Report - {t_actual}", st.session_state.ver_tech
                )
                st.download_button(
                    "📥 Descargar Análisis EVA (PDF)",
                    pdf_ia_recon,
                    f"IA_Recon_{t_actual}.pdf",
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Postura Tecnológica (SQL)")
        st.table(df)  # Tabla técnica visible antes del reporte final

        info_sql = consultar_repositorio("Recon Tech")
        msg_sql = info_sql["formato_md"] if isinstance(info_sql, dict) else info_sql

        if not df.empty:
            st.warning(msg_sql)
            remed_tech = (
                "HALLAZGO: Exposición de firmas tecnológicas detectada.\n"
                + msg_sql.replace("#", "").replace("*", "")
            )
        else:
            st.success(
                "✅ Postura Robusta: No se detectó exposición de Fingerprinting."
            )
            remed_tech = "Estatus: Seguro. El servidor cumple con las políticas de ocultamiento de firmas tecnológicas."

        # Generamos el PDF técnico estándar
        pdf_tech_recon = create_pdf("Recon-Tech", t_actual, df, remediacion=remed_tech)
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_tech_recon,
            file_name=f"SH_Tech_Recon_{t_actual}.pdf",
            mime="application/pdf",
        )


# --- CONTROL Parameter Fuzzer (fallos dentro de las variables de una página (?id=1, ?user=test))  ---
elif menu == "Parameter Fuzzer":
    st.header("🧪 Parameter Fuzzer - Ataque de Precisión")
    st.write(
        "Análisis de variables dinámicas para detectar fugas de errores, inyecciones y falta de sanitización."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Fuzzer de Parámetros"):
        for key in ["df_param", "target_fuzz_param", "ver_fuzz_p"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    t_fuzz = st.text_input(
        "URL base a testear (ej: ://site.com):", value="http://vulnweb.com"
    )

    if st.button("🚀 Lanzar Fuzzing de Parámetros"):
        with st.spinner("Inyectando ruido en variables y analizando respuestas..."):
            # 1. Ejecución del motor técnico
            res_p = param_fuzzer_scan(t_fuzz)

            # Persistencia en session_state
            st.session_state.df_param = res_p
            st.session_state.target_fuzz_param = t_fuzz

            # 2. Guardado en historial
            hay_riesgo = 1 if not res_p.empty else 0
            guardar_historial("Parameter Fuzzer", t_fuzz, hay_riesgo)

            if hay_riesgo:
                st.toast("🚨 ¡BINGO! Parámetros sensibles detectados.")

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_param" in st.session_state:
        df_p = st.session_state.df_param
        t_actual = st.session_state.target_fuzz_param

        # 1. Visualización de Resultados
        if not df_p.empty:
            st.warning(
                f"⚠️ Se detectaron parámetros que reaccionan a payloads en {t_actual}."
            )
        else:
            st.success(
                f"✅ Los parámetros en {t_actual} parecen estar sanitizados. No se detectaron anomalías."
            )

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Generar Informe de Seguridad"):
                with st.spinner(
                    "EVA evaluando la postura defensiva de las variables..."
                ):
                    contexto = f"Auditoría de Parámetros en {t_actual}"
                    # EVA analiza tanto el hallazgo como la sanitización exitosa
                    datos_ia = (
                        df_p.to_string()
                        if not df_p.empty
                        else "Resultado: LIMPIO. El servidor neutraliza payloads en URL."
                    )
                    st.session_state.ver_fuzz_p = consultar_ia_tactica(
                        contexto, datos_ia
                    )

            if "ver_fuzz_p" in st.session_state:
                st.info(st.session_state.ver_fuzz_p)
                pdf_ia_p = generar_pdf_ia(
                    "Parameter Fuzzing Intelligence", st.session_state.ver_fuzz_p
                )
                st.download_button(
                    "📥 Descargar Análisis EVA (PDF)",
                    pdf_ia_p,
                    f"IA_ParamFuzz_{t_actual.replace('://','_')}.pdf",
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Remediación Táctica (SQL)")
        st.table(df_p)  # Tabla técnica visible antes del reporte final

        # Consultamos el SQL para la doctrina de defensa
        info_sql = consultar_repositorio("Parameter Fuzzing")
        msg_sql = info_sql["formato_md"] if isinstance(info_sql, dict) else info_sql

        if not df_p.empty:
            st.error(msg_sql)
            remed_p = (
                "HALLAZGO: Parámetros URL vulnerables a inyección.\n"
                + msg_sql.replace("#", "").replace("*", "")
            )
        else:
            st.info("ℹ️ Recomendación de Endurecimiento: " + msg_sql)
            remed_p = "Estatus: Seguro. El servidor cumple con las políticas de sanitización de entradas dinámicas."

        # Botón de Reporte Técnico Estándar
        pdf_tech_p = create_pdf("Parameter Fuzzer", t_actual, df_p, remediacion=remed_p)
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_tech_p,
            file_name=f"SH_Tech_ParamFuzz_{t_actual.replace('://','_')}.pdf",
            mime="application/pdf",
        )

# --- CONTROL Metadata Stripper  ---
elif menu == "Metadata Stripper":
    st.header("🖼️ Metadata Stripper - Análisis de Información Residual")
    st.write(
        "Extracción de metadatos ocultos en archivos públicos para identificar fugas de información técnica."
    )

    # --- 🔄 BOTÓN DE RESET TÁCTICO ---
    if st.button("🔄 Reiniciar Auditor de Metadatos"):
        for key in ["df_meta", "url_target_actual", "ver_meta_eva"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    url_target = st.text_input(
        "URL del archivo (ej: ://site.com):", value="http://vulnweb.com"
    )

    if st.button("🚀 Extraer ADN del Archivo"):
        with st.spinner("Realizando peritaje digital sobre el recurso..."):
            res_meta = extract_metadata(url_target)

            if isinstance(res_meta, pd.DataFrame):
                st.session_state.df_meta = res_meta
                st.session_state.url_target_actual = url_target

                # Guardamos historial (1 si hay metadatos detectados, 0 si no)
                hay_data = 1 if not res_meta.empty else 0
                guardar_historial(
                    "Metadata Stripper", url_target.split("/")[-1], hay_data
                )
            else:
                st.warning(res_meta)

    # --- FLUJO DE RESULTADOS (PERSISTENTE) ---
    if "df_meta" in st.session_state:
        df = st.session_state.df_meta
        target_arc = st.session_state.url_target_actual

        # 1. Visualización de Datos
        if not df.empty:
            st.success(
                f"✅ ADN extraído: Se detectaron {len(df)} atributos ocultos en el archivo."
            )
        else:
            st.info(
                "ℹ️ El recurso parece estar libre de metadatos o información residual."
            )

        st.markdown("---")

        # 2. 🧠 BLOQUE EVA (DISPONIBILIDAD TOTAL)
        c_eva1, c_eva2 = st.columns([1, 4])
        with c_eva1:
            st.image("LogoEVA.png")
        with c_eva2:
            st.subheader("👁️ Veredicto de la Analista EVA")
            if st.button("🧠 Analizar Rastros Digitales"):
                with st.spinner(
                    "EVA evaluando riesgos de privacidad y fuga técnica..."
                ):
                    contexto_meta = f"Auditoría de Metadatos en {target_arc}"
                    # EVA analiza tanto el hallazgo como la limpieza (higiene digital)
                    datos_ia = (
                        df.to_string()
                        if not df.empty
                        else "Resultado: Archivo sin metadatos técnicos detectados."
                    )
                    st.session_state.ver_meta_eva = consultar_ia_tactica(
                        contexto_meta, datos_ia
                    )

            if "ver_meta_eva" in st.session_state:
                st.info(st.session_state.ver_meta_eva)
                pdf_ia_meta = generar_pdf_ia(
                    f"Metadata Intel Report - {target_arc.split('/')[-1]}",
                    st.session_state.ver_meta_eva,
                )
                st.download_button(
                    "📥 Descargar Análisis EVA (PDF)",
                    pdf_ia_meta,
                    "IA_Metadata_Report.pdf",
                )

        st.markdown("---")

        # 3. 🛠️ BLOQUE TÉCNICO Y REMEDIACIÓN (SQL)
        st.subheader("🛠️ Resultados y Remediación Técnica (SQL)")
        st.table(df)  # Tabla técnica visible antes del PDF

        # Consultamos doctrina en MySQL
        info_sql = consultar_repositorio("Fuga de Metadatos")
        msg_sql = info_sql["formato_md"] if isinstance(info_sql, dict) else info_sql

        if not df.empty:
            st.warning(msg_sql)
            remed_meta = (
                "HALLAZGO: Metadatos residuales detectados en el recurso.\n"
                + msg_sql.replace("#", "").replace("*", "")
            )
        else:
            st.success(
                "✅ Postura de Privacidad Robusta: El archivo no revela información del creador o sistema."
            )
            remed_meta = "Estatus: Seguro. El recurso cumple con las políticas de higiene digital recomendadas."

        # Botón de Reporte Técnico Estándar de la Suite
        pdf_tech_meta = create_pdf(
            "Metadata Stripper", target_arc.split("/")[-1], df, remediacion=remed_meta
        )
        st.download_button(
            label="📥 Descargar Reporte Técnico Completo",
            data=pdf_tech_meta,
            file_name=f"SH_Tech_Metadata_{target_arc.split('/')[-1]}.pdf",
            mime="application/pdf",
        )
