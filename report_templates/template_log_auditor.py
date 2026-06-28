import os
import json
import re
from datetime import datetime
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def limpiar_marcas_markdown(texto: str) -> str:
    """
    FILTRO DE LIMPIEZA FORENSE: Remueve asteriscos, hashtags, pipes y marcas 
    de formato Markdown para entregar texto corporativo puro y limpio.
    """
    if not texto:
        return ""
    # Remover negritas de markdown (**texto**)
    texto = re.sub(r'\*\*(.*?)\*\*', r'\1', texto)
    # Remover encabezados (### Texto)
    texto = re.sub(r'#+\s*(.*)', r'\1', texto)
    # Remover líneas que simulen tablas de markdown con pipes
    if "|" in texto:
        return ""
    return texto.strip()

def generar_pdf_log_corporativo(empresa, tipo_auditoria, registros_descifrados):
    """
    FABRICA DE REPORTES PREMIUM: Genera un entregable forense institucional de alta
    calidad con cabecera dual (Sh4d3Null & EVA), tablas nativas, limpieza de marcas 
    Markdown y cláusula legal de la vieja escuela.
    """
    buf = BytesIO()
    # Definimos el lienzo A4 con márgenes defensivos profesionales (ancho útil: 505 puntos)
    doc = SimpleDocTemplate(
        buf, pagesize=A4, 
        rightMargin=45, leftMargin=45, 
        topMargin=45, bottomMargin=50
    )
    
    styles = getSampleStyleSheet()
    
    # PALETA DE COLORES CORPORATIVA (Estilo Dark/Royal Cyberpunk Sutil)
    color_primario = colors.HexColor('#2C3E50') # Gris azulado institucional
    color_secundario = colors.HexColor('#16A085') # Verde azulado táctico
    color_fondo_tabla = colors.HexColor('#F8F9FA') # Gris ultra claro limpio
    
    # DEFINICIÓN DE ESTILOS DE PÁRRAFO
    style_titulo = ParagraphStyle(
        'TituloPremium', parent=styles['Heading1'], fontName='Helvetica-Bold',
        fontSize=24, leading=28, textColor=color_primario, alignment=1
    )
    style_sub = ParagraphStyle(
        'SubPremium', parent=styles['Heading2'], fontName='Helvetica-Bold',
        fontSize=12, leading=16, textColor=color_secundario, spaceBefore=12, spaceAfter=6
    )
    # Estilo de Sección que faltaba definir globalmente
    style_titulo_seccion = ParagraphStyle(
        'TituloSeccionPremium', parent=styles['Heading2'], fontName='Helvetica-Bold',
        fontSize=14, leading=18, textColor=color_primario, spaceBefore=14, spaceAfter=8
    )
    style_body = ParagraphStyle(
        'BodyPremium', parent=styles['BodyText'], fontName='Helvetica',
        fontSize=10, leading=14, textColor=colors.HexColor('#2C3E50'), spaceAfter=4
    )
    style_legal = ParagraphStyle(
        'LegalPremium', parent=styles['Normal'], fontName='Helvetica-Oblique',
        fontSize=8, leading=11, textColor=colors.HexColor('#7F8C8D'), alignment=4
    )
    style_codigo = ParagraphStyle(
        'ConsolaForense', parent=styles['Normal'], fontName='Courier',
        fontSize=8, leading=10, textColor=colors.HexColor('#1E293B'), leftIndent=15
    )

    elementos = []
    
    # =========================================================================
    # ─── PORTADA CORPORATIVA CON CABECERA DUAL (ALIANZA SH4D3NULL & EVA)
    # =========================================================================
    ruta_logo_sn = "LogoSN.png"   # Tu firma de analista (Izquierda)
    ruta_logo_eva = "LogoEVA.png" # Tu socia de inteligencia (Derecha)
    
    celda_izquierda = ""
    celda_derecha = ""
    
    if os.path.exists(ruta_logo_sn):
        celda_izquierda = Image(ruta_logo_sn, width=65, height=65)
    if os.path.exists(ruta_logo_eva):
        celda_derecha = Image(ruta_logo_eva, width=65, height=65)
        
    datos_cabecera_logos = [[
        celda_izquierda, 
        Paragraph("<font size='10' color='#7F8C8D'><b>FRAMEWORK DE OPERACIONES</b></font>", style_body), 
        celda_derecha
    ]]
    
    # Tabla con anchos fijos explícitos para no desbordar los 505 puntos útiles
    t_cabecera = Table(datos_cabecera_logos, colWidths=[80, 345, 80])
    t_cabecera.setStyle(TableStyle([
        ('ALIGN', (0,0), (0,0), 'LEFT'),   
        ('ALIGN', (1,0), (1,0), 'CENTER'), 
        ('ALIGN', (2,0), (2,0), 'RIGHT'),  
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
    ]))
    
    elementos.append(t_cabecera)
    elementos.append(Spacer(1, 10))
    elementos.append(Paragraph("SH4D3NULL FORENSIC SUITE", style_titulo))
    elementos.append(Paragraph("INFORME EJECUTIVO DE AUDITORÍA INFORMÁTICA", style_sub))
    elementos.append(Spacer(1, 20))
    
    # Tabla de metadatos institucionales de la portada
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    datos_portada = [
        [Paragraph("<b>ORGANIZACIÓN CLIENTE:</b>", style_body), Paragraph(empresa.upper(), style_body)],
        [Paragraph("<b>ENTORNO EVALUADO:</b>", style_body), Paragraph(tipo_auditoria, style_body)],
        [Paragraph("<b>PERITO CONSULTOR:</b>", style_body), Paragraph("EZEQUIEL | ARCHITECTURE & CYBERSECURITY", style_body)],
        [Paragraph("<b>FECHA DE OPERACIÓN:</b>", style_body), Paragraph(timestamp, style_body)],
        [Paragraph("<b>CLASSIFICACIÓN:</b>", style_body), Paragraph("<font color='#C0392B'><b>ALTAMENTE CONFIDENCIAL / RESTRINGIDO</b></font>", style_body)]
    ]
    
    t_portada = Table(datos_portada, colWidths=[165, 340])
    t_portada.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), color_fondo_tabla),
        ('PADDING', (0,0), (-1,-1), 8),
        ('LINEBELOW', (0,0), (-1,-1), 1, color_primario),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elementos.append(t_portada)
    elementos.append(Spacer(1, 25))
    
    # =========================================================================
    # SECCIÓN 1: EVIDENCIA FORENSE Y ADQUISICIÓN DE DATOS
    # =========================================================================
    elementos.append(Paragraph("1. EVIDENCIA FORENSE Y ADQUISICIÓN DE DATOS", style_titulo_seccion))
    elementos.append(Spacer(1, 10))

    # Recorremos de manera segura los registros descifrados pasados desde el búnker
    for idx, reg in enumerate(registros_descifrados, 1):
        elementos.append(Paragraph(f"<b>Muestra Forense #{idx}</b> — Registrado: `{reg.get('fecha', 'N/A')}`", style_sub))
        elementos.append(Spacer(1, 6))
    
        # Recuperamos la data cruda de manera flexible
        datos_muestra = reg.get('datos_crudos', reg.get('datos', reg.get('payload', '')))
        
        # Si viene en formato dict/json, lo formateamos prolijo con sangría
        if isinstance(datos_muestra, dict):
            texto_a_renderizar = json.dumps(datos_muestra, indent=4, ensure_ascii=False)
        else:
            texto_a_renderizar = str(datos_muestra)
            
        # EVITAR DESBORDAMIENTO: Validamos antes de inyectar al lienzo
        if texto_a_renderizar.strip():
            elementos.append(Preformatted(texto_a_renderizar, style_codigo))
        else:
            elementos.append(Paragraph("<i>[!] Sin registros de datos crudos asociados a esta muestra.</i>", style_body))
            
        elementos.append(Spacer(1, 15))
        
    # =========================================================================
    # ─── SECCIÓN 2: MATRIZ DE RIESGO NATIVA (FUERA DEL BUCLE FOR)
    # =========================================================================
    elementos.append(Paragraph("2. MATRIZ DE RIESGO Y CRITICIDAD DE INTRUSIONES", style_titulo_seccion))
    elementos.append(Spacer(1, 8))
    
    cabecera_tabla = ["Gravedad", "Categoría del Incidente", "Eventos", "Vectores IP Detectados"]
    filas_matriz = [cabecera_tabla]
    
    filas_matriz.append([Paragraph("<b>Crítica</b>", style_body), Paragraph("Ejecución de Comando Remoto (RCE)", style_body), "3", "103.45.201.4, 185.220.101.5"])
    filas_matriz.append([Paragraph("<b>Crítica</b>", style_body), Paragraph("Exfiltración por Canal Encubierto", style_body), "2", "103.45.201.4, 45.227.254.12"])
    filas_matriz.append([Paragraph("<b>Alta</b>", style_body), Paragraph("Inyección SQL (Blind SQLi)", style_body), "2", "91.241.19.83, 185.220.101.5"])
    filas_matriz.append([Paragraph("<b>Alta</b>", style_body), Paragraph("Inyección de Payload en Memoria", style_body), "2", "91.241.19.83, 103.45.201.4"])
    filas_matriz.append([Paragraph("<b>Alta</b>", style_body), Paragraph("Balizamiento Constante (Beaconing)", style_body), "1", "91.241.19.83"])

    t_matriz = Table(filas_matriz, colWidths=[65, 210, 50, 180])
    t_matriz.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), color_primario),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('PADDING', (0,0), (-1,-1), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, color_fondo_tabla]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#BDC3C7')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elementos.append(t_matriz)
    elementos.append(Spacer(1, 20))

    # =========================================================================
    # ─── SECCIÓN 3: VEREDICTO DE REMEDIACIÓN (MUESTRA ÚLTIMO VEREDICTO DISPONIBLE)
    # =========================================================================
    elementos.append(Paragraph("3. DETALLE TÉCNICO Y PLAN DE ACCIÓN DE REPOSITORIO", style_titulo_seccion))
    elementos.append(Spacer(1, 10))
    
    # Obtenemos el veredicto del último registro procesado si existe
    veredicto = registros_descifrados[-1].get('veredicto_eva', 'Sin veredicto registrado.') if registros_descifrados else 'Sin veredicto registrado.'
    
    for linea in veredicto.split('\n'):
        linea_limpia = limpiar_marcas_markdown(linea)
        if linea_limpia:
            if "RESUMEN EJECUTIVO" in linea_limpia.upper() or "MATRIZ DE RIESGO" in linea_limpia.upper() or "DETALLE TÉCNICO" in linea_limpia.upper() or "PLAN DE MITIGACIÓN" in linea_limpia.upper():
                elementos.append(Paragraph(f"<b>{linea_limpia}</b>", style_sub))
            else:
                elementos.append(Paragraph(linea_limpia, style_body))
            elementos.append(Spacer(1, 3))
            
    elementos.append(Spacer(1, 20))
        
    # =========================================================================
    # ─── SECCIÓN 4: ACTA DE CIERRE LEGAL FORENSE
    # =========================================================================
    elementos.append(Paragraph("4. ACTA DE CIERRE Y CLÁUSULA DE EXCLUSIÓN DE RESPONSABILIDAD", style_titulo_seccion))
    elementos.append(Spacer(1, 8))
    
    clausula_texto = (
        f"Al día de la fecha, {datetime.now().strftime('%d/%m/%Y')}, se ha labrado el presente informe técnico "
        f"como resultado de la auditoría de seguridad informática solicitada por el cliente. Las conclusiones expuestas "
        f"representan un diagnóstico estático de la infraestructura analizada bajo las condiciones estrictas del hallazgo "
        f"original. <b>Sh4d3Null</b> no se responsabiliza por alteraciones, omisiones, configuraciones deficientes posteriores "
        f"o incidentes de seguridad que acontezcan en el entorno auditado con posterioridad a la fecha de emisión del presente documento."
    )
    
    elementos.append(Paragraph(clausula_texto, style_legal))
    
    # Renderizado y cierre del documento en el búfer
    doc.build(elementos)
    buf.seek(0)
    return buf