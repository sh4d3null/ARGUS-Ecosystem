import os
from datetime import datetime
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generar_pdf_red_corporativo(empresa, tipo_auditoria, registros_descifrados):
    """
    PLANTILLA DE FÁBRICA: Genera un entregable de infraestructura de red de alta calidad.
    Muestra los estados de los puertos limpios y la mitigación de perímetros.
    """
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=50)
    styles = getSampleStyleSheet()
    
    style_titulo = ParagraphStyle(
        'TituloNet', parent=styles['Heading1'], fontName='Helvetica-Bold',
        fontSize=22, leading=26, textColor=colors.HexColor('#1F3A60'), alignment=1
    )
    style_sub = ParagraphStyle(
        'SubNet', parent=styles['Normal'], fontName='Helvetica-Bold',
        fontSize=11, leading=14, textColor=colors.HexColor('#4A5568')
    )
    style_body = ParagraphStyle(
        'BodyNet', parent=styles['BodyText'], fontName='Helvetica',
        fontSize=10, leading=14, textColor=colors.HexColor('#2D3748')
    )
    style_legal = ParagraphStyle(
        'LegalNet', parent=styles['Normal'], fontName='Helvetica-Oblique',
        fontSize=8, leading=11, textColor=colors.HexColor('#718096'), alignment=4
    )

    elementos = []
    
    # --- PORTADA CORPORATIVA DE PERÍMETRO ---
    elementos.append(Spacer(1, 40))
    elementos.append(Paragraph("SH4D3NULL NETWORK AUDIT SUITE", style_titulo))
    elementos.append(Spacer(1, 15))
    elementos.append(Paragraph("<b>INFORME TÉCNICO DE SEGURIDAD PERIMETRAL</b>", style_titulo))
    elementos.append(Spacer(1, 30))
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    datos_portada = [
        [Paragraph("<b>ORGANIZACIÓN CLIENTE:</b>", style_body), Paragraph(empresa.upper(), style_body)],
        [Paragraph("<b>ÁREA AUDITADA:</b>", style_body), Paragraph(tipo_auditoria, style_body)],
        [Paragraph("<b>AUDITOR EN JEFE:</b>", style_body), Paragraph("EZEQUIEL | NETWORK SECURITY", style_body)],
        [Paragraph("<b>MOMENTO DE EMISIÓN:</b>", style_body), Paragraph(timestamp, style_body)],
        [Paragraph("<b>CLASIFICACIÓN:</b>", style_body), Paragraph("<font color='#dd6b20'><b>RESTRINGIDO / CONFIDENCIAL</b></font>", style_body)]
    ]
    t_portada = Table(datos_portada, colWidths=[150, 350])
    t_portada.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#EDF2F7')),
        ('PADDING', (0,0), (-1,-1), 10),
        ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor('#1F3A60')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elementos.append(t_portada)
    elementos.append(Spacer(1, 40))
    
    # --- EXTRACCIÓN DINÁMICA DE RE-ESCANEOS ---
    elementos.append(Paragraph("---" * 25, style_body))
    elementos.append(Spacer(1, 15))
    elementos.append(Paragraph("<b>1. DIAGNÓSTICO DE INFRAESTRUCTURA DE RED Y PUERTOS</b>", style_sub))
    elementos.append(Spacer(1, 15))
    
    for idx, reg in enumerate(registros_descifrados, 1):
        elementos.append(Paragraph(f"<b>Análisis de Perímetro #{idx} ({reg.get('fecha')})</b>", style_sub))
        elementos.append(Spacer(1, 5))
        
        veredicto = reg.get('veredicto_eva', 'Sin informe registrado.')
        for linea in veredicto.split('\n'):
            if linea.strip():
                elementos.append(Paragraph(linea, style_body))
                elementos.append(Spacer(1, 4))
                
        elementos.append(Spacer(1, 15))
        
    # --- ACTA DE CIERRE LEGAL STANDARD ---
    elementos.append(Spacer(1, 20))
    elementos.append(Paragraph("---" * 25, style_body))
    elementos.append(Spacer(1, 15))
    elementos.append(Paragraph("<b>2. EXCLUSIÓN DE RESPONSABILIDAD DE INFRAESTRUCTURA</b>", style_sub))
    elementos.append(Spacer(1, 10))
    
    clausula_texto = f"Al día de la fecha, {datetime.now().strftime('%d/%m/%Y')}, se ha labrado el presente informe técnico como resultado de la auditoría de infraestructura y escaneo de puertos solicitado por el cliente. Las conclusiones expuestas representan un diagnóstico estático de la superficie de ataque perimetral analizada bajo las condiciones estrictas del tiro original. <b>Sh4d3Null</b> no se responsabiliza por la apertura posterior de servicios, asignaciones de IPs dinámicas deficientes o brechas perimetrales que acontezcan con posterioridad a la fecha de emisión del presente documento."
    elementos.append(Paragraph(clausula_texto, style_legal))
    
    doc.build(elementos)
    buf.seek(0)
    return buf
