from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from utils.s3_audit import get_s3_audit_summary
import datetime
import os

def generate_pdf_report():
    """Generate a summary PDF report of the latest S3 audit."""
    summary = get_s3_audit_summary()

    output_dir = "reports"
    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.join(output_dir, f"S3_Security_Report_{datetime.date.today()}.pdf")

    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("AWS S3 Security Audit Report", styles["Title"]))
    elements.append(Spacer(1, 20))
    elements.append(Paragraph(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    elements.append(Spacer(1, 15))

    # Summary Section
    summary_data = [
        ["Total Buckets", summary["total_buckets"]],
        ["Public Buckets", summary["public_buckets"]],
        ["Unencrypted Buckets", summary["unencrypted_buckets"]],
        ["Buckets with Public Objects", summary["buckets_with_public_objects"]],
        ["Total Issues Found", summary["issues_found"]]
    ]

    table = Table(summary_data, colWidths=[250, 100])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
        ("BOX", (0, 0), (-1, -1), 1, colors.black),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))

    elements.append(table)
    elements.append(Spacer(1, 30))
    elements.append(Paragraph("Report Summary:", styles["Heading2"]))
    elements.append(Paragraph(summary["summary_text"], styles["Normal"]))

    doc.build(elements)
    return filename
