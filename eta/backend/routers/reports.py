import logging
import traceback
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Body
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
import os, tempfile, json, secrets
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

from database import get_db, ThreatReport, ScanRecord, User, ScheduledReport, ShareLink, BrandingConfig
from routers.auth import get_current_user

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/report/{scan_id}")
def get_report(scan_id: str, db: Session = Depends(get_db)):
    rep = db.query(ThreatReport).filter(ThreatReport.scan_id == scan_id).first()
    if not rep:
        logger.warning(f"Report not found for scan_id: {scan_id}")
        raise HTTPException(404, f"Report not found: {scan_id}")
    return rep.report_json


@router.get("/report/{scan_id}/json")
def download_json(scan_id: str, db: Session = Depends(get_db)):
    rep = db.query(ThreatReport).filter(ThreatReport.scan_id == scan_id).first()
    if not rep:
        raise HTTPException(404, "Report not found")

    # Parse JSON string and save to temp file for download
    data = rep.report_json
    if isinstance(data, str):
        data = json.loads(data)

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode='w', encoding='utf-8')
    json.dump(data, tmp, indent=2, ensure_ascii=False)
    tmp.close()

    return FileResponse(
        tmp.name,
        media_type="application/json",
        filename=f"threat_report_{scan_id[:8]}.json"
    )


@router.post("/report/{scan_id}/pdf")
def generate_pdf(scan_id: str, db: Session = Depends(get_db)):
    rep = db.query(ThreatReport).filter(ThreatReport.scan_id == scan_id).first()
    if not rep:
        raise HTTPException(404, "Report not found")

    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_LEFT, TA_RIGHT

        # Page number callback
        def add_page_number(canvas, doc):
            page_num = canvas.getPageNumber()
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.HexColor("#64748B"))
            canvas.drawRightString(A4[0] - 2*cm, 0.75*cm, f"Page {page_num}")
            canvas.drawString(2*cm, 0.75*cm, "ETA Email Threat Analyzer")

        # Parse report JSON
        raw_data = rep.report_json
        data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data

        verdict = data.get("verdict", "unknown").lower()
        score = data.get("risk_score", 0)
        meta = data.get("meta", {})

        PRIMARY = colors.HexColor("#1E40AF")
        GRAY = colors.HexColor("#475569")
        LIGHT_GRAY = colors.HexColor("#F1F5F9")
        WHITE = colors.HexColor("#FFFFFF")
        DARK = colors.HexColor("#0F172A")

        banner_color = colors.HexColor("#DC2626") if verdict == "malicious" else colors.HexColor("#10B981") if verdict == "safe" else colors.HexColor("#F59E0B")

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        doc = SimpleDocTemplate(tmp.name, pagesize=A4, rightMargin=2.5*cm, leftMargin=2.5*cm, topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle("Title", parent=styles["Heading1"], fontSize=24, fontName="Helvetica-Bold", textColor=PRIMARY, spaceAfter=6, alignment=TA_LEFT)
        subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"], fontSize=10, textColor=GRAY, spaceAfter=4, alignment=TA_LEFT)
        section_style = ParagraphStyle("Section", parent=styles["Heading2"], fontSize=14, fontName="Helvetica-Bold", textColor=DARK, spaceBefore=16, spaceAfter=8)
        body_style = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, textColor=GRAY, spaceAfter=6, leading=14, alignment=TA_LEFT)
        small_style = ParagraphStyle("Small", parent=styles["Normal"], fontSize=8, textColor=GRAY)
        table_header_style = ParagraphStyle("TableHeader", parent=styles["Normal"], fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)
        table_cell_style = ParagraphStyle("TableCell", parent=styles["Normal"], fontSize=9, textColor=DARK)

        story = []
        story.append(Paragraph("EMAIL THREAT ANALYSIS REPORT", title_style))
        story.append(Spacer(1, 0.15*cm))
        story.append(Paragraph(f"Scan ID: {scan_id[:16]}... | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", subtitle_style))
        story.append(Spacer(1, 0.3*cm))
        story.append(HRFlowable(width="100%", thickness=1, color=LIGHT_GRAY))
        story.append(Spacer(1, 0.5*cm))

        # Verdict banner
        banner_data = [[Paragraph(f"STATUS: {verdict.upper()}", ParagraphStyle("BannerText", fontSize=16, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_LEFT)), Paragraph(f"Risk Score: {score}/100", ParagraphStyle("BannerScore", fontSize=16, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_RIGHT))]]
        banner_table = Table(banner_data, colWidths=[8*cm, 8*cm])
        banner_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), banner_color), ("PADDING", (0, 0), (-1, -1), 12), ("LEFTPADDING", (0, 0), (0, -1), 20), ("RIGHTPADDING", (1, 0), (1, -1), 20)]))
        story.append(banner_table)
        story.append(Spacer(1, 0.5*cm))

        # Executive summary
        story.append(Paragraph("Executive Summary", section_style))
        summary = data.get("analysis_summary") or data.get("summary") or "This email was analyzed for potential threats."
        story.append(Paragraph(summary, body_style))
        story.append(Spacer(1, 0.3*cm))

        # Email metadata
        story.append(Paragraph("Email Metadata", section_style))
        metadata_rows = [[Paragraph("Field", table_header_style), Paragraph("Value", table_header_style)]]
        for label, value in [("Verdict", verdict.upper()), ("From", meta.get("sender", "N/A")), ("To", meta.get("recipient", "N/A")), ("Subject", meta.get("subject", "N/A"))]:
            metadata_rows.append([Paragraph(label, table_cell_style), Paragraph(str(value), table_cell_style)])
        meta_table = Table(metadata_rows, colWidths=[3.5*cm, 13.5*cm])
        meta_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), PRIMARY), ("TEXTCOLOR", (0, 0), (-1, 0), WHITE), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("PADDING", (0, 0), (-1, -1), 8), ("BACKGROUND", (0, 1), (-1, -1), LIGHT_GRAY), ("GRID", (0, 0), (-1, -1), 0.5, GRAY)]))
        story.append(meta_table)
        story.append(Spacer(1, 0.4*cm))

        # Authentication
        story.append(Paragraph("Email Authentication", section_style))
        auth_data = data.get("header_analysis", {})
        auth_rows = [[Paragraph("Protocol", table_header_style), Paragraph("Status", table_header_style)]]
        for proto, label in [("spf", "SPF"), ("dkim", "DKIM"), ("dmarc", "DMARC")]:
            status = auth_data.get(proto, "unknown")
            auth_rows.append([Paragraph(label, table_cell_style), Paragraph(str(status).upper(), table_cell_style)])
        auth_table = Table(auth_rows, colWidths=[3*cm, 14*cm])
        auth_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), PRIMARY), ("TEXTCOLOR", (0, 0), (-1, 0), WHITE), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("PADDING", (0, 0), (-1, -1), 8), ("BACKGROUND", (0, 1), (-1, -1), WHITE), ("GRID", (0, 0), (-1, -1), 0.5, GRAY)]))
        story.append(auth_table)
        story.append(Spacer(1, 0.4*cm))

        # Footer
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=1, color=LIGHT_GRAY))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(f"ETA Email Threat Analyzer | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", small_style))

        doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
        return FileResponse(tmp.name, media_type="application/pdf", filename=f"threat_report_{scan_id[:8]}.pdf")

    except ImportError:
        raise HTTPException(500, "PDF generation unavailable - install reportlab")
    except Exception as e:
        raise HTTPException(500, f"PDF error: {str(e)}")


# ── Scheduled Report Exports ──────────────────────────────────────────────────

        # ── Scheduled Report Exports ──────────────────────────────────────────────────
@router.get("/scheduled-reports")
def list_scheduled(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = db.query(ScheduledReport).filter(ScheduledReport.user_id == user.id).all()
    return {"reports": [{"id": r.id, "email": r.email, "frequency": r.frequency,
      "scan_filter": r.scan_filter, "is_active": r.is_active,
      "next_send_at": r.next_send_at.isoformat(), "last_sent_at": r.last_sent_at.isoformat() if r.last_sent_at else None}
     for r in rows]}

@router.post("/scheduled-reports")
def create_scheduled(body: dict, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    freq = body.get("frequency", "daily")
    if freq not in ("daily", "weekly"):
        raise HTTPException(400, "frequency must be daily or weekly")
    now = datetime.utcnow()
    delta = timedelta(days=1) if freq == "daily" else timedelta(days=7)
    sr = ScheduledReport(
        user_id=user.id,
        email=body.get("email", user.email),
        frequency=freq,
        scan_filter=body.get("scan_filter"),
        next_send_at=now + delta,
    )
    db.add(sr)
    db.commit()
    db.refresh(sr)
    return {"id": sr.id, "next_send_at": sr.next_send_at.isoformat()}

@router.delete("/scheduled-reports/{id}", status_code=204)
def delete_scheduled(id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    db.query(ScheduledReport).filter(ScheduledReport.id == id, ScheduledReport.user_id == user.id).delete(synchronize_session=False)
    db.commit()
    return None


# ── Branding Config ───────────────────────────────────────────────────────────
@router.get("/branding")
def get_branding(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    cfg = db.query(BrandingConfig).filter(BrandingConfig.user_id == user.id).first()
    if not cfg:
        return {"company_name": "", "logo_url": "", "footer_text": "", "primary_color": "#06B6D4"}
    return {
        "company_name": cfg.company_name or "",
        "logo_url": cfg.logo_url or "",
        "footer_text": cfg.footer_text or "",
        "primary_color": cfg.primary_color or "#06B6D4",
    }

@router.put("/branding")
def save_branding(body: dict, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    cfg = db.query(BrandingConfig).filter(BrandingConfig.user_id == user.id).first()
    if not cfg:
        cfg = BrandingConfig(user_id=user.id)
        db.add(cfg)
    cfg.company_name = body.get("company_name", cfg.company_name)
    cfg.logo_url = body.get("logo_url", cfg.logo_url)
    cfg.footer_text = body.get("footer_text", cfg.footer_text)
    cfg.primary_color = body.get("primary_color", cfg.primary_color)
    db.commit()
    return {"message": "Branding saved"}


# ── Branded PDF export ─────────────────────────────────────────────────────────
@router.post("/report/{scan_id}/pdf/branded")
def generate_branded_pdf(scan_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rep = db.query(ThreatReport).filter(ThreatReport.scan_id == scan_id).first()
    if not rep:
        raise HTTPException(404, "Report not found")
    cfg = db.query(BrandingConfig).filter(BrandingConfig.user_id == user.id).first()

    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, Image, PageBreak
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        from reportlab.pdfgen import canvas as pdfcanvas
        from reportlab.platypus.flowables import Flowable
        from io import BytesIO

        # --- Page number callback ---
        def add_page_number(canvas, doc):
            """Add page numbers to each page"""
            page_num = canvas.getPageNumber()
            page_text = f"Page {page_num}"
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.HexColor("#64748B"))
            canvas.drawRightString(A4[0] - 2*cm, 0.75*cm, page_text)
            # Running header
            canvas.drawLeftString(2*cm, 0.75*cm, company)

        # Branding defaults - must be defined before callback use
        company = cfg.company_name if cfg and cfg.company_name else "ETA Email Threat Analyzer"
        logo_url = cfg.logo_url if cfg and cfg.logo_url else ""
        footer_txt = cfg.footer_text if cfg and cfg.footer_text else ""
        hex_color = cfg.primary_color if cfg and cfg.primary_color else "#06B6D4"

        raw_data = rep.report_json
        data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
        verdict = data.get("verdict", "unknown").lower()
        score = data.get("risk_score", 0)
        meta = data.get("meta", {})

        PRIMARY = colors.HexColor(hex_color)
        VERDICT_COLORS = {
            "malicious": colors.HexColor("#DC2626"),
            "suspicious": colors.HexColor("#F59E0B"),
            "safe": colors.HexColor("#10B981"),
        }
        banner_color = VERDICT_COLORS.get(verdict, colors.HexColor("#475569"))
        DARK = colors.HexColor("#0F172A")
        GRAY = colors.HexColor("#475569")
        LIGHT_GRAY = colors.HexColor("#F1F5F9")
        WHITE = colors.HexColor("#FFFFFF")

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        doc = SimpleDocTemplate(
            tmp.name, pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm, topMargin=2.5*cm, bottomMargin=2.5*cm,
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("Title", parent=styles["Heading1"], fontSize=22, fontName="Helvetica-Bold",
            textColor=PRIMARY, spaceAfter=4, alignment=TA_LEFT)
        subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"], fontSize=9, textColor=GRAY,
            spaceAfter=4, alignment=TA_LEFT)
        section_style = ParagraphStyle("Section", parent=styles["Heading2"], fontSize=13, fontName="Helvetica-Bold",
            textColor=DARK, spaceBefore=14, spaceAfter=6)
        body_style = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, textColor=GRAY,
            spaceAfter=5, leading=14)
        small_style = ParagraphStyle("Small", parent=styles["Normal"], fontSize=7.5, textColor=GRAY)
        table_header = ParagraphStyle("TH", parent=styles["Normal"], fontSize=9, fontName="Helvetica-Bold",
            textColor=WHITE)
        table_cell  = ParagraphStyle("TC", parent=styles["Normal"], fontSize=9, textColor=DARK)

        story = []

        # ── Brand Header ──
        if logo_url:
            try:
                import urllib.request
                logo_data = BytesIO(urllib.request.urlopen(logo_url, timeout=5).read())
                logo_img = Image(logo_data, width=3*cm, height=1.5*cm)
                story.append(logo_img)
                story.append(Spacer(1, 0.2*cm))
            except Exception:
                pass

        if company:
            story.append(Paragraph(company, ParagraphStyle("CompanyName",
                fontSize=14, fontName="Helvetica-Bold", textColor=PRIMARY)))
            story.append(Spacer(1, 0.1*cm))

        story.append(Paragraph("EMAIL THREAT ANALYSIS REPORT", title_style))
        story.append(Paragraph(f"Scan ID: {scan_id[:16]}... | {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", subtitle_style))
        story.append(Spacer(1, 0.2*cm))
        story.append(HRFlowable(width="100%", thickness=1, color=LIGHT_GRAY))
        story.append(Spacer(1, 0.4*cm))

        # ── Verdict Banner ──
        banner_data = [[
            Paragraph(f"STATUS: {verdict.upper()}", ParagraphStyle("BT", fontSize=15, fontName="Helvetica-Bold",
                textColor=WHITE, alignment=TA_LEFT)),
            Paragraph(f"Risk Score: {score}/100", ParagraphStyle("BS", fontSize=15, fontName="Helvetica-Bold",
                textColor=WHITE, alignment=TA_RIGHT)),
        ]]
        bt = Table(banner_data, colWidths=[8*cm, 8*cm])
        bt.setStyle(TableStyle([("BACKGROUND", (0,0),(-1,-1), banner_color), ("PADDING",(0,0),(-1,-1),10),
            ("LEFTPADDING",(0,0),(0,-1),16), ("RIGHTPADDING",(1,0),(1,-1),16)]))
        story.append(bt)
        story.append(Spacer(1, 0.4*cm))

        # ── Summary ──
        story.append(Paragraph("Executive Summary", section_style))
        summary = data.get("analysis_summary") or data.get("summary")
        story.append(Paragraph(summary or "No summary available.", body_style))
        story.append(Spacer(1, 0.3*cm))

        # ── Metadata Table ──
        story.append(Paragraph("Email Metadata", section_style))
        rows = [[Paragraph("Field", table_header), Paragraph("Value", table_header)]]
        for label, val in [("Verdict", verdict.upper()), ("From", meta.get("sender","N/A")),
            ("To", meta.get("recipient","N/A")), ("Subject", meta.get("subject","N/A")),
            ("Date", meta.get("date","N/A")), ("Domain", meta.get("sender_domain","N/A"))]:
            rows.append([Paragraph(label, table_cell), Paragraph(str(val), table_cell)])
        mt = Table(rows, colWidths=[3*cm, 14*cm])
        mt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0), PRIMARY), ("TEXTCOLOR",(0,0),(-1,0), WHITE),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,0),10),
            ("PADDING",(0,0),(-1,-1),7), ("BACKGROUND",(0,1),(-1,-1), LIGHT_GRAY),
            ("BACKGROUND",(0,2),(-1,-1), WHITE), ("GRID",(0,0),(-1,-1),0.5, GRAY),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"), ("LEFTPADDING",(0,0),(-1,-1),8),
            ("BOTTOMPADDING",(0,0),(-1,-1),6), ("TOPPADDING",(0,0),(-1,-1),6)]))
        story.append(mt)
        story.append(Spacer(1, 0.3*cm))

        # ── IOCs ──
        iocs = data.get("iocs", [])
        if iocs:
            story.append(Paragraph(f"Indicators of Compromise ({len(iocs)})", section_style))
            rows = [[Paragraph("Type", table_header), Paragraph("Value", table_header), Paragraph("Risk", table_header)]]
            for ioc in iocs[:30]:
                rows.append([Paragraph(str(ioc.get("type","")).upper(), table_cell),
                    Paragraph(str(ioc.get("value","N/A")), table_cell),
                    Paragraph(str(ioc.get("risk","")).upper(), table_cell)])
            it = Table(rows, colWidths=[2.5*cm, 12*cm, 3*cm])
            it.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0), PRIMARY), ("TEXTCOLOR",(0,0),(-1,0), WHITE),
                ("GRID",(0,0),(-1,-1),0.5, GRAY), ("PADDING",(0,0),(-1,-1),6),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"), ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                ("BACKGROUND",(0,1),(-1,-1), WHITE), ("BACKGROUND",(0,2),(-1,-1), LIGHT_GRAY),
                ("BOTTOMPADDING",(0,0),(-1,-1),5), ("TOPPADDING",(0,0),(-1,-1),5)]))
            story.append(it)
            story.append(Spacer(1, 0.3*cm))

        # ── Recommendations ──
        recs = data.get("recommendations") or []
        if recs:
            story.append(Paragraph("Recommendations", section_style))
            for r in recs:
                story.append(Paragraph(f"• {r}", body_style))
        elif verdict == "malicious":
            story.append(Paragraph("Recommendations", section_style))
            for r in ["Do not click any links or attachments in this email.",
                "Report to your security team immediately.",
                "Block the sender domain."]:
                story.append(Paragraph(f"• {r}", body_style))

        # ── Branded Footer ──
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_GRAY))
        story.append(Spacer(1, 0.15*cm))
        if footer_txt:
            story.append(Paragraph(footer_txt, small_style))
        story.append(Paragraph(
            f"{company} | {datetime.now().strftime('%Y-%m-%d %H:%M UTC')} | Scan: {scan_id[:16]}...",
            small_style))
        story.append(Paragraph(
            "This report is for informational purposes only. Consult your security team for final decisions.",
            small_style))

        doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
        return FileResponse(tmp.name, media_type="application/pdf",
            filename=f"threat_report_{scan_id[:8]}.pdf")
    except ImportError:
        raise HTTPException(500, "PDF generation unavailable")
    except Exception as e:
        raise HTTPException(500, f"PDF error: {str(e)}")


# ── Shareable Links ────────────────────────────────────────────────────────────
@router.post("/share/{scan_id}")
def create_share_link(scan_id: str, body: dict = Body(default={}),
    db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    hours = min(max(body.get("hours", 24), 1), 168)  # 1h–168h
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=hours)
    sl = ShareLink(scan_id=scan_id, token=token, expires_at=expires_at,
        views_left=1, created_by=user.id)
    db.add(sl)
    db.commit()
    base_url = os.environ.get("BASE_URL", "http://localhost:8000")
    return {"url": f"{base_url}/api/share/{token}", "expires_at": expires_at.isoformat()}

@router.get("/share/{token}")
def view_shared(token: str, db: Session = Depends(get_db)):
    sl = db.query(ShareLink).filter(ShareLink.token == token).first()
    if not sl:
        raise HTTPException(404, "Link not found or expired")
    if datetime.utcnow() > sl.expires_at or sl.views_left <= 0:
        raise HTTPException(410, "This link has expired")
    rep = db.query(ThreatReport).filter(ThreatReport.scan_id == sl.scan_id).first()
    if not rep:
        raise HTTPException(404, "Report not found")
    sl.views_left = max(0, sl.views_left - 1)
    db.commit()
    raw = rep.report_json
    return JSONResponse(content=json.loads(raw) if isinstance(raw, str) else raw)


# ── Excel/CSV Export ───────────────────────────────────────────────────────────
@router.get("/export/history")
def export_history(
    format: str = Query("csv", regex="^(csv|xlsx)$"),
    db: Session = Depends(get_db), user: User = Depends(get_current_user),
):
    records = db.query(ScanRecord).filter(ScanRecord.user_id == user.id).order_by(ScanRecord.created_at.desc()).limit(5000).all()

    if format == "csv":
        import csv, io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["scan_id","filename","sender","subject","verdict","risk_score",
            "url_count","attach_count","source","duration_s","created_at"])
        for r in records:
            w.writerow([r.scan_id, r.filename, r.sender, r.subject, r.verdict,
                r.risk_score, r.url_count, r.attach_count, r.source,
                r.duration_s, r.created_at.isoformat() if r.created_at else ""])
        buf.seek(0)
        from fastapi.responses import StreamingResponse
        import io as io_module
        return StreamingResponse(io_module.BytesIO(buf.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=scan_history_{datetime.now().strftime('%Y%m%d')}.csv"})

    # xlsx via openpyxl
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        wb = Workbook()
        ws = wb.active
        ws.title = "Scan History"

        hdrs = ["Scan ID","Filename","Sender","Subject","Verdict","Risk Score",
            "URL Count","Attachment Count","Source","Duration (s)","Created At"]
        hdr_fill = PatternFill("solid", fgColor="1E40AF")
        hdr_font = Font(bold=True, color="FFFFFF")
        for col, h in enumerate(hdrs, 1):
            c = ws.cell(row=1, column=col, value=h)
            c.font = hdr_font; c.fill = hdr_fill
            c.alignment = Alignment(horizontal="center")

        verdicts = {"malicious": "DC2626", "suspicious": "F59E0B", "safe": "10B981"}
        for row_idx, r in enumerate(records, 2):
            ws.cell(row=row_idx, column=1, value=r.scan_id)
            ws.cell(row=row_idx, column=2, value=r.filename)
            ws.cell(row=row_idx, column=3, value=r.sender)
            ws.cell(row=row_idx, column=4, value=r.subject)
            vc = ws.cell(row=row_idx, column=5, value=r.verdict)
            if r.verdict and r.verdict.lower() in verdicts:
                vc.font = Font(bold=True, color=verdicts[r.verdict.lower()])
            ws.cell(row=row_idx, column=6, value=r.risk_score)
            ws.cell(row=row_idx, column=7, value=r.url_count)
            ws.cell(row=row_idx, column=8, value=r.attach_count)
            ws.cell(row=row_idx, column=9, value=r.source)
            ws.cell(row=row_idx, column=10, value=r.duration_s)
            ws.cell(row=row_idx, column=11, value=r.created_at.isoformat() if r.created_at else "")

        ws.column_dimensions["A"].width = 12
        ws.column_dimensions["B"].width = 30
        ws.column_dimensions["C"].width = 25
        ws.column_dimensions["D"].width = 35
        ws.column_dimensions["E"].width = 12
        ws.column_dimensions["F"].width = 12
        ws.freeze_panes = "A2"

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx")
        wb.save(tmp.name)
        return FileResponse(tmp.name, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            filename=f"scan_history_{datetime.now().strftime('%Y%m%d')}.xlsx")
    except ImportError:
        raise HTTPException(500, "openpyxl not installed — run: pip install openpyxl")


# ── Analytics Export ───────────────────────────────────────────────────────────
@router.get("/export/analytics")
def export_analytics(
    db: Session = Depends(get_db), user: User = Depends(get_current_user),
):
    stats_total = db.query(func.count(ScanRecord.id)).filter(ScanRecord.user_id == user.id).scalar() or 0
    stats_mal   = db.query(func.count(ScanRecord.id)).filter(ScanRecord.user_id == user.id, ScanRecord.verdict == "malicious").scalar() or 0
    stats_sus   = db.query(func.count(ScanRecord.id)).filter(ScanRecord.user_id == user.id, ScanRecord.verdict == "suspicious").scalar() or 0
    stats_safe  = db.query(func.count(ScanRecord.id)).filter(ScanRecord.user_id == user.id, ScanRecord.verdict == "safe").scalar() or 0
    stats_avg   = db.query(func.avg(ScanRecord.risk_score)).filter(ScanRecord.user_id == user.id).scalar() or 0
    stats_mr    = round((stats_mal / max(1, stats_total)) * 100, 1)
    recent = db.query(ScanRecord).filter(ScanRecord.user_id == user.id).order_by(ScanRecord.created_at.desc()).limit(20).all()
    stats_trend = [{"date": r.created_at.strftime("%m/%d"), "score": round(r.risk_score, 1), "verdict": r.verdict, "total": 1, "malicious": 1 if r.verdict == "malicious" else 0}
                   for r in reversed(recent)]
    stats = {"total": stats_total, "malicious": stats_mal, "suspicious": stats_sus, "safe": stats_safe,
             "avg_score": round(float(stats_avg), 1), "malicious_rate": stats_mr, "trend": stats_trend}
    try:
        from openpyxl import Workbook
        from openpyxl.chart import BarChart, Reference, PieChart
        from openpyxl.styles import Font, PatternFill, Alignment
        wb = Workbook()
        ws = wb.active
        ws.title = "Analytics Summary"
        ws.cell(row=1, column=1, value="ETA Analytics Report").font = Font(bold=True, size=14)
        ws.cell(row=2, column=1, value=datetime.now().strftime("%Y-%m-%d %H:%M")).font = Font(size=9, color="666666")

        labels = ["Total Scans","Malicious","Suspicious","Safe","Avg Risk Score","Malicious Rate (%)"]
        values = [stats["total"], stats["malicious"], stats["suspicious"], stats["safe"],
            stats["avg_score"], stats["malicious_rate"]]
        for i, (l, v) in enumerate(zip(labels, values)):
            ws.cell(row=4+i, column=1, value=l).font = Font(bold=True)
            ws.cell(row=4+i, column=2, value=v)
        ws.column_dimensions["A"].width = 22
        ws.column_dimensions["B"].width = 18

        # Trend sheet
        if stats.get("trend"):
            ws2 = wb.create_sheet("Trend")
            ws2.cell(row=1, column=1, value="Daily Trend").font = Font(bold=True)
            ws2.cell(row=2, column=1, value="Date")
            ws2.cell(row=2, column=2, value="Malicious")
            ws2.cell(row=2, column=3, value="Total")
            for i, t in enumerate(stats["trend"]):
                ws2.cell(row=3+i, column=1, value=t.get("date",""))
                ws2.cell(row=3+i, column=2, value=t.get("malicious",0))
                ws2.cell(row=3+i, column=3, value=t.get("total",0))

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx")
        wb.save(tmp.name)
        return FileResponse(tmp.name, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            filename=f"analytics_{datetime.now().strftime('%Y%m%d')}.xlsx")
    except ImportError:
        raise HTTPException(500, "openpyxl not installed")