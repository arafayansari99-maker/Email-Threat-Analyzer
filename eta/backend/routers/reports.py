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


def _assert_scan_owner(scan_id: str, user: User, db: Session):
    """Raise 403 if the authenticated user does not own the given scan."""
    scan = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(404, f"Report not found: {scan_id}")
    if scan.user_id != user.id:
        raise HTTPException(403, "Not authorized to access this report")


@router.get("/report/{scan_id}")
def get_report(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _assert_scan_owner(scan_id, current_user, db)
    rep = db.query(ThreatReport).filter(ThreatReport.scan_id == scan_id).first()
    if not rep:
        logger.warning(f"Report not found for scan_id: {scan_id}")
        raise HTTPException(404, f"Report not found: {scan_id}")
    return rep.report_json


@router.get("/report/{scan_id}/json")
def download_json(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _assert_scan_owner(scan_id, current_user, db)
    rep = db.query(ThreatReport).filter(ThreatReport.scan_id == scan_id).first()
    if not rep:
        raise HTTPException(404, "Report not found")

    raw = rep.report_json
    d = json.loads(raw) if isinstance(raw, str) else raw

    meta     = d.get("meta", {})
    header_a = d.get("header_analysis", {})
    url_a    = d.get("url_analysis", {})
    attach_a = d.get("attachment_analysis", {})
    ml_a     = d.get("ml_analysis", {})
    sem_a    = d.get("semantic_analysis", {})
    breakdown= d.get("breakdown", {})
    iocs     = d.get("iocs", [])
    recs     = d.get("recommendations", [])
    ti       = d.get("threat_intel", {})

    def _clean_recs(lst):
        return [r.replace("🚨","").replace("⚠️","").replace("✓","").strip() for r in lst]

    export = {
        "report_metadata": {
            "schema_version": "2.0",
            "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scan_id": d.get("scan_id", scan_id),
            "filename": d.get("filename", ""),
            "analysis_duration_seconds": d.get("duration"),
            "analysis_timestamp": d.get("timestamp"),
        },

        "summary": {
            "verdict": d.get("verdict", "unknown"),
            "risk_score": d.get("risk_score"),
            "analysis_summary": d.get("analysis_summary", ""),
            "recommendations": _clean_recs(recs),
        },

        "email_metadata": {
            "sender_display": meta.get("sender", ""),
            "sender_email":   meta.get("sender_email", ""),
            "sender_domain":  meta.get("sender_domain", ""),
            "recipient":      meta.get("recipient", ""),
            "subject":        meta.get("subject", ""),
            "date":           meta.get("date", ""),
            "reply_to":       meta.get("reply_to", ""),
        },

        "authentication": {
            "spf":   {"status": header_a.get("spf", "unknown"),  "score": header_a.get("auth_score")},
            "dkim":  {"status": header_a.get("dkim", "unknown")},
            "dmarc": {"status": header_a.get("dmarc", "unknown")},
        },

        "risk_breakdown": {
            "header_score":     breakdown.get("header"),
            "url_score":        breakdown.get("url"),
            "attachment_score": breakdown.get("attachment"),
            "ml_score":         breakdown.get("ml"),
            "semantic_score":   breakdown.get("semantic"),
            "total":            d.get("risk_score"),
        },

        "ml_analysis": {
            "classification":       ml_a.get("classification"),
            "phishing_probability": ml_a.get("phishing_probability"),
            "confidence":           ml_a.get("confidence"),
            "model":                ml_a.get("method"),
            "keywords_found": {
                "critical": ml_a.get("suspicious_keywords_found", {}).get("critical", []),
                "high":     ml_a.get("suspicious_keywords_found", {}).get("high", []),
                "total":    ml_a.get("suspicious_keywords_found", {}).get("total_detected", 0),
            },
            "shap_explanation": [
                {
                    "feature":      e.get("feature"),
                    "impact":       e.get("impact"),
                    "shap_value":   e.get("shap_value"),
                    "feature_value":e.get("feature_value"),
                }
                for e in ml_a.get("explanation", [])
            ],
        },

        "semantic_analysis": {
            "probability": sem_a.get("semantic_prob"),
            "method":      sem_a.get("method"),
            "top_tokens":  sem_a.get("top_tokens", []),
        } if sem_a.get("method") != "unavailable" else {"method": "unavailable"},

        "url_analysis": {
            "total":     url_a.get("total", 0),
            "malicious": url_a.get("malicious", 0),
            "suspicious":url_a.get("suspicious", 0),
            "safe":      url_a.get("safe", 0),
            "risk_score":url_a.get("score", 0),
            "urls": [
                {
                    "url":     ua.get("url"),
                    "verdict": ua.get("verdict"),
                    "score":   ua.get("score"),
                    "flags":   ua.get("flags", []),
                }
                for ua in url_a.get("analyses", [])
            ],
        },

        "attachment_analysis": {
            "count":      attach_a.get("count", 0),
            "risk_score": attach_a.get("score", 0),
            "attachments": [
                {
                    "filename":     a.get("filename"),
                    "content_type": a.get("content_type"),
                    "size_bytes":   a.get("size_bytes"),
                    "extension":    a.get("extension"),
                    "risk":         a.get("risk"),
                    "md5":          a.get("md5"),
                    "sha256":       a.get("sha256"),
                    "is_malicious_extension": a.get("is_malicious_ext", False),
                    "is_risky_extension":     a.get("is_risky_ext", False),
                }
                for a in attach_a.get("all", [])
            ],
            "indicators": attach_a.get("indicators", []),
        },

        "header_indicators": [
            {
                "type":     ind.get("type"),
                "severity": ind.get("severity"),
                "description": ind.get("desc"),
            }
            for ind in header_a.get("indicators", [])
        ],

        "indicators_of_compromise": [
            {
                "type":     ioc.get("type"),
                "value":    ioc.get("value"),
                "filename": ioc.get("filename"),  # only present for hash IOCs
            }
            for ioc in iocs
        ],

        "threat_intelligence": ti if ti and not ti.get("skipped") else {
            "status": ti.get("skipped", "not requested"),
        },
    }

    # Remove keys with None values at top level for cleaner output
    export = {k: v for k, v in export.items() if v is not None}

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode='w', encoding='utf-8')
    json.dump(export, tmp, indent=2, ensure_ascii=False, default=str)
    tmp.close()

    return FileResponse(
        tmp.name,
        media_type="application/json",
        filename=f"threat_report_{d.get('scan_id', scan_id)[:8]}.json",
        headers={"Content-Disposition": f'attachment; filename="threat_report_{scan_id[:8]}.json"'},
    )


@router.post("/report/{scan_id}/pdf")
def generate_pdf(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _assert_scan_owner(scan_id, current_user, db)
    rep = db.query(ThreatReport).filter(ThreatReport.scan_id == scan_id).first()
    if not rep:
        raise HTTPException(404, "Report not found")

    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, KeepTogether,
        )
        from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER

        W = A4[0] - 5*cm  # usable width (2.5cm margins each side)

        # ── Colour palette ────────────────────────────────────────────────────
        PRIMARY    = colors.HexColor("#1E40AF")
        DARK       = colors.HexColor("#0F172A")
        GRAY       = colors.HexColor("#475569")
        LIGHT_GRAY = colors.HexColor("#F1F5F9")
        MID_GRAY   = colors.HexColor("#E2E8F0")
        WHITE      = colors.HexColor("#FFFFFF")
        RED        = colors.HexColor("#DC2626")
        ORANGE     = colors.HexColor("#F59E0B")
        GREEN      = colors.HexColor("#10B981")
        BLUE       = colors.HexColor("#3B82F6")
        PURPLE     = colors.HexColor("#8B5CF6")

        raw_data = rep.report_json
        data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data

        verdict  = (data.get("verdict") or "unknown").lower()
        score    = data.get("risk_score", 0)
        meta     = data.get("meta", {})
        header_a = data.get("header_analysis", {})
        url_a    = data.get("url_analysis", {})
        attach_a = data.get("attachment_analysis", {})
        ml_a     = data.get("ml_analysis", {})
        iocs     = data.get("iocs", [])
        recs     = data.get("recommendations", [])
        breakdown= data.get("breakdown", {})

        VERDICT_COLOR = {"malicious": RED, "suspicious": ORANGE, "safe": GREEN}.get(verdict, GRAY)

        # ── Styles ────────────────────────────────────────────────────────────
        SS = getSampleStyleSheet()
        def sty(name, **kw):
            base = kw.pop("parent", SS["Normal"])
            return ParagraphStyle(name, parent=base, **kw)

        title_sty    = sty("T", parent=SS["Heading1"], fontSize=22, fontName="Helvetica-Bold", textColor=PRIMARY, spaceAfter=4)
        sub_sty      = sty("S", fontSize=9, textColor=GRAY, spaceAfter=3)
        sec_sty      = sty("Sec", parent=SS["Heading2"], fontSize=13, fontName="Helvetica-Bold", textColor=DARK, spaceBefore=14, spaceAfter=6)
        body_sty     = sty("B", fontSize=9.5, textColor=GRAY, spaceAfter=4, leading=14)
        small_sty    = sty("Sm", fontSize=7.5, textColor=GRAY)
        th_sty       = sty("TH", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)
        td_sty       = sty("TD", fontSize=9, textColor=DARK)
        td_gray_sty  = sty("TDG", fontSize=9, textColor=GRAY)
        badge_sty    = sty("Badge", fontSize=11, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER)
        score_sty    = sty("Score", fontSize=28, fontName="Helvetica-Bold", textColor=VERDICT_COLOR, alignment=TA_CENTER)
        rec_sty      = sty("Rec", fontSize=9, textColor=DARK, spaceAfter=3, leading=13)

        def hr(): return HRFlowable(width="100%", thickness=0.5, color=MID_GRAY, spaceAfter=4)
        def section(title): return Paragraph(title, sec_sty)
        def th(t): return Paragraph(t, th_sty)
        def td(t): return Paragraph(str(t), td_sty)
        def tdg(t): return Paragraph(str(t), td_gray_sty)

        def _auth_color(status):
            s = (status or "").lower()
            if s == "pass":   return GREEN
            if s in ("fail", "softfail"): return RED
            return GRAY

        def _ioc_color(itype):
            return {"url": BLUE, "domain": PURPLE, "ip": ORANGE, "hash": RED}.get(itype, GRAY)

        def _risk_color(risk):
            r = (risk or "").lower()
            if r == "malicious": return RED
            if r == "suspicious": return ORANGE
            return GREEN

        # ── Page callbacks ────────────────────────────────────────────────────
        def _header_footer(canvas, doc):
            canvas.saveState()
            canvas.setFont("Helvetica", 7.5)
            canvas.setFillColor(GRAY)
            canvas.drawString(2.5*cm, 0.8*cm, "ETA Email Threat Analyzer — Confidential")
            canvas.drawRightString(A4[0]-2.5*cm, 0.8*cm, f"Page {doc.page}")
            canvas.setStrokeColor(MID_GRAY)
            canvas.setLineWidth(0.5)
            canvas.line(2.5*cm, 1.1*cm, A4[0]-2.5*cm, 1.1*cm)
            canvas.restoreState()

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        doc = SimpleDocTemplate(
            tmp.name, pagesize=A4,
            rightMargin=2.5*cm, leftMargin=2.5*cm,
            topMargin=2*cm, bottomMargin=1.8*cm,
        )

        story = []

        # ── HEADER ───────────────────────────────────────────────────────────
        story.append(Paragraph("EMAIL THREAT ANALYSIS REPORT", title_sty))
        story.append(Paragraph(
            f"Scan ID: {scan_id[:24]}...  |  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
            sub_sty,
        ))
        story.append(hr())
        story.append(Spacer(1, 0.3*cm))

        # ── VERDICT BANNER (3-column: status | score gauge | ML prob) ────────
        ml_prob = round(ml_a.get("phishing_probability", 0) * 100)
        banner_rows = [[
            Paragraph(f"STATUS\n{verdict.upper()}", sty("BV", fontSize=15, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER, leading=20)),
            Paragraph(f"{score}/100\nRISK SCORE",    sty("BS", fontSize=15, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER, leading=20)),
            Paragraph(f"{ml_prob}%\nML PHISHING",    sty("BM", fontSize=15, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER, leading=20)),
        ]]
        bt = Table(banner_rows, colWidths=[W/3, W/3, W/3])
        bt.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), VERDICT_COLOR),
            ("TOPPADDING",   (0,0), (-1,-1), 14),
            ("BOTTOMPADDING",(0,0), (-1,-1), 14),
            ("LEFTPADDING",  (0,0), (-1,-1), 14),
            ("RIGHTPADDING", (0,0), (-1,-1), 14),
            ("LINEAFTER",    (0,0), (1,-1),  0.5, WHITE),
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ]))
        story.append(bt)
        story.append(Spacer(1, 0.5*cm))

        # ── EXECUTIVE SUMMARY ────────────────────────────────────────────────
        story.append(KeepTogether([
            section("Executive Summary"),
            Paragraph(data.get("analysis_summary") or "Email analyzed for potential threats.", body_sty),
            Spacer(1, 0.2*cm),
        ]))

        # ── RISK SCORE BREAKDOWN ──────────────────────────────────────────────
        bd = breakdown
        if any(v is not None for v in bd.values()):
            story.append(KeepTogether([
                section("Risk Score Breakdown"),
                Spacer(1, 0.1*cm),
            ]))
            bd_rows = [[th("Component"), th("Contribution"), th("Bar")]]
            components = [
                ("Header Analysis",    bd.get("header")),
                ("URL Analysis",       bd.get("url")),
                ("Attachment Analysis",bd.get("attachment")),
                ("ML Classifier",      bd.get("ml")),
                ("Semantic NLP",       bd.get("semantic")),
            ]
            for label, val in components:
                if val is None:
                    continue
                bar_w   = max(0.1, (val / 100) * (W - 5*cm))
                bar_tbl = Table([[""]], colWidths=[bar_w])
                bar_tbl.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,-1), VERDICT_COLOR),
                    ("TOPPADDING", (0,0),(-1,-1), 5),
                    ("BOTTOMPADDING",(0,0),(-1,-1), 5),
                ]))
                bd_rows.append([td(label), td(f"{val:.1f} pts"), bar_tbl])
            bd_tbl = Table(bd_rows, colWidths=[5*cm, 3*cm, W-8*cm])
            bd_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,0),  PRIMARY),
                ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
                ("GRID",          (0,0), (-1,-1), 0.3, MID_GRAY),
                ("PADDING",       (0,0), (-1,-1), 6),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ]))
            story.append(bd_tbl)
            story.append(Spacer(1, 0.4*cm))

        # ── EMAIL METADATA ───────────────────────────────────────────────────
        story.append(section("Email Metadata"))
        fields = [
            ("From",    meta.get("sender") or "N/A"),
            ("To",      meta.get("recipient") or "N/A"),
            ("Subject", meta.get("subject") or "N/A"),
            ("Date",    meta.get("date") or "N/A"),
            ("Domain",  meta.get("sender_domain") or "N/A"),
            ("Reply-To",meta.get("reply_to") or "N/A"),
        ]
        m_rows = [[th("Field"), th("Value")]]
        for label, val in fields:
            m_rows.append([td(label), tdg(val[:120] if len(str(val)) > 120 else val)])
        m_tbl = Table(m_rows, colWidths=[3*cm, W-3*cm])
        m_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  PRIMARY),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
            ("GRID",          (0,0), (-1,-1), 0.3, MID_GRAY),
            ("PADDING",       (0,0), (-1,-1), 7),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ]))
        story.append(m_tbl)
        story.append(Spacer(1, 0.4*cm))

        # ── EMAIL AUTHENTICATION ─────────────────────────────────────────────
        story.append(section("Email Authentication"))
        a_rows = [[th("Protocol"), th("Status"), th("Detail")]]
        for proto in [("SPF","spf"), ("DKIM","dkim"), ("DMARC","dmarc")]:
            lbl, key = proto
            status = header_a.get(key, "unknown") or "unknown"
            color  = _auth_color(status)
            badge  = Table([[Paragraph(status.upper(), sty("AB", fontSize=8, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER))]],
                           colWidths=[2*cm])
            badge.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),color),("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3)]))
            detail = {
                "spf":  "Sender Policy Framework — verifies sender IP is authorised",
                "dkim": "DomainKeys Identified Mail — verifies message integrity",
                "dmarc":"Domain-based Message Authentication — policy enforcement",
            }.get(key, "")
            a_rows.append([td(lbl), badge, tdg(detail)])
        a_tbl = Table(a_rows, colWidths=[2.5*cm, 2.5*cm, W-5*cm])
        a_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  PRIMARY),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
            ("GRID",          (0,0), (-1,-1), 0.3, MID_GRAY),
            ("PADDING",       (0,0), (-1,-1), 7),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ]))
        story.append(a_tbl)
        story.append(Spacer(1, 0.4*cm))

        # ── ML ANALYSIS ──────────────────────────────────────────────────────
        story.append(section("ML / AI Analysis"))
        ml_method = ml_a.get("method", "N/A")
        ml_class  = ml_a.get("classification", "N/A")
        ml_conf   = round(ml_a.get("confidence", 0) * 100)
        kw        = ml_a.get("suspicious_keywords_found", {})
        ml_rows   = [[th("Property"), th("Value")]]
        ml_rows  += [
            [td("Classification"),    tdg(ml_class.upper())],
            [td("Phishing Prob."),    tdg(f"{ml_prob}%")],
            [td("Confidence"),        tdg(f"{ml_conf}%")],
            [td("Model"),             tdg(ml_method)],
            [td("Critical Keywords"), tdg(", ".join(kw.get("critical", [])[:6]) or "None")],
            [td("High-Risk Keywords"),tdg(", ".join(kw.get("high", [])[:6]) or "None")],
            [td("Total Keywords"),    tdg(str(kw.get("total_detected", 0)))],
        ]
        explanation = ml_a.get("explanation", [])
        if explanation:
            top_feats = "; ".join(
                f"{e['feature']} ({'+' if e['impact']=='increases_risk' else '-'}{abs(e['shap_value']):.3f})"
                for e in explanation[:5]
            )
            ml_rows.append([td("Top SHAP Features"), tdg(top_feats)])
        ml_tbl = Table(ml_rows, colWidths=[4.5*cm, W-4.5*cm])
        ml_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  PRIMARY),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
            ("GRID",          (0,0), (-1,-1), 0.3, MID_GRAY),
            ("PADDING",       (0,0), (-1,-1), 7),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ]))
        story.append(ml_tbl)
        story.append(Spacer(1, 0.4*cm))

        # ── URL ANALYSIS ─────────────────────────────────────────────────────
        story.append(section(f"URL Analysis  ({url_a.get('total', 0)} URLs found)"))
        u_summary = [[th("Category"), th("Count"), th("Risk Score")]]
        u_summary += [
            [td("Malicious"),  tdg(str(url_a.get("malicious",0))),  tdg(f"{url_a.get('score',0)}/100")],
            [td("Suspicious"), tdg(str(url_a.get("suspicious",0))), tdg("")],
            [td("Safe"),       tdg(str(url_a.get("safe",0))),        tdg("")],
        ]
        u_sum_tbl = Table(u_summary, colWidths=[4*cm, 3*cm, W-7*cm])
        u_sum_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  PRIMARY),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
            ("GRID",          (0,0), (-1,-1), 0.3, MID_GRAY),
            ("PADDING",       (0,0), (-1,-1), 7),
        ]))
        story.append(u_sum_tbl)

        # High-risk URL detail table
        high_risk_urls = [a for a in url_a.get("analyses", []) if a.get("verdict") in ("malicious","suspicious")][:15]
        if high_risk_urls:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph("High-Risk URLs", sty("HR", fontSize=10, fontName="Helvetica-Bold", textColor=DARK, spaceAfter=4)))
            u_rows = [[th("URL"), th("Score"), th("Verdict"), th("Flags")]]
            for ua in high_risk_urls:
                url_str = ua.get("url","")
                url_display = (url_str[:65] + "...") if len(url_str) > 65 else url_str
                vc = _risk_color(ua.get("verdict"))
                vbadge = Table([[Paragraph(ua.get("verdict","").upper(), sty("VB", fontSize=7, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER))]],
                               colWidths=[2*cm])
                vbadge.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),vc),("TOPPADDING",(0,0),(-1,-1),2),("BOTTOMPADDING",(0,0),(-1,-1),2)]))
                flags_str = "; ".join(ua.get("flags",[])[:3])
                u_rows.append([tdg(url_display), td(str(ua.get("score",0))), vbadge, tdg(flags_str[:60])])
            u_tbl = Table(u_rows, colWidths=[6.5*cm, 1.5*cm, 2.5*cm, W-10.5*cm])
            u_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,0),  PRIMARY),
                ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
                ("GRID",          (0,0), (-1,-1), 0.3, MID_GRAY),
                ("PADDING",       (0,0), (-1,-1), 5),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
                ("FONTSIZE",      (0,1), (-1,-1), 8),
            ]))
            story.append(u_tbl)
        story.append(Spacer(1, 0.4*cm))

        # ── ATTACHMENT ANALYSIS ───────────────────────────────────────────────
        attach_all = attach_a.get("all", [])
        if attach_all:
            story.append(section(f"Attachment Analysis  ({attach_a.get('count', 0)} attachments)"))
            att_rows = [[th("Filename"), th("Type"), th("Size"), th("Risk")]]
            for att in attach_all[:10]:
                rc = _risk_color(att.get("risk","safe"))
                rbadge = Table([[Paragraph((att.get("risk") or "safe").upper(), sty("RB", fontSize=7, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER))]],
                               colWidths=[2*cm])
                rbadge.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),rc),("TOPPADDING",(0,0),(-1,-1),2),("BOTTOMPADDING",(0,0),(-1,-1),2)]))
                att_rows.append([
                    tdg(att.get("filename","?")[:50]),
                    tdg(att.get("content_type","?")[:30]),
                    tdg(f"{att.get('size_kb',0)} KB"),
                    rbadge,
                ])
            att_tbl = Table(att_rows, colWidths=[6*cm, 4*cm, 2*cm, 2.5*cm])
            att_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,0),  PRIMARY),
                ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
                ("GRID",          (0,0), (-1,-1), 0.3, MID_GRAY),
                ("PADDING",       (0,0), (-1,-1), 6),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ]))
            story.append(att_tbl)
            story.append(Spacer(1, 0.4*cm))

        # ── INDICATORS OF COMPROMISE ─────────────────────────────────────────
        if iocs:
            story.append(section(f"Indicators of Compromise  ({len(iocs)})"))
            ioc_rows = [[th("Type"), th("Indicator")]]
            for ioc in iocs[:40]:
                itype = ioc.get("type","?")
                ival  = ioc.get("value","?")
                c = _ioc_color(itype)
                type_badge = Table([[Paragraph(itype.upper(), sty("IB", fontSize=7, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER))]],
                                   colWidths=[1.8*cm])
                type_badge.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),c),("TOPPADDING",(0,0),(-1,-1),2),("BOTTOMPADDING",(0,0),(-1,-1),2)]))
                display_val = (ival[:90]+"...") if len(str(ival)) > 90 else str(ival)
                ioc_rows.append([type_badge, tdg(display_val)])
            ioc_tbl = Table(ioc_rows, colWidths=[2.2*cm, W-2.2*cm])
            ioc_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,0),  PRIMARY),
                ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
                ("GRID",          (0,0), (-1,-1), 0.3, MID_GRAY),
                ("PADDING",       (0,0), (-1,-1), 5),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
                ("FONTSIZE",      (0,1), (-1,-1), 8),
            ]))
            story.append(ioc_tbl)
            if len(iocs) > 40:
                story.append(Paragraph(f"... and {len(iocs)-40} more IOCs (truncated for readability)", small_sty))
            story.append(Spacer(1, 0.4*cm))

        # ── HEADER INDICATORS ────────────────────────────────────────────────
        h_indicators = header_a.get("indicators", [])
        if h_indicators:
            story.append(section("Header Threat Indicators"))
            hi_rows = [[th("Severity"), th("Type"), th("Description")]]
            sev_colors = {"critical": RED, "high": ORANGE, "medium": colors.HexColor("#EAB308"), "low": BLUE}
            for ind in h_indicators[:15]:
                sev = ind.get("severity","low")
                sc  = sev_colors.get(sev, GRAY)
                sev_badge = Table([[Paragraph(sev.upper(), sty("SB", fontSize=7, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER))]],
                                  colWidths=[1.8*cm])
                sev_badge.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),sc),("TOPPADDING",(0,0),(-1,-1),2),("BOTTOMPADDING",(0,0),(-1,-1),2)]))
                hi_rows.append([sev_badge, tdg(ind.get("type","?")[:25]), tdg(ind.get("desc","")[:80])])
            hi_tbl = Table(hi_rows, colWidths=[2.2*cm, 3.5*cm, W-5.7*cm])
            hi_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,0),  PRIMARY),
                ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
                ("GRID",          (0,0), (-1,-1), 0.3, MID_GRAY),
                ("PADDING",       (0,0), (-1,-1), 5),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ]))
            story.append(hi_tbl)
            story.append(Spacer(1, 0.4*cm))

        # ── RECOMMENDATIONS ──────────────────────────────────────────────────
        if recs:
            story.append(section("Recommendations"))
            for i, r in enumerate(recs, 1):
                clean = r.replace("🚨","").replace("⚠️","").replace("✓","").strip()
                story.append(Paragraph(f"{i}.  {clean}", rec_sty))
            story.append(Spacer(1, 0.3*cm))

        # ── FOOTER ───────────────────────────────────────────────────────────
        story.append(hr())
        story.append(Paragraph(
            f"ETA Email Threat Analyzer  |  Scan: {scan_id[:24]}...  |  {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
            small_sty,
        ))
        story.append(Paragraph(
            "This report is generated automatically and is for informational purposes only. "
            "Consult your security team before taking action.",
            small_sty,
        ))

        doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
        return FileResponse(tmp.name, media_type="application/pdf",
                            filename=f"threat_report_{scan_id[:8]}.pdf")

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
    _assert_scan_owner(scan_id, user, db)
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
    _assert_scan_owner(scan_id, user, db)
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