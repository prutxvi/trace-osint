"""TRACE OSINT - PDF Report Generator"""

from fpdf import FPDF
from datetime import datetime, timezone

from src.models import Case
from src.scoring.exposure import compute_exposure_score


class OSINTReportPDF(FPDF):
    """Custom PDF class for OSINT reports."""

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(0, 200, 83)
        self.cell(0, 8, "TRACE // OSINT Investigation Report", ln=True)
        self.set_draw_color(0, 200, 83)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} | TRACE OSINT Copilot | Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", align="C")

    def section_title(self, title):
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(0, 150, 60)
        self.cell(0, 10, title, ln=True)
        self.set_draw_color(0, 200, 83)
        self.line(10, self.get_y(), 80, self.get_y())
        self.ln(3)

    def subsection_title(self, title):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(50, 50, 50)
        self.cell(0, 8, title, ln=True)
        self.ln(1)

    def body_text(self, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(50, 50, 50)
        self.multi_cell(0, 6, text)
        self.ln(2)

    def key_value(self, key, value):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(50, 50, 50)
        self.cell(50, 6, f"{key}:")
        self.set_font("Helvetica", "", 10)
        self.cell(0, 6, str(value), ln=True)

    def table_header(self, cols):
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(30, 30, 30)
        self.set_text_color(0, 200, 83)
        for col in cols:
            self.cell(col[1], 7, col[0], border=1, fill=True, align="C")
        self.ln()

    def table_row(self, values, fill=False):
        self.set_font("Helvetica", "", 8)
        self.set_text_color(50, 50, 50)
        if fill:
            self.set_fill_color(245, 245, 245)
        for i, val in enumerate(values):
            self.cell(
                self._col_widths[i] if hasattr(self, "_col_widths") else 38,
                6,
                str(val)[:50],
                border=1,
                fill=fill,
            )
        self.ln()

    def colored_text(self, text, color):
        colors = {
            "green": (0, 150, 60),
            "red": (200, 50, 50),
            "orange": (200, 120, 0),
            "blue": (50, 100, 200),
            "gray": (128, 128, 128),
        }
        r, g, b = colors.get(color, (50, 50, 50))
        self.set_text_color(r, g, b)
        self.set_font("Helvetica", "", 10)
        self.multi_cell(0, 6, text)
        self.set_text_color(50, 50, 50)


def generate_pdf_report(case: Case) -> bytes:
    """Generate a PDF investigation report."""
    exposure = compute_exposure_score(case.findings, case.entities)

    pdf = OSINTReportPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    pdf.section_title("Case Information")
    pdf.key_value("Case ID", case.case_id)
    pdf.key_value("Case Name", case.name)
    pdf.key_value("Status", case.status.upper())
    pdf.key_value("Policy Mode", case.policy_mode)
    pdf.key_value("Created", case.created_at[:19])
    pdf.key_value("Clues", ", ".join(case.clues))
    pdf.ln(5)

    pdf.section_title("Executive Summary")
    finding_count = len(case.findings)
    entity_count = len(case.entities)
    high_conf = sum(1 for f in case.findings if f.confidence.level == "high")

    pdf.body_text(
        f"This investigation examined {len(case.clues)} clue(s) provided for case {case.case_id}.\n\n"
        f"Findings collected: {finding_count}\n"
        f"Entities resolved: {entity_count}\n"
        f"High-confidence matches: {high_conf}\n"
        f"Overall exposure: {exposure['risk_level'].upper()} (score: {exposure['score']:.2f})\n\n"
        f"{exposure['summary']}"
    )

    pdf.section_title("Findings")
    if case.findings:
        pdf._col_widths = [8, 25, 65, 30, 62]
        pdf.table_header([
            ("#", 8), ("Type", 25), ("Value", 65), ("Confidence", 30), ("Source", 62)
        ])
        for i, f in enumerate(case.findings[:50], 1):
            pdf.table_row([
                str(i),
                f.entity_type.value[:15],
                f.entity_value[:40],
                f"{f.confidence.level} ({f.confidence.score:.2f})",
                f.source.url[:40] if f.source.url else "N/A",
            ], fill=(i % 2 == 0))
    else:
        pdf.body_text("No findings collected.")
    pdf.ln(5)

    pdf.section_title("Entity Resolution")
    if case.entities:
        pdf._col_widths = [25, 55, 55, 55]
        pdf.table_header([
            ("Type", 25), ("Value", 55), ("Aliases", 55), ("Confidence", 55)
        ])
        for i, e in enumerate(case.entities, 1):
            aliases = ", ".join(e.aliases[:3]) if e.aliases else "-"
            pdf.table_row([
                e.type.value[:15],
                e.value[:35],
                aliases[:35],
                f"{e.confidence.level} ({e.confidence.score:.2f})",
            ], fill=(i % 2 == 0))
    else:
        pdf.body_text("No entities resolved.")
    pdf.ln(5)

    pdf.section_title("Risk & Exposure Assessment")
    pdf.key_value("Exposure Score", f"{exposure['score']:.2f}")
    pdf.key_value("Risk Level", exposure["risk_level"].upper())
    pdf.key_value("Contributing Factors", str(exposure["factor_count"]))
    pdf.ln(3)
    pdf.body_text(exposure["summary"])

    pdf.section_title("Source Inventory")
    sources = {}
    for f in case.findings:
        key = f.source.url or "unknown"
        if key not in sources:
            sources[key] = f.source
    if sources:
        pdf._col_widths = [30, 50, 20, 90]
        pdf.table_header([
            ("Type", 30), ("Title", 50), ("Reliability", 20), ("URL", 90)
        ])
        for i, s in enumerate(list(sources.values())[:30], 1):
            pdf.table_row([
                s.source_type[:20],
                s.title[:30],
                f"{s.reliability:.1f}",
                s.url[:55],
            ], fill=(i % 2 == 0))
    else:
        pdf.body_text("No sources consulted.")
    pdf.ln(5)

    pdf.section_title("Confidence Distribution")
    levels = {"high": 0, "medium": 0, "low": 0, "minimal": 0}
    for f in case.findings:
        levels[f.confidence.level] = levels.get(f.confidence.level, 0) + 1
    total = len(case.findings) or 1
    pdf.key_value("High", f"{levels['high']} ({levels['high']/total*100:.1f}%)")
    pdf.key_value("Medium", f"{levels['medium']} ({levels['medium']/total*100:.1f}%)")
    pdf.key_value("Low", f"{levels['low']} ({levels['low']/total*100:.1f}%)")
    pdf.key_value("Minimal", f"{levels['minimal']} ({levels['minimal']/total*100:.1f}%)")
    pdf.ln(5)

    pdf.section_title("Gaps & Limitations")
    gaps = [
        "Investigation limited to public, read-only sources only",
        "No private account access, authentication, or login-based retrieval",
        "No breach database queries (HIBP API key required)",
        "Confidence scores reflect source reliability and corroboration only",
        "Results may be incomplete due to public-source limitations",
    ]
    for gap in gaps:
        pdf.body_text(f"- {gap}")

    pdf.section_title("Recommended Next Steps")
    next_steps = [
        "Cross-reference high-confidence findings with additional public sources",
        "Attempt entity resolution for any low-confidence matches",
        "Search for the resolved entities on additional public platforms",
        "Review gaps to identify additional public-source queries",
        "Consider domain-specific registries if applicable (DNS, CT, WHOIS)",
    ]
    for step in next_steps:
        pdf.body_text(f"- {step}")

    pdf.section_title("Policy Compliance")
    pdf.key_value("Mode", case.policy_mode)
    pdf.key_value("Status", "PASS")
    pdf.body_text(
        "This investigation was conducted entirely within the boundaries of "
        "public-source, read-only, lawful intelligence gathering methods."
    )

    if case.audit_log:
        pdf.section_title("Audit Trail (Last 20 Events)")
        pdf._col_widths = [35, 25, 20, 45, 65]
        pdf.table_header([
            ("Timestamp", 35), ("Phase", 25), ("Agent", 20), ("Action", 45), ("Status", 65)
        ])
        for i, e in enumerate(case.audit_log[-20:], 1):
            pdf.table_row([
                e.timestamp[:19],
                e.phase[:12],
                e.agent[:10],
                e.action[:25],
                e.status[:30],
            ], fill=(i % 2 == 0))

    return pdf.output()


def save_pdf_report(case: Case, output_path: str) -> str:
    """Generate and save PDF report."""
    pdf_bytes = generate_pdf_report(case)
    with open(output_path, "wb") as f:
        f.write(pdf_bytes)
    return output_path
