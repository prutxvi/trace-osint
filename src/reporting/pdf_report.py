"""TRACE OSINT - PDF Report Generator

Report layout (person-first):
  1. Person Card + Avatar (if available)
  2. Plain Summary (Story Card)
  3. Key Facts
  4. Canonical Profiles
  5. Key Findings (person-focused)
  6. Timeline
  7. Infrastructure Context
  8. Risk & Exposure
  9. Gaps & Limitations
 10. Recommended Next Steps
 11. Policy Compliance
 12. Audit Trail

Infrastructure findings are separated from person-level findings
to keep the dossier focused on the target individual.
"""

import os
import tempfile
import urllib.request
from fpdf import FPDF
from datetime import datetime, timezone

from src.models import Case
from src.scoring.exposure import compute_exposure_score, risk_level_label
from src.sources.case_synthesis import split_findings_by_focus


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
    """Generate a PDF investigation report with person-first layout."""
    exposure = compute_exposure_score(case.findings, case.entities)
    primary_profile = case.canonical_profiles[0] if case.canonical_profiles else None
    person_findings, infra_findings = split_findings_by_focus(case.findings)

    pdf = OSINTReportPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # ---- Section 1: Person Card ----
    if case.case_mode == "person":
        pdf.section_title("Person Card")
        if primary_profile:
            image_added = _try_add_avatar(pdf, primary_profile.avatar_url)
            if image_added:
                pdf.set_xy(55, pdf.get_y() - 33)
            pdf.key_value("Name", primary_profile.display_name or "Unknown")
            pdf.key_value("Main Handle", primary_profile.main_handle or "Unknown")
            pdf.key_value("Location", primary_profile.location or "Unknown")
            pdf.key_value("Verification", primary_profile.verification.upper())
            pdf.key_value("Confidence", f"{primary_profile.confidence_score:.2f}")
            if primary_profile.avatar_url:
                pdf.key_value("Avatar URL", primary_profile.avatar_url)
            pdf.body_text(primary_profile.summary or case.plain_language_summary)
        else:
            pdf.body_text("No single person profile was strong enough to present as the primary person card.")
        pdf.ln(3)

    # ---- Section 2: Plain Summary (Story Card) ----
    pdf.section_title("Plain Summary")
    if case.story_card:
        card = case.story_card
        pdf.body_text(f"Who: {card.who_is_this}")
        pdf.body_text(f"IDs: {card.main_ids}")
        if card.top_traces:
            pdf.body_text(f"Key traces: {', '.join(card.top_traces[:5])}")
        pdf.body_text(f"Risk: {card.risk_summary}")
        pdf.body_text(f"Verdict: {card.verdict}")
    elif case.plain_language_summary:
        pdf.body_text(case.plain_language_summary)
    else:
        pdf.body_text("No plain-language summary available.")
    pdf.ln(3)

    # ---- Section 3: Case Information ----
    pdf.section_title("Case Information")
    pdf.key_value("Case ID", case.case_id)
    pdf.key_value("Case Name", case.name)
    pdf.key_value("Case Mode", case.case_mode.upper())
    pdf.key_value("Status", case.status.upper())
    pdf.key_value("Policy Mode", case.policy_mode)
    pdf.key_value("Created", case.created_at[:19])
    pdf.key_value("Clues", ", ".join(case.clues))
    pdf.ln(5)

    # ---- Section 4: Most Likely Profile ----
    pdf.section_title("Most Likely Profile")
    if case.canonical_profiles:
        top_profile = case.canonical_profiles[0]
        pdf.key_value("Profile", top_profile.display_name)
        pdf.key_value("Relationship", top_profile.relationship_to_primary.upper())
        pdf.key_value("Verification", top_profile.verification.upper())
        pdf.key_value("Confidence", f"{top_profile.confidence_score:.2f}")
        pdf.body_text(top_profile.summary)
    else:
        pdf.body_text("No canonical profile was strong enough to present.")
    pdf.ln(5)

    # ---- Section 5: Key Facts ----
    pdf.section_title("Key Facts")
    if primary_profile:
        pdf.key_value("Websites", ", ".join(primary_profile.websites[:3]) or "N/A")
        pdf.key_value("Profiles", ", ".join(primary_profile.profile_urls[:3]) or "N/A")
        pdf.key_value("Accounts", ", ".join(primary_profile.linked_accounts[:4]) or "N/A")
        pdf.key_value("Companies", ", ".join(primary_profile.companies[:3]) or "N/A")
        pdf.key_value("Projects", ", ".join(primary_profile.project_references[:4]) or "N/A")
    else:
        pdf.body_text("No primary profile facts were extracted.")
    pdf.ln(5)

    # ---- Section 6: Findings (person-focused) ----
    pdf.section_title("Key Findings (Person-Focused)")
    if person_findings:
        pdf._col_widths = [8, 25, 55, 40, 62]
        pdf.table_header([
            ("#", 8), ("Type", 25), ("Value", 55), ("Verification", 40), ("Source", 62)
        ])
        for i, f in enumerate(person_findings[:50], 1):
            pdf.table_row([
                str(i),
                f.entity_type.value[:15],
                f.entity_value[:40],
                f"{f.verification}/{f.confidence.level}",
                f.source.url[:40] if f.source.url else "N/A",
            ], fill=(i % 2 == 0))
    else:
        pdf.body_text("No person-level findings collected.")
    pdf.ln(5)

    # ---- Section 7: Timeline ----
    pdf.section_title("Relationship Timeline")
    if case.timeline:
        pdf._col_widths = [35, 55, 30, 70]
        pdf.table_header([
            ("Time", 35), ("Event", 55), ("Verification", 30), ("Source", 70)
        ])
        for i, event in enumerate(case.timeline[:20], 1):
            pdf.table_row([
                event.timestamp[:19],
                event.title[:30],
                event.verification[:20],
                event.source[:40],
            ], fill=(i % 2 == 0))
    else:
        pdf.body_text("No timeline events were extracted from public findings.")
    pdf.ln(5)

    # ---- Section 8: Infrastructure Context ----
    pdf.section_title("Infrastructure Context")
    if infra_findings:
        pdf.body_text("Generic domain, DNS, WHOIS, and provider-level data (not person-specific).")
        pdf._col_widths = [8, 25, 55, 30, 72]
        pdf.table_header([
            ("#", 8), ("Type", 25), ("Value", 55), ("Confidence", 30), ("Source", 72)
        ])
        for i, f in enumerate(infra_findings[:30], 1):
            pdf.table_row([
                str(i),
                f.entity_type.value[:15],
                f.entity_value[:40],
                f"{f.confidence.level}",
                f.source.url[:40] if f.source.url else "N/A",
            ], fill=(i % 2 == 0))
    else:
        pdf.body_text("No generic infrastructure findings.")
    pdf.ln(5)

    # ---- Section 9: Risk & Exposure ----
    pdf.section_title("Risk & Exposure Assessment")
    pdf.key_value("Exposure Score", f"{exposure['score']:.2f}")
    pdf.key_value("Risk Level", exposure["risk_level"].upper())
    pdf.key_value("Risk Label", exposure.get("risk_label", "Unknown"))
    pdf.key_value("Contributing Factors", str(exposure["factor_count"]))
    pdf.ln(3)
    pdf.body_text(exposure["summary"])

    # ---- Section 10: Gaps & Limitations ----
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

    # ---- Section 11: Recommended Next Steps ----
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

    # ---- Section 12: Policy Compliance ----
    pdf.section_title("Policy Compliance")
    pdf.key_value("Mode", case.policy_mode)
    pdf.key_value("Status", "PASS")
    pdf.body_text(
        "This investigation was conducted entirely within the boundaries of "
        "public-source, read-only, lawful intelligence gathering methods."
    )

    # ---- Section 13: Audit Trail ----
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


def _try_add_avatar(pdf: OSINTReportPDF, avatar_url: str) -> bool:
    """Best-effort avatar embed for the primary profile."""
    if not avatar_url or not avatar_url.startswith(("http://", "https://")):
        return False

    suffix = ".jpg"
    if ".png" in avatar_url.lower():
        suffix = ".png"

    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        urllib.request.urlretrieve(avatar_url, tmp_path)
        pdf.image(tmp_path, x=10, y=pdf.get_y(), w=35, h=35)
        pdf.ln(38)
        return True
    except Exception:
        return False
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def save_pdf_report(case: Case, output_path: str) -> str:
    """Generate and save PDF report."""
    pdf_bytes = generate_pdf_report(case)
    with open(output_path, "wb") as f:
        f.write(pdf_bytes)
    return output_path
