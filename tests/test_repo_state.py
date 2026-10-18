"""The committed samples, dashboard and README must agree with what the code produces today."""
import json
import re
from pathlib import Path

from forensictriage import synthetic as syn
from forensictriage.config import load_config
from forensictriage.custody import verify_chain
from forensictriage.evaluate import evaluate

ROOT = Path(__file__).resolve().parent.parent
DASH = ROOT / "dashboard"
CASE = ROOT / "data" / "synthetic" / f"case-{syn.CASE_ID}"
REPORTS = ROOT / "reports"
STABLE_KEYS = ("summary", "findings", "narrative", "files", "timeline", "iocs", "carved", "deleted", "browser", "artifacts", "mitre", "rules", "window")


# ------------------------------------------------------------------ dashboard, static checks
def test_index_references_existing_assets():
    html = (DASH / "index.html").read_text()
    for ref in re.findall(r'(?:src|href)="([^"#:]+)"', html):
        assert (DASH / ref).exists(), ref


def test_no_inline_scripts_styles_or_handlers_so_csp_can_be_strict():
    html = (DASH / "index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert not re.search(r"\son[a-z]+=", html)
    assert 'style="' not in html and "<style" not in html


def test_app_never_injects_html():
    js = (DASH / "app.js").read_text()
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert bad not in js, bad


def test_vercel_configs_are_valid_and_set_security_headers():
    for path in (DASH / "vercel.json", ROOT / "vercel.json"):
        cfg = json.loads(path.read_text())
        headers = {h["key"]: h["value"] for rule in cfg["headers"] for h in rule["headers"]}
        assert headers["X-Content-Type-Options"] == "nosniff" and headers["X-Frame-Options"] == "DENY"
        csp = headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp and "script-src 'self'" in csp and "unsafe" not in csp
    assert json.loads((ROOT / "vercel.json").read_text())["outputDirectory"] == "dashboard"


def test_index_has_banner_and_every_panel_the_script_fills():
    html = (DASH / "index.html").read_text()
    js = (DASH / "app.js").read_text()
    assert "SYNTHETIC DATA" in html
    for needle in ("timeline", "f-table", "fl-table", "ioc-table", "carve-table", "custody-table", "integrity-status", "mitre-table", "rules-table", "drawer", "kpis", "chain-verify"):
        assert f'id="{needle}"' in html, needle
    for el_id in set(re.findall(r'\$\("([a-z0-9-]+)"\)', js)):
        assert f'id="{el_id}"' in html or el_id in ("kpi-critical",) or el_id.startswith(("chip-", "kpi-")), el_id


def test_dashboard_data_is_exactly_the_committed_report():
    assert (DASH / "data" / "case.json").read_bytes() == (REPORTS / "case_report.json").read_bytes()
    data = json.loads((DASH / "data" / "case.json").read_text())
    assert data["meta"]["synthetic"] is True and data["integrity"]["ok"] is True
    assert "/workspace/" not in (DASH / "data" / "case.json").read_text() and "/home/" not in (DASH / "data" / "case.json").read_text()


def test_the_javascript_chain_check_uses_the_same_canonical_rule_as_python():
    js = (DASH / "app.js").read_text()
    assert "function canon" in js and "sort()" in js and r"\\u" in js       # sorted keys, \uXXXX escapes (ensure_ascii)
    py = (ROOT / "forensictriage" / "custody.py").read_text()
    assert 'sort_keys=True, separators=(",", ":"), ensure_ascii=True' in py


# ------------------------------------------------------------------ committed samples match the code
def test_committed_synthetic_case_equals_a_fresh_generation(tmp_path):
    syn.generate(tmp_path / "fresh")
    fresh = {str(p.relative_to(tmp_path / "fresh")): p.read_bytes() for p in (tmp_path / "fresh").rglob("*") if p.is_file()}
    committed = {str(p.relative_to(CASE)): p.read_bytes() for p in CASE.rglob("*") if p.is_file()}
    assert fresh.keys() == committed.keys()
    assert [k for k in fresh if fresh[k] != committed[k]] == []


def test_committed_report_matches_a_fresh_run(report):
    committed = json.loads((REPORTS / "case_report.json").read_text())
    for key in STABLE_KEYS:
        assert report[key] == committed[key], key
    assert report["integrity"]["before"] == committed["integrity"]["before"]
    assert report["integrity"]["after"] == committed["integrity"]["after"]


def test_committed_reports_are_internally_consistent():
    rep = json.loads((REPORTS / "case_report.json").read_text())
    custody = json.loads((REPORTS / "custody_log.json").read_text())
    entries = custody["entries"] if isinstance(custody, dict) else custody
    assert verify_chain(entries)[0] and rep["integrity"]["custody_chain_ok"]
    manifest = json.loads((REPORTS / "evidence_manifest.json").read_text())
    assert manifest["digest_sha256"] == rep["integrity"]["before"]["manifest_sha256"] == rep["integrity"]["after"]["manifest_sha256"]
    md = (REPORTS / "case_report.md").read_text()
    assert "SYNTHETIC" in md and rep["meta"]["case_id"] in md
    for f in rep["findings"]:
        assert f["id"] in md
    carved = sorted(p.name for p in (REPORTS / "carved").iterdir())
    assert carved == sorted(c["name"] for c in rep["carved"]["files"])


def test_committed_evaluation_passes_and_is_reproducible(report, truth):
    ev = json.loads((REPORTS / "evaluation.json").read_text())
    fresh = evaluate(report, truth)
    assert ev["passed"] is True and fresh["passed"] is True
    assert ev["scenarios_total"] == fresh["scenarios_total"] and ev["scenarios_passed"] == fresh["scenarios_passed"]


def test_every_configured_rule_is_documented_in_the_readme():
    readme = (ROOT / "README.md").read_text()
    for rule in load_config()["rules"]:
        assert f"`{rule['id']}`" in readme, rule["id"]


def test_readme_numbers_match_the_committed_report():
    readme = (ROOT / "README.md").read_text()
    rep = json.loads((REPORTS / "case_report.json").read_text())
    s, ev = rep["summary"], json.loads((REPORTS / "evaluation.json").read_text())
    sev = s["by_severity"]
    assert f"findings {s['findings']} ({sev['critical']} critical, {sev['high']} high, {sev['medium']} medium, {sev['low']} low)" in readme
    assert f"{ev['scenarios_passed']}/{ev['scenarios_total']} scenarios" in readme
    assert f"carved {s['carved_complete']} complete + {s['carved_partial']} partial" in readme
    assert rep["integrity"]["before"]["manifest_sha256"][:16] in readme


# ------------------------------------------------------------------ case-file redesign
EM_DASH = "\u2014"
BUZZWORDS = ("leverage", "robust", "seamless", "cutting-edge", "comprehensive", "state-of-the-art", "synergy", "powerful", "best-in-class", "holistic")
TAB_NAMES = ("guide", "case", "timeline", "findings", "files", "clues", "recovered", "custody", "traces", "attack")


def test_every_folder_tab_has_a_matching_panel_and_only_the_first_is_open():
    html = (DASH / "index.html").read_text()
    for name in TAB_NAMES:
        assert f'id="tab-{name}"' in html and f'data-tab="{name}"' in html, name
        assert f'aria-controls="page-{name}"' in html, name
        assert re.search(rf'<section class="page" id="page-{name}" role="tabpanel" aria-labelledby="tab-{name}"( hidden)?>', html), name
    assert len(re.findall(r'role="tab"', html)) == len(TAB_NAMES)
    open_pages = re.findall(r'<section class="page" id="page-(\w+)" role="tabpanel" aria-labelledby="tab-\w+">', html)
    assert open_pages == ["case"]
    assert 'aria-selected="true"' in html.split('id="tab-timeline"')[0].split('id="tab-case"')[1]


def test_fonts_are_bundled_locally_with_their_licences_and_nothing_loads_from_a_cdn():
    css = (DASH / "style.css").read_text()
    urls = re.findall(r"url\(\"?([^)\"]+)\"?\)", css)
    assert urls, "expected @font-face rules"
    for u in urls:
        assert not u.startswith(("http:", "https:", "//")), u
        assert (DASH / u).exists(), u
    fonts = sorted(p.name for p in (DASH / "fonts").glob("*.woff2"))
    assert len(fonts) == 6 and all((DASH / "fonts" / f).read_bytes()[:4] == b"wOF2" for f in fonts)
    licences = (DASH / "fonts" / "LICENSES.txt").read_text()
    assert licences.count("SIL OPEN FONT LICENSE") >= 3
    for family in ("Caveat", "Courier Prime", "Lora"):
        assert family in licences
    for name in ("index.html", "style.css"):
        text = (DASH / name).read_text()
        assert not re.search(r"(?:src|href|url\()\s*=?\s*[\"']?https?://", text), name
    external = set(re.findall(r"https?://[^\s\"')]+", (DASH / "app.js").read_text()))
    assert {u for u in external if "attack.mitre.org" not in u} == set()


def test_the_font_stacks_have_web_safe_fallbacks():
    css = (DASH / "style.css").read_text()
    assert re.search(r'--hand: "Caveat", [^;]*cursive;', css)
    assert re.search(r'--mono: "Courier Prime", "Courier New", Courier[^;]*monospace;', css)
    assert re.search(r'--serif: "Lora", Georgia[^;]*serif;', css)


def test_csp_allows_only_local_fonts():
    for path in (DASH / "vercel.json", ROOT / "vercel.json"):
        cfg = json.loads(path.read_text())
        csp = next(h["value"] for rule in cfg["headers"] for h in rule["headers"] if h["key"] == "Content-Security-Policy")
        assert "font-src 'self'" in csp and "http" not in csp


def test_the_personal_note_is_on_the_first_page_and_reads_like_a_person():
    html = (DASH / "index.html").read_text()
    page = html.split('id="page-case"')[1].split('id="page-timeline"')[0]
    note = page.split('id="why-title"')[1].split("</article>")[0]
    for must in ("Toronto", "GCFE", "teaching myself", "tripped me up", "graded the tool against my own answer key", "Next I"):
        assert must in note, must
    assert EM_DASH not in note
    assert not re.search(r"\b(?:years? old|aged? \d+)\b", note)
    assert len(re.sub(r"<[^>]+>", " ", note).split()) < 260


def test_no_em_dashes_or_marketing_words_in_the_text_i_wrote():
    for rel in ("dashboard/index.html", "dashboard/app.js", "dashboard/style.css", "README.md", "portfolio_blurb.txt"):
        text = (ROOT / rel).read_text()
        assert EM_DASH not in text, rel
    for rel in ("dashboard/index.html", "README.md", "portfolio_blurb.txt"):
        low = (ROOT / rel).read_text().lower()
        for word in BUZZWORDS:
            assert word not in low, (rel, word)


def test_labels_are_plain_language():
    html = (DASH / "index.html").read_text()
    for label in ("What I found", "Every file", "Did I change anything?", "Deleted, then found", "Other traces", "Pretend someone edited an entry"):
        assert label in html, label
    for jargon in ("Evidence integrity &amp; chain of custody", "Indicators of compromise", "Carved files", "Artefacts"):
        assert jargon not in html, jargon


def test_every_panel_the_script_hides_or_shows_exists_and_the_board_and_list_share_filters():
    html = (DASH / "index.html").read_text()
    js = (DASH / "app.js").read_text()
    for el_id in ("f-board", "f-list", "f-order", "f-view", "tabs", "sheet", "banner"):
        assert f'id="{el_id}"' in html, el_id
    assert "function goTab" in js and "renderFindings" in js and "function ecard" in js
    assert 'id="banner"' in html and "SYNTHETIC DATA." in html.split('id="banner"')[1].split("</div>")[0]
    assert "[hidden] { display: none !important; }" in (DASH / "style.css").read_text()


# ------------------------------------------------------------------ the "How to use this" guide
def _guide_section():
    html = (DASH / "index.html").read_text()
    start = html.index('id="page-guide"')
    return html[start:html.index("</section>", html.index('id="skills-title"'))]


def test_guide_tab_is_first_in_the_nav_and_the_case_still_opens_first():
    html = (DASH / "index.html").read_text()
    assert html.index('id="tab-guide"') < html.index('id="tab-case"')
    assert "How to use this" in html.split('id="tab-case"')[0].split('id="tab-guide"')[1]
    assert 'id="start-here"' in html and 'id="start-dismiss"' in html and 'id="start-open"' in html
    assert re.search(r'<aside id="start-here"[^>]*\bhidden\b', html)        # shown by script only if it was not dismissed


def test_guide_has_the_four_required_parts_and_five_steps():
    g = _guide_section()
    for heading in ("Try this in 60 seconds", "Words you will see", "What this shows about my skills"):
        assert heading in g, heading
    assert "forensics triage tool I wrote" in g                               # one-sentence what and why
    assert len(re.findall(r"<li><p><b>", g)) == 5
    for term in ("Hash (MD5, SHA-1, SHA-256)", "Chain of custody", "Hash chain", "Timestomping", "MACB", "File carving", "IOC (indicator of compromise)", "MITRE ATT&amp;CK", "UTC"):
        assert f"<dt>{term}</dt>" in g, term


def test_guide_steps_only_name_things_that_exist_in_the_data_and_ui():
    g = _guide_section()
    html = (DASH / "index.html").read_text()
    rep = json.loads((REPORTS / "case_report.json").read_text())
    titles = [f["title"] for f in rep["findings"]]
    assert "Extension does not match content: holiday_photos_2025.jpg" in titles and "Extension does not match content: holiday_photos_2025.jpg" in g
    assert rep["summary"]["by_severity"]["critical"] == 1 and "1 critical" in g and "1 of 20 findings" in g and len(titles) == 20
    crit = [f for f in rep["findings"] if f["severity"] == "critical"][0]
    assert "invoice_template.pdf" in crit["title"] and "invoice_template.pdf" in g
    cf1 = rep["carved"]["files"][0]
    assert cf1["id"] == "CF-001" and f"{cf1['length']:,}" in g and "CF-001" in g
    assert "proj_backup.zip" in json.dumps(cf1) and "holiday_photos_2025.jpg" in json.dumps(cf1)
    for label in ("Check the chain here", "Pretend someone edited an entry", "Undo", "Start over", "Take me there", "Files involved", "Why I flagged it", "What to do about it", "In short"):
        assert label in html or label in (DASH / "app.js").read_text(), label
    assert "entry 3" in g and "chainEntries[2]" in (DASH / "app.js").read_text()   # the tamper button edits entry 3
    for tab in re.findall(r'data-go="(\w+)"', g):
        assert f'id="tab-{tab}"' in html, tab


def test_start_here_dismissal_is_remembered_and_storage_failures_are_survivable():
    js = (DASH / "app.js").read_text()
    assert "forensics-triage-guide-dismissed" in js and "localStorage" in js
    assert re.search(r"function storeGet\(\) \{ try \{", js) and re.search(r"function storeSet\(\) \{ try \{", js)
    assert "wireGuide" in js and "function openGuide" in js


def test_guide_is_responsive_and_copy_is_plain():
    css = (DASH / "style.css").read_text()
    assert ".walk" in css and "dl.gloss" in css and ".postit" in css and "min-height: 40px" in css
    g = _guide_section().lower()
    for word in BUZZWORDS + ("vibe",):
        assert word not in g, word
    assert EM_DASH not in g


def test_readme_documents_the_guide():
    readme = (ROOT / "README.md").read_text()
    assert "## How to use the demo" in readme
    section = readme[readme.index("## How to use the demo"):readme.index("## Why I made it")]
    for needle in ("holiday_photos_2025.jpg", "CF-001", "Check the chain here", "Pretend someone edited an entry", "1 critical"):
        assert needle in section, needle


# ------------------------------------------------------------------ simplified layout
def test_main_tabs_are_five_and_the_rest_are_folded_under_more_of_the_file():
    html = (DASH / "index.html").read_text()
    main = html[html.index('id="tabs"'):html.index('id="tabs-more"')]
    assert re.findall(r'data-tab="(\w+)"', main) == ["guide", "case", "timeline", "findings", "files"]
    more = html[html.index('id="more-tabs"'):html.index("</nav>")]
    assert re.findall(r'data-tab="(\w+)"', more) == ["clues", "recovered", "custody", "traces", "attack"]
    assert re.search(r'<div id="more-tabs"[^>]*\bhidden\b', html) and 'aria-expanded="false" aria-controls="more-tabs"' in html
    js = (DASH / "app.js").read_text()
    assert "MORE_TABS" in js and "function setMore" in js and "function visibleTabs" in js


def test_case_page_shows_four_stamps_and_a_short_story_with_the_rest_behind_clicks():
    html = (DASH / "index.html").read_text()
    js = (DASH / "app.js").read_text()
    assert 'id="kpi-more"' in html and 'id="kpis2"' in html and 'id="stats-more"' in html and 'id="story-more"' in html
    assert "note-kpi" not in html and "note-tl" not in html and "note-chain" not in html     # decorative hand notes removed
    assert 'class="why-fold" id="why"' in html                                               # personal note is a quiet fold
    assert "SHOW = 6" in js and "i < 4 ? st : st2" in js
    start = html[html.index('id="start-here"'):html.index('id="banner"')]
    assert "btn-row" not in start and len(re.sub(r"<[^>]+>", " ", start).split()) < 30        # one short line, not a big sticky note


def test_extra_findings_filters_sit_in_one_expander():
    html = (DASH / "index.html").read_text()
    tools = html[html.index('id="f-tools"'):html.index("</details>", html.index('id="f-tools"'))]
    assert 'id="f-cat"' in tools and 'id="f-order"' in tools
