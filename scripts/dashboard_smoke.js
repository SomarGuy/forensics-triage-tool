/* Optional end-to-end check of the dashboard in a real (headless) Chrome, plus README screenshots.
 *   npm i playwright-core            (no browser download: uses your installed Chrome/Chromium)
 *   python -m http.server 8077 --directory dashboard &
 *   CHROME=/usr/bin/google-chrome node scripts/dashboard_smoke.js http://127.0.0.1:8077 screenshots
 * Run from the project root (it reads dashboard/data/case.json for the hostile-input test).
 */
const { chromium } = require("playwright-core");
const assert = require("assert");
const fs = require("fs"), os = require("os"), path = require("path");
const base = process.argv[2] || "http://127.0.0.1:8077";
const outDir = process.argv[3] || "screenshots";
const report = JSON.parse(fs.readFileSync("dashboard/data/case.json", "utf8"));

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME || "/usr/bin/google-chrome", args: ["--no-sandbox"] });
  const errors = [];
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  let dialogs = 0;
  page.on("dialog", async (d) => { dialogs++; await d.dismiss(); });
  const rows = (sel) => page.locator(sel + " tbody tr").count();

  await page.goto(base + "/", { waitUntil: "networkidle" });
  await page.waitForSelector("#f-table tbody tr", { state: "attached" });
  const tab = async (name) => { await page.click("#tab-" + name); await page.waitForSelector("#page-" + name + ":not([hidden])"); };

  // ---- the case file: tabs, banner, personal note
  const tabNames = ["case", "timeline", "findings", "files", "clues", "recovered", "custody", "traces", "attack"];
  assert.strictEqual(await page.locator('[role="tab"]').count(), tabNames.length, "nine folder tabs");
  assert.strictEqual(await page.locator('.page:not([hidden])').count(), 1, "only the open page is visible");
  assert.strictEqual(await page.getAttribute("#tab-case", "aria-selected"), "true", "first tab selected");
  const why = await page.locator("#why-title").locator("xpath=..").textContent();
  assert(/Toronto/.test(why) && /GCFE/.test(why) && /Diogo/.test(why), "personal note present");
  assert(!/\u2014/.test(why), "no em dash in the personal note");
  await page.focus("#tab-case"); await page.keyboard.press("ArrowDown");
  assert.strictEqual(await page.getAttribute("#tab-timeline", "aria-selected"), "true", "arrow key moves to the next tab");
  await page.waitForSelector("#page-timeline:not([hidden])");
  await tab("case");

  // ---- summary, banner, KPIs match the report
  assert(/SYNTHETIC/.test(await page.locator("#banner").textContent()), "synthetic banner");
  assert.strictEqual(await rows("#f-table"), report.findings.length, "all findings listed");
  for (const sev of ["critical", "high", "medium", "low"]) {
    assert.strictEqual((await page.locator(`.kpi[data-sev="${sev}"] .n`).textContent()).trim(), String(report.summary.by_severity[sev]), "KPI " + sev);
  }
  assert.strictEqual(await rows("#fl-table"), report.files.length, "all files listed");
  assert.strictEqual(await rows("#ioc-table"), report.iocs.length, "all IOCs listed");
  assert.strictEqual(await rows("#carve-table"), report.carved.files.length, "carved files listed");
  assert.strictEqual(await rows("#custody-table"), report.integrity.custody.length, "custody entries listed");
  assert.strictEqual(await rows("#mitre-table"), report.mitre.length, "MITRE rows");
  assert(/unchanged/i.test(await page.locator("#integrity-status").textContent()), "integrity status shows unchanged");
  assert((await page.locator("#story li").count()) === report.narrative.length, "storyline listed");
  assert.strictEqual(await page.locator("#f-board .ecard").count(), report.findings.length, "one evidence card per finding");
  assert((await page.locator("#story .gap").count()) >= 1, "gaps between story events are written out");
  const pixels = () => page.evaluate(() => {
    const c = document.getElementById("timeline"); const d = c.getContext("2d").getImageData(0, 0, c.width, c.height).data;
    let n = 0; for (let i = 3; i < d.length; i += 4) if (d[i] !== 0) n++; return n;
  });
  await page.screenshot({ path: outDir + "/01-dashboard.png" });
  await page.screenshot({ path: outDir + "/01-dashboard-full.png", fullPage: true });
  await tab("timeline");
  assert((await pixels()) > 2000, "timeline canvas has drawn content");
  await tab("case");

  // ---- findings filters
  await page.click('.kpi[data-sev="critical"]');
  await page.waitForSelector("#page-findings:not([hidden])");
  assert.strictEqual(await rows("#f-table"), report.summary.by_severity.critical, "critical filter count");
  assert.strictEqual(await page.locator("#f-board .ecard").count(), report.summary.by_severity.critical, "board follows the filter");
  await page.click("#f-reset");
  await page.fill("#f-search", "timestomp");
  assert((await rows("#f-table")) >= 1, "search finds timestomp finding");
  await page.click("#f-reset");
  await tab("attack");
  await page.click('#mitre-table tr[data-tech="T1070.006"]');
  await page.waitForSelector("#page-findings:not([hidden])");
  const t = await rows("#f-table");
  assert.strictEqual(await page.locator("#f-board .ecard").count(), t, "board and list agree");
  assert(t >= 1 && t < report.findings.length, "technique filter narrows, got " + t);
  await page.click("#f-reset");

  // ---- list view of the findings: sort works and the list is a real table
  await page.click('#f-view button[data-view="list"]');
  assert(await page.locator("#f-table").isVisible() && await page.locator("#f-board").isHidden(), "list view swaps the board for the table");
  await page.click('#f-table button.sort[data-sort="time"]');
  const firsts = await page.$$eval("#f-table tbody tr td:last-child", (tds) => tds.map((x) => x.textContent));
  assert(firsts.every((v, i) => i === 0 || firsts[i - 1] >= v), "time sort (newest first on first click)");
  await page.click('#f-view button[data-view="board"]');
  await page.selectOption("#f-order", "time");
  const cardsFirst = await page.locator("#f-board .ecard").first().getAttribute("data-id");
  assert.strictEqual(cardsFirst, report.findings.slice().sort((a, b) => a.first_seen_ms - b.first_seen_ms || (a.id < b.id ? -1 : 1))[0].id, "oldest-first order on the board");
  await page.click("#f-reset");
  assert.strictEqual(await page.locator("#f-order").inputValue(), "severity", "reset brings back worst-first");

  // ---- file table: sort, flagged-only, drill-down
  await tab("files");
  await page.check("#fl-only");
  const flagged = await rows("#fl-table");
  assert.strictEqual(flagged, report.summary.flagged_files, "flagged-only count equals the report's flagged_files");
  assert(flagged < report.files.length, "flagged-only hides clean files");
  await page.uncheck("#fl-only");
  await page.selectOption("#fl-flag", "signature_mismatch");
  assert.strictEqual(await rows("#fl-table"), report.summary.signature_mismatches, "signature_mismatch filter");
  await page.selectOption("#fl-flag", "");
  await page.click('#fl-table button.sort[data-sort="size"]');
  const sizes = await page.$$eval("#fl-table tbody tr td.num", (tds) => tds.map((x) => Number(x.textContent.replace(/,/g, ""))));
  assert(sizes.every((v, i) => i === 0 || sizes[i - 1] >= v), "size sort (descending first)");
  await page.fill("#fl-search", "Atlas_Roadmap");
  await page.locator("#fl-table tbody tr").first().click();
  await page.waitForSelector("#drawer:not([hidden])");
  const dr = await page.locator("#drawer-body").textContent();
  assert(/STANDARD_INFORMATION/.test(dr) && /si_created_before_fn/.test(dr) && /SHA-256/.test(dr), "file drawer shows $SI/$FN and indicators");
  await page.keyboard.press("Escape");
  await page.fill("#fl-search", "");

  // ---- finding drill-down
  await tab("findings");
  await page.fill("#f-search", "known-bad");
  await page.locator("#f-board .ecard").first().click();
  await page.waitForSelector("#drawer:not([hidden])");
  assert(/invoice_template/.test(await page.locator("#drawer-body").textContent()), "drawer shows the file");
  await page.waitForTimeout(500);
  await page.screenshot({ path: outDir + "/02-finding-drilldown.png" });
  await page.keyboard.press("Escape");
  assert(await page.locator("#drawer").isHidden(), "Escape closes drawer");
  await page.click("#f-reset");
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: outDir + "/07-evidence-board.png" });

  // ---- IOC filters
  await tab("clues");
  await page.click('#ioc-types button[data-type="ipv4"]');
  const ips = await rows("#ioc-table");
  assert(ips >= 1 && ips < report.iocs.length, "IOC type filter, got " + ips);
  await page.click('#ioc-types button[data-type="ipv4"]');

  // ---- carved: open drawer, sees correlation
  await tab("recovered");
  await page.locator("#carve-table tbody tr").first().click();
  await page.waitForSelector("#drawer:not([hidden])");
  assert(/holiday_photos_2025/.test(await page.locator("#drawer-body").textContent()), "carved ZIP is correlated with the renamed JPEG");
  await page.keyboard.press("Escape");

  // ---- timeline: window vs all, click a bucket, source toggle
  await tab("timeline");
  const inWindow = await page.locator("#tl-count").textContent();
  await page.click('#tl-mode button[data-mode="all"]');
  const all = await page.locator("#tl-count").textContent();
  assert(parseInt(all) > parseInt(inWindow), "all-dates shows more events than the incident window: " + inWindow + " vs " + all);
  assert(/impossible/.test(await page.locator("#tl-table").textContent()), "1970 event flagged as impossible");
  await page.click('#tl-mode button[data-mode="window"]');
  await page.evaluate(() => document.getElementById("timeline").scrollIntoView({ block: "center" }));
  const box = await page.locator("#timeline").boundingBox();
  // find the busiest bucket by scanning along the chart until a click filters the list
  let clicked = false;
  for (let f = 0.2; f < 0.95 && !clicked; f += 0.02) {
    await page.mouse.move(box.x + box.width * f, box.y + box.height * 0.5);
    if (await page.locator("#tooltip").isVisible() && /(^|[^0-9])[1-9]\d* events?/.test(await page.locator("#tooltip").textContent())) { await page.mouse.click(box.x + box.width * f, box.y + box.height * 0.5); clicked = true; }
  }
  assert(clicked, "found a bucket with events");
  assert(await page.locator("#tl-active .pill").count() === 1, "bucket click adds a range pill");
  assert(parseInt(await page.locator("#tl-count").textContent()) < parseInt(inWindow), "bucket filter narrows the list");
  await page.screenshot({ path: outDir + "/03-timeline-hover.png", clip: { x: Math.max(0, box.x - 20), y: Math.max(0, box.y - 120), width: box.width + 40, height: box.height + 200 } });
  await page.click("#tl-active .pill button");
  await page.click('#tl-legend button:has-text("FILESYSTEM")');
  assert(!(await page.locator("#tl-table tbody").textContent()).includes("FILESYSTEM  "), "source toggle hides FILESYSTEM rows");
  await page.click("#tl-reset");

  // ---- custody chain verify + tamper detection (recomputed in the browser)
  await tab("custody");
  await page.click("#chain-verify");
  await page.waitForFunction(() => /Chain intact/.test(document.getElementById("chain-result").textContent));
  await page.click("#chain-tamper");
  await page.click("#chain-verify");
  await page.waitForFunction(() => /BROKEN at entry 3/.test(document.getElementById("chain-result").textContent));
  assert.strictEqual(await page.locator("#custody-table tr.broken").count(), 1, "broken entry highlighted");
  await page.locator("#page-custody").screenshot({ path: outDir + "/05-chain-of-custody.png" });
  await page.click("#chain-reset");
  assert.strictEqual(await page.locator("#custody-table tr.broken").count(), 0, "reset clears highlight");
  assert.strictEqual(dialogs, 0, "no dialogs");

  // ---- user-supplied report: not-synthetic banner, hostile strings stay inert, broken file shows an error
  const custom = JSON.parse(JSON.stringify(report));
  custom.meta.synthetic = false;
  custom.findings[0].title = "<img src=x onerror=alert(1)> injected";
  custom.files[0].path = "dir/<script>alert(2)</script>.txt";
  custom.iocs[0].value = "<svg onload=alert(3)>";
  const tmp = path.join(os.tmpdir(), "custom-case.json");
  fs.writeFileSync(tmp, JSON.stringify(custom));
  await page.setInputFiles("#file-input", tmp);
  await page.waitForFunction(() => /YOUR DATA/.test(document.getElementById("banner").textContent));
  assert.strictEqual(await page.locator("main img, main svg[onload], main script").count(), 0, "hostile HTML stays text");
  assert(/<script>alert\(2\)/.test(await page.locator("#fl-table").textContent()), "hostile file name shown as text");
  fs.writeFileSync(tmp, "{not json");
  await page.setInputFiles("#file-input", tmp);
  await page.waitForSelector("#error:not([hidden])");
  fs.writeFileSync(tmp, JSON.stringify({ hello: 1 }));
  await page.setInputFiles("#file-input", tmp);
  await page.waitForFunction(() => /Invalid report file/.test(document.getElementById("error").textContent));
  assert.strictEqual(dialogs, 0, "no dialogs after hostile input");
  fs.unlinkSync(tmp);

  // ---- mobile
  const m = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
  m.on("pageerror", (e) => errors.push("mobile: " + e));
  m.on("console", (x) => { if (x.type() === "error") errors.push("mobile: " + x.text()); });
  await m.goto(base + "/", { waitUntil: "networkidle" });
  await m.waitForSelector("#f-table tbody tr", { state: "attached" });
  const sw = await m.evaluate(() => document.documentElement.scrollWidth);
  assert(sw <= 392, "no horizontal overflow on mobile, got " + sw);
  await m.screenshot({ path: outDir + "/04-mobile.png" });
  await m.click("#tab-findings");
  await m.waitForSelector("#f-board .ecard");
  assert((await m.evaluate(() => document.documentElement.scrollWidth)) <= 392, "no horizontal overflow on the mobile board");
  await m.screenshot({ path: outDir + "/08-mobile-board.png" });
  for (const n of ["files", "recovered", "custody", "traces"]) { await m.click("#tab-" + n); assert((await m.evaluate(() => document.documentElement.scrollWidth)) <= 392, "no overflow on mobile tab " + n); }

  assert.deepStrictEqual(errors, [], "no console errors: " + errors.join("; "));
  console.log("dashboard smoke test OK:", { findings: report.findings.length, files: report.files.length, flaggedOnly: flagged, techniqueFilter: t });
  await browser.close();
})().catch((e) => { console.error("FAILED:", e.message); process.exit(1); });
