# Look4Gold13

**AU-13 Publicly Available Content (PAC) scanner + CVE monitor with NIST AU-2/AU-3 audit logging.**

Look4Gold13 automates the process of searching for your organization's publicly exposed information across the internet. It combines DuckDuckGo search dorking, NIST NVD CVE lookups, and GenAI-powered intelligence gathering (via Ask Sage) to find leaked credentials, breached data, exposed documents, misconfigured cloud resources, known vulnerabilities, and more. Results are compiled into an HTML report with severity ratings, and every scan action is recorded in a NIST-compliant audit log.

---

## What It Does

1. **Search Dorking** -- Takes your keywords (company names, domains, project names, etc.) and combines them with a library of search dorks targeting paste sites, code repos, breach databases, and security news sources. Each keyword is searched against every dork via DuckDuckGo.

2. **CVE Monitoring** -- Queries the NIST National Vulnerability Database (NVD) API for CVEs matching each keyword. CVEs are filtered by publication date (configurable lookback, default 7 days) and include CVSS severity scores mapped to the same Critical/High/Medium/Low/Informational levels used throughout the tool. CVE lookup is on by default.

3. **GenAI Intelligence** -- If an Ask Sage API key is configured, a **separate GenAI query runs for each keyword** after that keyword's dork searches and CVE lookup complete. Each query sends the keyword, discovered URLs, and CVE findings to a Gemini 2.5 Flash model with live web search enabled. The GenAI searches broadly across the internet for recent cybersecurity events and assigns severity ratings. Running per-keyword gives the GenAI more focused, contextual results.

4. **NIST AU-2/AU-3 Audit Logging** -- Every significant scan event is recorded in a structured audit log that satisfies NIST SP 800-53 AU-2 (auditable event definitions) and AU-3 (audit record content). Each record contains: event type, timestamp (ISO 8601), source system/host, source function, outcome (Success/Failure/Warning), and subject identity.

5. **Reporting** -- All results are compiled into output files in a per-scan folder (`Outputs/Scan_<timestamp>/`):
   - **HTML Report** -- A styled, dark-themed report organized by keyword. GenAI findings are always visible; CVE results and dork results are in collapsible sections for readability.
   - **NIST Audit Log (JSON)** -- Structured audit event log with metadata, suitable for SIEM ingestion or compliance review.
   - **NIST Audit Log (CSV)** -- Same audit data in Excel-compatible format for spreadsheet analysis.
   - **NIST Audit Log (NDJSON)** -- Real-time event stream written as the scan runs (one JSON object per line, append-safe).

**Note:** Some variable names, parameter flags (e.g., `-AgiOnly`), and output filenames (e.g., `Look4Gold13_AGI_*.json`) still use "AGI" instead of "GenAI". This is a naming artifact from early development -- the feature uses generative AI (GenAI), not artificial general intelligence (AGI). Code-level names are kept as-is to avoid breaking changes.

---

## Quick Start

```powershell
# 1. Set up keywords
Copy-Item config/keywords.example.txt config/keywords.txt
# Edit keywords.txt with your organization-specific terms

# 2. Set up search dorks
Copy-Item config/sources.example.json config/sources.json
# Optionally edit sources.json to customize dorks

# 3. Run a scan (includes DDG dorks + CVE lookup + GenAI if key is set)
.\Look4Gold13.ps1

# 4. Run with fewer dorks for a quick test
.\Look4Gold13.ps1 -MaxDorks 4

# 5. CVE-only mode (fast -- just NVD queries, no dork scanning or GenAI)
.\Look4Gold13.ps1 -CveOnly

# 6. GenAI-only mode (skip dork scanning and CVE, just Ask Sage)
.\Look4Gold13.ps1 -AgiOnly

# 7. Search further back in time (14 days instead of default 7)
.\Look4Gold13.ps1 -DaysBack 14

# 8. Run silently (no console output, files only)
.\Look4Gold13.ps1 -Silent

# 9. Custom timing (slower to be gentler on DDG)
.\Look4Gold13.ps1 -BaseDelay 90 -MinJitter 10 -MaxJitter 30
```

### Ask Sage (GenAI) Setup

The GenAI query is optional but recommended. Without it you still get dork results and CVE findings; with it you get an additional layer of AI-driven intelligence.

```powershell
# Set your Ask Sage API key (get one from https://chat.genai.army.mil/ > Settings > Account > Manage API Keys)
$env:ASK_SAGE_API_KEY = "your-api-key-here"

# Or set it permanently so it persists across sessions:
[System.Environment]::SetEnvironmentVariable("ASK_SAGE_API_KEY", "your-key", "User")
# Restart PowerShell after setting this
```

### NVD API Key (Optional)

CVE lookups work without an API key but are rate-limited to 5 requests per 30 seconds. With a free NVD API key, you get 50 requests per 30 seconds.

```powershell
# Request a key at: https://nvd.nist.gov/developers/request-an-api-key
$env:NVD_API_KEY = "your-nvd-api-key-here"

# Or set it permanently:
[System.Environment]::SetEnvironmentVariable("NVD_API_KEY", "your-key", "User")
```

### Custom Persona (Recommended)

For best results, create a custom persona in Ask Sage named exactly **Look4Gold13**. The script automatically looks up this persona by name via the `get-personas` API and uses it for GenAI queries. If not found, it falls back to the built-in ISSO (Cyber) persona (ID 5).

**To create the persona:**

1. Go to https://chat.genai.army.mil/
2. Navigate to **Settings > Personas > Create New Persona**
3. Name it exactly: `Look4Gold13`
4. Paste the following preamble into the persona instructions:

<details>
<summary>Click to expand persona preamble</summary>

```
You are a cybersecurity expert focused on NIST SP 800-53 AU-13 (Monitoring for Information Disclosure). When talking about yourself, speak in the first-person point of view. Make sure you cite references using [number] notation after the reference. For math, and for both block equations and inline equations, you must use the following LaTeX format: equation    equation    equation. Example for a block equation: f(x)=x2    f(x) = x^2    f(x)=x2. Example for an inline equation: The function is given by f(x)=x2    f(x) = x^2    f(x)=x2. When you write software code, provide a description statement, followed by the indented code with detailed comments wrapped with ```markdown
You are an Information Systems Security Officer (ISSO) with decades of experience. Your job is to ensure the security of the organization's information systems, including developing and implementing security policies, procedures, and standards, as well as monitoring and responding to security incidents. You must ensure that the organization's systems are compliant with applicable laws and regulations, particularly the NIST Cybersecurity Framework and the Risk Management Framework for the Department of Defense. Additionally, you must stay up to date on the latest security trends and technologies to ensure the organization's systems remain secure. Your purpose is to help government teams drive outcomes by assisting them with their cybersecurity requirements and issues, with a specific emphasis on AU-13 compliance, which involves monitoring organizational systems for indicators of inappropriate or unusual information disclosure (e.g., data leaks, unauthorized sharing, or exposure of sensitive information).
You provide accurate answers, but if you are asked a question that is nonsense, trickery, or has no truthful answer, you will respond with "I am not sure". You are helpful, very friendly, factual, and do not come up with made-up video links. Your logic and reasoning should be rigorous, intelligent, and defensible. When searching for information, prioritize sources related to information disclosure risks, such as data leaks, breaches involving exposure, vulnerabilities that enable disclosure, and relevant compliance guidance. Use multiple search queries if needed to cover breadth, including government sources (e.g., NIST, CISA), industry reports, and news outlets. Cross-verify information from diverse, reputable sources to ensure comprehensiveness and accuracy for AU-13 monitoring purposes.
```

</details>

5. Save the persona

The script calls the `get-personas` API on each run to resolve the ID automatically -- just create the persona and go.

---

## How the Search Works (and Why It's Designed This Way)

### The Rate-Limit Problem

DuckDuckGo aggressively rate-limits automated queries. After just a handful of requests from the same session, DDG starts returning CAPTCHA pages or HTTP 202 responses instead of real search results. A naive script that fires requests in a loop will get blocked within minutes, making it useless for scanning dozens of keyword+dork combinations.

Look4Gold13 uses several techniques working together to avoid this:

### Browser Session Priming

Before any automated queries begin, the script opens the DuckDuckGo HTML endpoint (`https://html.duckduckgo.com/html/`) in a **new, minimized browser window** on the same machine. This is not just a convenience -- it has a real technical purpose.

When a browser visits DDG, it establishes cookies and a session that DDG's anti-bot system recognizes. Subsequent requests from the same IP address are treated more leniently because DDG sees that there's a "real" browser session active on that IP. Without this priming step, automated requests get flagged much faster.

The window is opened minimized (using off-screen positioning for Chromium browsers and Win32 minimize calls), and it's automatically closed when the scan completes.

### Identity Rotation

Every single HTTP request uses a **completely fresh identity**:

- **New User-Agent** -- Randomly selected from a pool of 10 real browser profiles (Chrome 131/132, Firefox 133/134, Edge 131/132 across Windows and macOS). Each profile includes the correct matching `Sec-CH-UA` headers that the real browser would send. Firefox profiles correctly omit these headers, just like real Firefox does.
- **New session** -- Each request gets a fresh `WebRequestSession` (cookie jar), so there's no session tracking between requests.
- **Randomized Referer** -- Each request randomly includes or omits a Referer header, choosing from realistic DDG-related URLs.
- **Randomized parameters** -- Each DDG query varies the region (`us-en`, `uk-en`, `au-en`, `ca-en`, or worldwide) and date filter (anytime, past week, past month). This makes each request look like it came from a different user searching for different things.

The goal is that each request, looked at in isolation, appears to be a completely different person using a completely different browser.

### Timing and Jitter

Requests are spaced apart with a configurable delay plus random jitter:

- **Base delay** (default: 120 seconds) -- The minimum gap between requests.
- **Jitter** (default: 5-15 seconds) -- A random amount added on top of the base delay.

So by default, requests go out every 125-135 seconds. This mimics a human who searches, reads results, and then searches again. The randomness prevents a detectable fixed-interval pattern. You can tune these values with `-BaseDelay`, `-MinJitter`, and `-MaxJitter`.

### Dork Grouping (OR Queries)

To reduce the total number of requests, `site:` dorks are automatically combined into a single OR query. For example, instead of searching for:

```
"MyCompany" site:pastebin.com
"MyCompany" site:github.com
"MyCompany" site:gist.github.com
```

The script combines them into one request:

```
"MyCompany" (site:pastebin.com OR site:github.com OR site:gist.github.com)
```

Results are then mapped back to the correct individual dork label based on the URL domain. This cuts the number of DDG requests significantly -- fewer requests means less chance of triggering rate limits.

### CAPTCHA Handling

If DDG does return a CAPTCHA despite all precautions, the script doesn't just give up:

1. It detects the CAPTCHA (HTTP 202, "anomaly-modal", "automated requests" text, etc.)
2. Applies exponential backoff: 60s, then 120s, then 240s, up to 480s
3. Retries with a completely fresh identity and rebuilt URL
4. If the retry also hits a CAPTCHA, it halts DDG queries for this keyword (but still runs the per-keyword CVE lookup and GenAI query with whatever results were collected, and continues to subsequent keywords)

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-KeywordFile` | string | `config/keywords.txt` | Path to a custom keywords file |
| `-MaxDorks` | int | `0` (all) | Limit to the first N dorks. Useful for quick tests |
| `-BaseDelay` | int | `120` | Base seconds to wait between DDG requests |
| `-MinJitter` | int | `5` | Minimum random seconds added to the delay |
| `-MaxJitter` | int | `15` | Maximum random seconds added to the delay |
| `-DaysBack` | int | `7` | Lookback period in days for both CVE and GenAI searches |
| `-VerboseOutput` | switch | off | Show extra debug info (saved HTML on empty results, NVD pagination, etc.) |
| `-OutputFile` | string | auto | Custom path for the HTML report |
| `-NoExport` | switch | off | Suppress all file output (HTML, audit logs) |
| `-Silent` | switch | off | Suppress all console output. Files are still written |
| `-AgiOnly` | switch | off | Skip dork scanning, run only the Ask Sage GenAI query |
| `-CveOnly` | switch | off | Run only CVE lookup (no dork scanning, no GenAI) |
| `-NoCve` | switch | off | Disable CVE lookup (dorks + GenAI only) |
| `-CveMaxResults` | int | `100` | Maximum CVE results per keyword |
| `-AuditLogFile` | string | auto | Custom path for the NDJSON audit log |
| `-NoAuditLog` | switch | off | Disable audit logging |

**Mutually exclusive flags:** `-CveOnly` cannot be used with `-AgiOnly` or `-NoCve`.

---

## Per-Keyword Scan Flow

For each keyword, the scan runs three phases in order:

```
Dork Searches  -->  CVE Lookup  -->  GenAI Query
(DDG dorking)      (NIST NVD)      (Ask Sage)
```

CVE results are discovered before the GenAI query runs, so they are included as additional context in the GenAI prompt. This gives the AI richer analysis -- it can correlate CVE findings with news, breaches, and other intelligence.

---

## Time Estimates

Scan duration depends on the number of keywords, the number of dork groups, and the base delay. The default `sources.json` ships with 26 dorks that get batched into **13 query groups** per keyword.

**Per-keyword breakdown (defaults: 120s base + 5-15s jitter):**

| Phase | Time | Notes |
|---|---|---|
| DDG dork searches | ~28 min | 13 query groups x ~130s average delay |
| NVD CVE lookup | ~6-12 sec | 1-2 API calls (rate-limited without key) |
| Ask Sage GenAI query | ~30 sec | Single API call with live web search |
| **Total per keyword** | **~29 min** | |

**Multi-keyword examples:**

| Keywords | Mode | Estimated Total |
|---|---|---|
| 1 keyword | Full (dorks + CVE + GenAI) | ~29 min |
| 3 keywords | Full (dorks + CVE + GenAI) | ~87 min (~1.5 hrs) |
| 5 keywords | Full (dorks + CVE + GenAI) | ~145 min (~2.4 hrs) |
| 5 keywords | `-MaxDorks 4` | ~35 min |
| Any count | `-CveOnly` | ~10 sec per keyword |
| Any count | `-AgiOnly` | ~30 sec per keyword |

**Tips for faster scans:**
- Use `-CveOnly` for a quick vulnerability check (just NVD queries, very fast)
- Use `-MaxDorks N` to limit to the first N dorks (e.g., `-MaxDorks 4` runs only 4 groups)
- Use `-AgiOnly` to skip dork scanning and CVE, running just the GenAI query
- Use `-NoCve` to skip CVE lookups if you only want dork + GenAI results
- Lower `-BaseDelay` to reduce wait time between queries (increases CAPTCHA risk)

The script displays its own time estimate at the start of each run based on your actual parameters.

---

## Output Files

All output files are written to a per-scan folder: `Outputs/Scan_<yyyy-MM-dd_HHmm>/`

| File | Format | Contents |
|---|---|---|
| `Look4Gold13_Report_<timestamp>.html` | HTML | Report organized by keyword. GenAI findings always visible; CVE and dork results in collapsible sections. |
| `Look4Gold13_Audit_<timestamp>.json` | JSON | NIST AU-2/AU-3 compliant audit log: `{ metadata: {...}, audit_events: [{timestamp, event_type, source_system, outcome, subject, ...}] }` |
| `Look4Gold13_Audit_<timestamp>.csv` | CSV | Same audit data in Excel-compatible tabular format |
| `Look4Gold13_Audit_<timestamp>.jsonl` | NDJSON | Real-time event stream (one JSON object per line, written as the scan runs) |

### Audit Log Event Types (AU-2)

The following events are recorded to satisfy NIST SP 800-53 AU-2:

| Event Type | Category | Description |
|---|---|---|
| `SCAN_START` / `SCAN_COMPLETE` | Execution | Scan lifecycle with parameters and summary |
| `CONFIG_LOAD` | Configuration | Keywords or sources file loaded |
| `KEYWORD_START` / `KEYWORD_COMPLETE` | Execution | Per-keyword processing |
| `DORK_QUERY` | Access | DDG search query executed |
| `CAPTCHA_DETECTED` / `CAPTCHA_BLOCKED` | Security | Rate limiting events |
| `CVE_QUERY_START` / `CVE_QUERY_COMPLETE` / `CVE_QUERY_ERROR` | Access | NVD API calls |
| `GENAI_QUERY` / `GENAI_RESPONSE` / `GENAI_ERROR` | Access | Ask Sage API calls |
| `PERSONA_LOOKUP` | Configuration | Ask Sage persona resolved |
| `DATA_EXPORT` | Export | Output file written |
| `BROWSER_OPEN` / `BROWSER_CLOSE` | System | DDG session priming |

### Audit Record Content (AU-3)

Each audit record contains the six fields required by NIST SP 800-53 AU-3:

| AU-3 Requirement | Field | Example |
|---|---|---|
| (a) Type of event | `event_type` | `CVE_QUERY_COMPLETE` |
| (b) When it occurred | `timestamp` | `2026-02-18T14:30:00.000-05:00` |
| (c) Where it occurred | `source_system` + `source_host` | `Look4Gold13` on `WORKSTATION01` |
| (d) Source of event | `source_function` | `Invoke-NvdCveSearch` |
| (e) Outcome | `outcome` | `Success` / `Failure` / `Warning` |
| (f) Identity | `subject` | Username, keyword, or API name |

---

## Configuration

All configuration lives in the `config/` folder:

| File | Purpose | Git tracked? |
|---|---|---|
| `keywords.txt` | Your search keywords (one per line) | No (gitignored) |
| `keywords.example.txt` | Starter keywords showing the format | Yes |
| `sources.json` | Search dorks -- DDG site dorks + breach/news dorks | No (gitignored) |
| `sources.example.json` | Default dorks (reference copy) | Yes |
| `au13-config.example.asksage.json` | Ask Sage config template (reference) | Yes |
| `au13-config.example.grok.json` | Grok/xAI config template (reference) | Yes |

### Keywords

Copy the example and add your own terms:

```powershell
Copy-Item config/keywords.example.txt config/keywords.txt
```

Add organization-specific keywords like company names, domain names, project codenames, internal IP ranges, employee email patterns, etc. Lines starting with `#` are comments.

**Important:** Do not include classified or controlled information in the keywords file.

### Search Dorks

Copy the example and customize:

```powershell
Copy-Item config/sources.example.json config/sources.json
```

The `sources.json` file defines two groups of dorks:

- **`ddgDorks`** -- Target specific sites where leaked content commonly appears (Pastebin, GitHub, GitHub Gist, Reddit, Dropbox, Google Docs, Archive.org, and many paste sites).
- **`breachDorks`** -- Target breach/security news sources and concepts (breach news, ransomware reports, credential exposure, Have I Been Pwned, DataBreaches.net, BleepingComputer, KrebsOnSecurity, etc.).

Both groups are always included in every scan. Breach dorks run first since they tend to be the most actionable and DDG is least likely to be rate-limiting at the start of a scan.

Edit `sources.json` to add or remove dorks. See `sources.example.json` as a reference for the default set.

---

## How a Scan Runs (Step by Step)

1. **Load configuration** -- Keywords from `keywords.txt`, dorks from `sources.json`.
2. **Initialize audit log** -- Create the `Outputs/Scan_<timestamp>/` folder and begin NDJSON event logging.
3. **Group dorks** -- All `site:` dorks are combined into OR queries to minimize request count.
4. **Open DDG browser session** -- A minimized browser window opens `html.duckduckgo.com` to prime the session.
5. **Resolve persona** -- If `ASK_SAGE_API_KEY` is set, look up the "Look4Gold13" custom persona once.
6. **Per-keyword loop** -- For each keyword:
   - **Dork searches** -- Execute each dork group query with fresh browser identity, parse results, wait a randomized delay.
   - **CVE lookup** -- Query the NIST NVD API for CVEs matching the keyword (published in the last N days).
   - **GenAI query** -- Send the keyword, discovered URLs, and CVE findings to Ask Sage for AI-powered analysis with severity ratings.
7. **Results summary** -- Print scan statistics (duration, result counts, CAPTCHA events).
8. **Export NIST audit log** -- Write audit events to JSON and CSV in the scan output folder.
9. **Generate HTML report** -- Results organized by keyword with collapsible CVE and dork sections.
10. **Cleanup** -- The DDG browser window is closed.

---

## Example Usage

```powershell
# Full scan with defaults (dorks + CVE + GenAI, 7-day lookback)
.\Look4Gold13.ps1

# Quick test: only first 2 dorks, faster timing
.\Look4Gold13.ps1 -MaxDorks 2 -BaseDelay 30

# CVE-only: fast vulnerability check, no DDG or GenAI
.\Look4Gold13.ps1 -CveOnly

# CVE-only with 30-day lookback
.\Look4Gold13.ps1 -CveOnly -DaysBack 30

# Full scan with 14-day lookback for CVE and GenAI
.\Look4Gold13.ps1 -DaysBack 14

# Skip CVE lookup (dorks + GenAI only)
.\Look4Gold13.ps1 -NoCve

# Silent mode for scheduled tasks / automation
.\Look4Gold13.ps1 -Silent

# Custom keywords file
.\Look4Gold13.ps1 -KeywordFile "C:\scans\my-keywords.txt"

# Custom HTML report location
.\Look4Gold13.ps1 -OutputFile "C:\reports\scan-report.html"

# GenAI-only: just the Ask Sage intelligence query
.\Look4Gold13.ps1 -AgiOnly

# Disable audit logging (not recommended for compliance)
.\Look4Gold13.ps1 -NoAuditLog

# Maximum stealth: slow and steady
.\Look4Gold13.ps1 -BaseDelay 180 -MinJitter 15 -MaxJitter 45
```

---

## Environment Variables

| Variable | Required | Purpose |
|---|---|---|
| `ASK_SAGE_API_KEY` | No | Ask Sage API key for GenAI queries. Without it, GenAI is skipped. |
| `NVD_API_KEY` | No | NIST NVD API key for higher CVE query rate limits (50 vs 5 req/30s). |

---

## Requirements

- **PowerShell 5.1+** (ships with Windows 10/11) or PowerShell 7+
- **Internet access** to DuckDuckGo, `services.nvd.nist.gov` (NVD), and optionally `api.genai.army.mil` (Ask Sage)
- **A web browser** installed on the machine (Chrome, Edge, Firefox, or Brave -- used for DDG session priming)

---

## License

GNU General Public License v2.0 -- see [LICENSE](LICENSE) for details.
