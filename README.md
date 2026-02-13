# Look4Gold13

**AU-13 Publicly Available Content (PAC) scanner for NIST SP 800-53 compliance.**

Look4Gold13 automates the process of searching for your organization's publicly exposed information across the internet. It combines DuckDuckGo search dorking with AGI-powered intelligence gathering (via Ask Sage) to find leaked credentials, breached data, exposed documents, misconfigured cloud resources, and more. Results are compiled into an HTML report with severity ratings.

---

## What It Does

1. **Search Dorking** -- Takes your keywords (company names, domains, project names, etc.) and combines them with a library of search dorks targeting paste sites, code repos, breach databases, and security news sources. Each keyword is searched against every dork via DuckDuckGo.

2. **AGI Intelligence** -- If an Ask Sage API key is configured, the tool sends your keywords (along with any URLs discovered during dorking) to a Gemini 2.5 Pro model with live web search enabled. The AGI searches broadly across the internet for recent cyber security events related to your keywords and assigns a severity rating (Critical, High, Medium, Low, or Informational) to each finding.

3. **Reporting** -- All results are compiled into three output files:
   - **HTML Report** (`Look4Gold13_Report_<timestamp>.html`) -- A styled, dark-themed report with AGI findings listed first (with color-coded severity badges), followed by search dork results. This is the primary deliverable.
   - **JSON** (`Look4Gold13_AGI_<timestamp>.json`) -- Structured AGI results with metadata, suitable for ingestion into other tools or SIEMs.
   - **CSV** (`Look4Gold13_Results_<timestamp>.csv`) -- Flat export of all dork results (Title, Summary, URL).

---

## Quick Start

```powershell
# 1. Set up keywords
Copy-Item config/keywords.example.txt config/keywords.txt
# Edit keywords.txt with your organization-specific terms

# 2. Run a scan
.\Look4Gold13.ps1

# 3. Run with fewer dorks for a quick test
.\Look4Gold13.ps1 -MaxDorks 4

# 4. Run silently (no console output, files only)
.\Look4Gold13.ps1 -Silent

# 5. Custom timing (slower to be gentler on DDG)
.\Look4Gold13.ps1 -BaseDelay 90 -MinJitter 10 -MaxJitter 30
```

### Ask Sage (AGI) Setup

The AGI query is optional but recommended. Without it you still get all the dork results; with it you get an additional layer of AI-driven intelligence.

```powershell
# Set your Ask Sage API key (get one from https://api.genai.army.mil > Settings > Account > Manage API Keys)
$env:ASK_SAGE_API_KEY = "your-api-key-here"

# Or set it permanently so it persists across sessions:
[System.Environment]::SetEnvironmentVariable("ASK_SAGE_API_KEY", "your-key", "User")
# Restart PowerShell after setting this
```

---

## How the Search Works (and Why It's Designed This Way)

### The Rate-Limit Problem

DuckDuckGo aggressively rate-limits automated queries. After just a handful of requests from the same session, DDG starts returning CAPTCHA pages or HTTP 202 responses instead of real search results. A naive script that fires requests in a loop will get blocked within minutes, making it useless for scanning dozens of keyword+dork combinations.

Look4Gold13 uses several techniques working together to avoid this:

### Browser Session Priming

Before any automated queries begin, the script opens the DuckDuckGo HTML endpoint (`https://html.duckduckgo.com/html/`) in a **new, minimized browser window** on the same machine. This is not just a convenience -- it has a real technical purpose.

When a browser visits DDG, it establishes cookies and a session that DDG's anti-bot system recognizes. Subsequent requests from the same IP address are treated more leniently because DDG sees that there's a "real" browser session active on that IP. Without this priming step, automated requests get flagged much faster.

The window is opened minimized so it stays out of your way, and it's automatically closed when the scan completes.

### Identity Rotation

Every single HTTP request uses a **completely fresh identity**:

- **New User-Agent** -- Randomly selected from a pool of 10 real browser profiles (Chrome 131/132, Firefox 133/134, Edge 131/132 across Windows and macOS). Each profile includes the correct matching `Sec-CH-UA` headers that the real browser would send. Firefox profiles correctly omit these headers, just like real Firefox does.
- **New session** -- Each request gets a fresh `WebRequestSession` (cookie jar), so there's no session tracking between requests.
- **Randomized Referer** -- Each request randomly includes or omits a Referer header, choosing from realistic DDG-related URLs.
- **Randomized parameters** -- Each DDG query varies the region (`us-en`, `uk-en`, `au-en`, `ca-en`, or worldwide) and date filter (anytime, past week, past month). This makes each request look like it came from a different user searching for different things.

The goal is that each request, looked at in isolation, appears to be a completely different person using a completely different browser.

### Timing and Jitter

Requests are spaced apart with a configurable delay plus random jitter:

- **Base delay** (default: 60 seconds) -- The minimum gap between requests.
- **Jitter** (default: 5-15 seconds) -- A random amount added on top of the base delay.

So by default, requests go out every 65-75 seconds. This mimics a human who searches, reads results, and then searches again. The randomness prevents a detectable fixed-interval pattern. You can tune these values with `-BaseDelay`, `-MinJitter`, and `-MaxJitter`.

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
4. If the retry also hits a CAPTCHA, it halts all remaining DDG queries (but still proceeds to the AGI step with whatever results it collected)

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-KeywordFile` | string | `config/keywords.txt` | Path to a custom keywords file |
| `-MaxDorks` | int | `0` (all) | Limit to the first N dorks. Useful for quick tests |
| `-BaseDelay` | int | `60` | Base seconds to wait between DDG requests |
| `-MinJitter` | int | `5` | Minimum random seconds added to the delay |
| `-MaxJitter` | int | `15` | Maximum random seconds added to the delay |
| `-VerboseOutput` | switch | off | Show extra debug info (saved HTML on empty results, etc.) |
| `-OutputFile` | string | auto-timestamped | Custom path for the CSV export |
| `-NoExport` | switch | off | Suppress all file output (CSV, JSON, HTML) |
| `-Silent` | switch | off | Suppress all console output. Files are still written |

---

## Output Files

All output files are written to the script's directory with timestamps in the filename.

| File | Format | Contents |
|---|---|---|
| `Look4Gold13_Report_<timestamp>.html` | HTML | Combined report -- AGI intelligence (with severity badges) followed by dork results. Open in any browser. |
| `Look4Gold13_AGI_<timestamp>.json` | JSON | Structured AGI results: `{ metadata: {...}, results: [{severity, title, summary, link, ...}] }` |
| `Look4Gold13_Results_<timestamp>.csv` | CSV | Flat dork results: Title, Summary, URL |

---

## Configuration

All configuration lives in the `config/` folder:

| File | Purpose | Git tracked? |
|---|---|---|
| `keywords.txt` | Your search keywords (one per line) | No (gitignored) |
| `keywords.example.txt` | Starter keywords showing the format | Yes |
| `sources.json` | Search dorks -- DDG site dorks + breach/news dorks | Yes |
| `sources.example.json` | Default dorks (reference copy) | Yes |

### Keywords

Copy the example and add your own terms:

```powershell
Copy-Item config/keywords.example.txt config/keywords.txt
```

Add organization-specific keywords like company names, domain names, project codenames, internal IP ranges, employee email patterns, etc. Lines starting with `#` are comments.

**Important:** Do not include classified or controlled information in the keywords file.

### Search Dorks

The `sources.json` file defines two groups of dorks:

- **`ddgDorks`** -- Target specific sites where leaked content commonly appears (Pastebin, GitHub, GitHub Gist, Reddit, Dropbox, Google Docs, Archive.org, and many paste sites).
- **`breachDorks`** -- Target breach/security news sources and concepts (breach news, ransomware reports, credential exposure, Have I Been Pwned, DataBreaches.net, BleepingComputer, KrebsOnSecurity, etc.).

Both groups are always included in every scan. Breach dorks run first since they tend to be the most actionable and DDG is least likely to be rate-limiting at the start of a scan.

You can edit `sources.json` directly to add or remove dorks. See `sources.example.json` as a reference.

---

## How a Scan Runs (Step by Step)

1. **Load configuration** -- Keywords from `keywords.txt`, dorks from `sources.json`.
2. **Group dorks** -- All `site:` dorks are combined into OR queries to minimize request count.
3. **Open DDG browser session** -- A minimized browser window opens `html.duckduckgo.com` to prime the session.
4. **Execute searches** -- For each keyword, for each dork group: build a randomized DDG query, send it with a fresh browser identity, parse results, wait a randomized delay.
5. **Collect and deduplicate** -- Results are deduplicated by keyword+URL.
6. **Export CSV** -- Dork results are saved to a CSV file.
7. **AGI query** -- If `ASK_SAGE_API_KEY` is set, keywords and discovered URLs are sent to Ask Sage for AI-powered analysis with severity ratings.
8. **Export JSON** -- AGI results are saved as structured JSON.
9. **Generate HTML report** -- AGI findings (with severity) and dork results are combined into a styled HTML report.
10. **Cleanup** -- The DDG browser window is closed.

---

## Example Usage

```powershell
# Full scan with defaults (all dorks, 60s+jitter between requests)
.\Look4Gold13.ps1

# Quick test: only first 2 dorks, faster timing
.\Look4Gold13.ps1 -MaxDorks 2 -BaseDelay 30

# Silent mode for scheduled tasks / automation
.\Look4Gold13.ps1 -Silent

# Custom keywords file
.\Look4Gold13.ps1 -KeywordFile "C:\scans\my-keywords.txt"

# Custom output location
.\Look4Gold13.ps1 -OutputFile "C:\reports\scan-results.csv"

# Maximum stealth: slow and steady
.\Look4Gold13.ps1 -BaseDelay 120 -MinJitter 15 -MaxJitter 45
```

---

## Requirements

- **PowerShell 5.1+** (ships with Windows 10/11) or PowerShell 7+
- **Internet access** to DuckDuckGo and optionally to `api.genai.army.mil` (Ask Sage)
- **A web browser** installed on the machine (Chrome, Edge, Firefox, or Brave -- used for DDG session priming)

---

## License

GNU General Public License v2.0 -- see [LICENSE](LICENSE) for details.
