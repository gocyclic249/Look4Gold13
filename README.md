# Look4Gold13

**AU-13 Publicly Available Content (PAC) scanner for NIST SP 800-53 compliance.**

Look4Gold13 automates the process of searching for your organization's publicly exposed information across the internet. It combines DuckDuckGo search dorking with GenAI-powered intelligence gathering (via Ask Sage) to find leaked credentials, breached data, exposed documents, misconfigured cloud resources, and more. Results are compiled into an HTML report with severity ratings.

---

## What It Does

1. **Search Dorking** -- Takes your keywords (company names, domains, project names, etc.) and combines them with a library of search dorks targeting paste sites, code repos, breach databases, and security news sources. Each keyword is searched against every dork via DuckDuckGo.

2. **GenAI Intelligence** -- If an Ask Sage API key is configured, a **separate GenAI query runs for each keyword** immediately after that keyword's dork searches complete. Each query sends the keyword (along with any URLs discovered during its dorking) to a Gemini 2.5 Flash model with live web search enabled. The GenAI searches broadly across the internet for recent cyber security events and assigns a severity rating (Critical, High, Medium, Low, or Informational) to each finding. Running per-keyword gives the GenAI more focused results than a single combined query.

3. **Reporting** -- All results are compiled into three output files:
   - **HTML Report** (`Look4Gold13_Report_<timestamp>.html`) -- A styled, dark-themed report organized by keyword. Each keyword section shows its GenAI findings (with color-coded severity badges) followed by its dork results. This is the primary deliverable.
   - **JSON** (`Look4Gold13_AGI_<timestamp>.json`) -- Structured GenAI results with metadata, suitable for ingestion into other tools or SIEMs.
   - **CSV** (`Look4Gold13_Results_<timestamp>.csv`) -- Flat export of all dork results (Title, Summary, URL).

**Note:** Some variable names, parameter flags (e.g., `-AgiOnly`), and output filenames (e.g., `Look4Gold13_AGI_*.json`) still use "AGI" instead of "GenAI". This is a naming mix-up from early development — the feature uses generative AI (GenAI), not artificial general intelligence (AGI). The code-level names are kept as-is to avoid breaking changes.

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

# 5. GenAI-only mode (skip dork scanning, just Ask Sage)
.\Look4Gold13.ps1 -AgiOnly

# 6. Custom timing (slower to be gentler on DDG)
.\Look4Gold13.ps1 -BaseDelay 90 -MinJitter 10 -MaxJitter 30
```

### Ask Sage (GenAI) Setup

The GenAI query is optional but recommended. Without it you still get all the dork results; with it you get an additional layer of AI-driven intelligence.

```powershell
# Set your Ask Sage API key (get one from https://api.genai.army.mil > Settings > Account > Manage API Keys)
$env:ASK_SAGE_API_KEY = "your-api-key-here"

# Or set it permanently so it persists across sessions:
[System.Environment]::SetEnvironmentVariable("ASK_SAGE_API_KEY", "your-key", "User")
# Restart PowerShell after setting this
```

### Custom Persona (Recommended)

For best results, create a custom persona in Ask Sage named exactly **Look4Gold13**. The script automatically looks up this persona by name via the `get-personas` API and uses it for GenAI queries. If not found, it falls back to the built-in ISSO (Cyber) persona (ID 5).

**To create the persona:**

1. Go to https://api.genai.army.mil
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

### GenAI-Only Mode

To skip dork scanning and run only the Ask Sage GenAI query:

```powershell
.\Look4Gold13.ps1 -AgiOnly
```

This is useful for quick intelligence checks without the time cost of DDG scanning.

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
4. If the retry also hits a CAPTCHA, it halts DDG queries for this keyword (but still runs the per-keyword GenAI query with whatever results were collected, and continues to subsequent keywords)

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-KeywordFile` | string | `config/keywords.txt` | Path to a custom keywords file |
| `-MaxDorks` | int | `0` (all) | Limit to the first N dorks. Useful for quick tests |
| `-BaseDelay` | int | `120` | Base seconds to wait between DDG requests |
| `-MinJitter` | int | `5` | Minimum random seconds added to the delay |
| `-MaxJitter` | int | `15` | Maximum random seconds added to the delay |
| `-VerboseOutput` | switch | off | Show extra debug info (saved HTML on empty results, etc.) |
| `-OutputFile` | string | auto-timestamped | Custom path for the CSV export |
| `-NoExport` | switch | off | Suppress all file output (CSV, JSON, HTML) |
| `-Silent` | switch | off | Suppress all console output. Files are still written |
| `-AgiOnly` | switch | off | Skip dork scanning, run only the Ask Sage GenAI query |

---

## Time Estimates

Scan duration depends on the number of keywords, the number of dork groups, and the base delay. The default `sources.json` ships with 26 dorks that get batched into **13 query groups** per keyword.

**Per-keyword breakdown (defaults: 120s base + 5-15s jitter):**

| Phase | Time | Notes |
|---|---|---|
| DDG dork searches | ~28 min | 13 query groups x ~130s average delay |
| Ask Sage GenAI query | ~30 sec | Single API call with live web search |
| **Total per keyword** | **~28-29 min** | |

**Multi-keyword examples:**

| Keywords | Dorks Mode | Estimated Total |
|---|---|---|
| 1 keyword | Full (all dorks) | ~29 min |
| 3 keywords | Full (all dorks) | ~87 min (~1.5 hrs) |
| 5 keywords | Full (all dorks) | ~145 min (~2.4 hrs) |
| 5 keywords | `-MaxDorks 4` | ~35 min |
| Any count | `-AgiOnly` | ~30 sec per keyword |

**Tips for faster scans:**
- Use `-MaxDorks N` to limit to the first N dorks (e.g., `-MaxDorks 4` runs only 4 groups)
- Use `-AgiOnly` to skip dork scanning entirely (just the GenAI intelligence query)
- Lower `-BaseDelay` to reduce wait time between queries (increases CAPTCHA risk)

The script displays its own time estimate at the start of each run based on your actual parameters.

---

## Output Files

All output files are written to the script's directory with timestamps in the filename.

| File | Format | Contents |
|---|---|---|
| `Look4Gold13_Report_<timestamp>.html` | HTML | Report organized by keyword -- each section shows GenAI findings (with severity badges) then dork results. Open in any browser. |
| `Look4Gold13_AGI_<timestamp>.json` | JSON | Structured GenAI results tagged by keyword: `{ metadata: {...}, results: [{keyword, severity, title, summary, link, ...}] }` |
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
4. **Resolve persona** -- If `ASK_SAGE_API_KEY` is set, look up the "Look4Gold13" custom persona once.
5. **Per-keyword loop** -- For each keyword:
   - **Dork searches** -- Execute each dork group query with fresh browser identity, parse results, wait a randomized delay.
   - **GenAI query** -- Send the keyword and its discovered URLs to Ask Sage for AI-powered analysis with severity ratings.
6. **Collect and deduplicate** -- Results are deduplicated by keyword+URL.
7. **Export CSV** -- Dork results are saved to a CSV file.
8. **Export JSON** -- GenAI results (tagged by keyword) are saved as structured JSON.
9. **Generate HTML report** -- Results are organized by keyword, each section showing GenAI findings then dork results.
10. **Cleanup** -- The DDG browser window is closed.

---

## Example Usage

```powershell
# Full scan with defaults (all dorks, 120s+jitter between requests)
.\Look4Gold13.ps1

# Quick test: only first 2 dorks, faster timing
.\Look4Gold13.ps1 -MaxDorks 2 -BaseDelay 30

# Silent mode for scheduled tasks / automation
.\Look4Gold13.ps1 -Silent

# Custom keywords file
.\Look4Gold13.ps1 -KeywordFile "C:\scans\my-keywords.txt"

# Custom output location
.\Look4Gold13.ps1 -OutputFile "C:\reports\scan-results.csv"

# GenAI-only: just the Ask Sage intelligence query
.\Look4Gold13.ps1 -AgiOnly

# Maximum stealth: slow and steady (default is already 120s base)
.\Look4Gold13.ps1 -BaseDelay 180 -MinJitter 15 -MaxJitter 45
```

---

## Requirements

- **PowerShell 5.1+** (ships with Windows 10/11) or PowerShell 7+
- **Internet access** to DuckDuckGo and optionally to `api.genai.army.mil` (Ask Sage)
- **A web browser** installed on the machine (Chrome, Edge, Firefox, or Brave -- used for DDG session priming)

---

## License

GNU General Public License v2.0 -- see [LICENSE](LICENSE) for details.
