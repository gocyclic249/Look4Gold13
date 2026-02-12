# DO NOT USE Latest UPDATE for NIPR completely broke this

> **ALPHA** — This script is in early alpha testing. Expect rough edges, breaking changes, and incomplete features. If you run into bugs or have ideas for improvements, please [open an issue](https://github.com/gocyclic249/Look4Gold13/issues) — feedback and recommendations are welcome!

> **CLASSIFICATION: UNCLASSIFIED**
>
> This script and repository are unclassified. However, the **keywords you search for may be sensitive**. The `config/keywords.txt` file is gitignored to prevent accidental disclosure, but exercise care when choosing search terms — do not include classified or controlled information in your keywords. Once results are generated, the HTML report should be handled according to your organization's data handling policies.

A PowerShell script for monitoring compliance with **NIST SP 800-53 AU-13 (Monitoring for Information Disclosure)**.

AU-13 requires organizations to monitor open-source information and publicly accessible sites for evidence of unauthorized disclosure of organizational information.

## Quick Start

**1. Copy `Look4Gold13.ps1` and set up keywords:**

```powershell
Copy-Item config/keywords.example.txt config/keywords.txt
# Edit config/keywords.txt - add your organization-specific search terms
```

**2. (Optional) Set up GenAI token for AI-powered summaries and Web UI:**

```powershell
[System.Environment]::SetEnvironmentVariable("GENAI_API_TOKEN", "your-key", "User")
# Restart PowerShell after setting User-level env vars
```

When a GenAI token is set, the script automatically launches the **Web UI** — a browser-based dashboard with real-time scan progress, keyword editing, AI analysis, and report generation.

**3. (Optional) Set up NVD API key for faster CVE searches:**

```powershell
[System.Environment]::SetEnvironmentVariable("NVD_API_KEY", "your-key", "User")
```

Without a key, NVD searches still work but are rate-limited to 5 requests per 30 seconds. With a key, the rate is 50 requests per 30 seconds. Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

**4. Run the scanner:**

```powershell
# Default mode - launches Web UI if GenAI token is set, otherwise interactive CLI
.\Look4Gold13.ps1

# Silent mode - uses defaults, no prompts, CLI only
.\Look4Gold13.ps1 -Silent

# Government computer with Menlo Security proxy
.\Look4Gold13.ps1 -UseProxy
```

## Requirements

- PowerShell 7.0+
- GenAI API token (optional, for AI summaries + Web UI default mode) — supports either:
  - **Ask Sage** (army.mil) — Settings > Account > Manage API Keys
  - **Grok** (xAI) — [xAI API Console](https://console.x.ai/)
- NVD API key (optional, for faster CVE queries) — [Request a free key](https://nvd.nist.gov/developers/request-an-api-key)

## Operational Modes

The script has three modes of operation:

### Web UI Mode (default when GenAI token is available)

When a GenAI API token is configured, the script automatically launches a **browser-based dashboard** at `http://localhost:<port>/`. No `-WebUI` flag needed.

Features:
- **Keyword editor** — add, remove, and save keywords directly in the browser (updates `config/keywords.txt`)
- **Real-time scan progress** — progress bar, per-search log, and live results table
- **AI analysis** — per-keyword AI summaries displayed inline
- **Report generation** — one-click HTML report export
- **Auto-shutdown** — server automatically stops 5 seconds after report generation
- **Manual shutdown** — "Shutdown Server" button always available in the page footer
- **Dual search mode** — automatically selects the right search strategy based on your network (see below)

```powershell
# Launches Web UI automatically (GenAI token must be set)
.\Look4Gold13.ps1

# Explicitly request Web UI
.\Look4Gold13.ps1 -WebUI

# Web UI on government network
.\Look4Gold13.ps1 -UseProxy
```

**Dual Search Mode:**

The Web UI automatically detects your network and picks the right search strategy:

| Network | Search Mode | Console Output |
|---|---|---|
| Direct (no proxy) | DDG + Breach + NVD | `[Search: Standard (DDG + Breach + NVD direct)]` |
| Government (Menlo proxy) | AskSage + NVD | `[Search: AskSage (gov network via Menlo proxy)]` |

On direct networks, the Web UI uses DuckDuckGo and Breach scraping (same as CLI mode). On government networks where web scraping is blocked by Menlo Security, it uses AskSage API for live web searches. **NIST NVD CVE searches work on all networks** — the NVD API is a .gov endpoint accessible directly.

### Interactive CLI Mode

When no GenAI token is set, the script falls back to interactive CLI mode and prompts for all settings:

```powershell
.\Look4Gold13.ps1
```

You'll be asked for:
- GenAI API token (optional, checks `$env:GENAI_API_TOKEN` first)
- Keywords file path
- Days back to search
- Which sources to scan
- Output file path

### Silent CLI Mode

Use the `-Silent` flag with parameters for automated/scheduled runs:

```powershell
# All defaults (30 days, all sources)
.\Look4Gold13.ps1 -Silent

# Custom settings
.\Look4Gold13.ps1 -Silent -DaysBack 7 -Sources DuckDuckGo,Breach

# Specify output path
.\Look4Gold13.ps1 -Silent -OutputFile "./my-report.html"

# Custom config file
.\Look4Gold13.ps1 -Silent -ConfigFile "./my-config.json"
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Silent` | off | Skip prompts, use flags/defaults (CLI mode) |
| `-WebUI` | auto | Launch browser-based dashboard (auto-enabled when GenAI token is set) |
| `-KeywordFile` | `./config/keywords.txt` | Path to keywords file |
| `-DaysBack` | 30 | How many days back to search |
| `-Sources` | All | Which sources: `DuckDuckGo`, `Breach` |
| `-OutputFile` | Auto-generated | Path for HTML report |
| `-ConfigFile` | `config/au13-config.json` | Path to config file |
| `-UseProxy` | off | Route searches through Menlo Security proxy (gov computers) |

## Sources Scanned

| Source | Method | Auth Required | Network |
|---|---|---|---|
| **DuckDuckGo** | HTML lite endpoint with `site:`, `filetype:`, and contextual dork queries (22 queries/keyword) covering code repos, paste sites, social media, file sharing, and archive sites — with CAPTCHA detection and retry | No | Direct |
| **Breach Info** | DuckDuckGo searches across security/breach sites in 8 query groups — only results with actual hits are included | No | Direct |
| **NIST NVD CVEs** | Direct API queries to the National Vulnerability Database for CVEs matching keywords, with CVSS severity mapping | No (optional API key for faster rate) | All networks |
| **AskSage Live Search** | AI-powered web search across 6 categories (paste sites, code repos, documents, breach DBs, security news, forums/social) | GenAI token | Gov network |

### Sites & Platforms Monitored

**Breach/Security News** (via Breach Info dorks): haveibeenpwned.com, databreaches.net, bleepingcomputer.com, krebsonsecurity.com, plus contextual searches for breach announcements, ransomware incidents, credential exposures, and BreachForums aggregator mentions.

**Social Media & Code** (via DuckDuckGo dorks): reddit.com, github.com, gist.github.com

**Paste Sites** (via DuckDuckGo dorks): pastebin.com, paste.ee, ghostbin.com, dpaste.org, rentry.co, justpaste.it, controlc.com, privatebin.net, 0bin.net, hastebin.com, ideone.com

**File Sharing & Archives** (via DuckDuckGo dorks): dropbox.com (public links), docs.google.com, archive.org

**Vulnerability Database**: NIST National Vulnerability Database (NVD) — CVEs with CVSS severity scores

> **Note:** All DuckDuckGo searches are routed through the HTML lite endpoint — no direct API access or authentication is needed for any of these sites.
>
> **Note:** Report links include a "DDG search" link for each finding so you can verify the search that found it. These URLs are also passed to GenAI for context.

## NIST NVD CVE Database

The scanner queries the [NIST National Vulnerability Database](https://nvd.nist.gov/) for CVEs matching your keywords within the configured time window. This runs in **all modes** (Web UI, Interactive CLI, Silent CLI) and on **all networks** (the NVD API is a .gov endpoint — no proxy needed).

### How It Works

- Searches `https://services.nvd.nist.gov/rest/json/cves/2.0` for each keyword
- Filters by publication date (based on your `-DaysBack` setting)
- Paginates automatically for large result sets
- Maps CVSS base scores to severity levels:

| CVSS Score | Severity |
|---|---|
| 9.0 - 10.0 | Critical |
| 7.0 - 8.9 | High |
| 4.0 - 6.9 | Medium |
| < 4.0 or unscored | Review |

### Rate Limiting

| Mode | Rate | How |
|---|---|---|
| No API key | 5 requests / 30 seconds (7s delay) | Default — works out of the box |
| With API key | 50 requests / 30 seconds (0.8s delay) | Set `$env:NVD_API_KEY` |

### Setting Up an API Key (Optional)

```powershell
# Get a free key at https://nvd.nist.gov/developers/request-an-api-key
[System.Environment]::SetEnvironmentVariable("NVD_API_KEY", "your-key", "User")
# Restart PowerShell after setting
```

The console will indicate which rate is active:
```
[NVD] API key detected - using fast rate
[NVD] No API key - using public rate (7s delay)
```

## Government Network / Menlo Security Proxy

Government computers typically route web traffic through [Menlo Security](https://safe.menlosecurity.com) web isolation. The script handles this in two ways:

**Web UI mode** (default): Automatically switches to **AskSage API** for web searches when a proxy is detected. AskSage performs live web searches server-side, bypassing Menlo's JavaScript-based isolation that blocks traditional web scraping. The console clearly shows the active mode:

```
Launching Web UI... [Search: AskSage (gov network via Menlo proxy)]

  Look4Gold13 Web UI running at: http://localhost:55306/
  Search mode: AskSage + NVD
```

**CLI mode**: Uses the `-UseProxy` flag to prefix DuckDuckGo URLs with the Menlo Security proxy base. Includes CAPTCHA detection, exponential backoff, and interstitial handling.

**NVD CVE searches always work** on government networks — the NVD API is a .gov endpoint that doesn't go through Menlo.

### Before Running with Proxy

1. Open a browser and go to [https://safe.menlosecurity.com](https://safe.menlosecurity.com)
2. Log in if prompted (usually only required after a reboot)
3. Once the page loads successfully, you're authenticated

### Usage

```powershell
# Interactive mode — will ask if you're on a government computer
.\Look4Gold13.ps1

# Skip the prompt and enable proxy directly
.\Look4Gold13.ps1 -UseProxy

# Silent mode with proxy
.\Look4Gold13.ps1 -Silent -UseProxy
```

In **interactive mode** (without `-UseProxy`), the script will ask if you're on a government computer and remind you to log into Menlo Security before continuing.

The proxy base URL defaults to `https://safe.menlosecurity.com` and can be changed via the `search.webProxyBase` config setting if your organization uses a different proxy.

## DuckDuckGo Rate Limiting & VPN Tip

DuckDuckGo may rate-limit or CAPTCHA-block requests depending on your source IP. Some ISPs (e.g., Starlink) are more aggressively rate-limited than others. If you're seeing frequent `[CAPTCHA]` or `[Error]` messages:

- **Use a VPN** — routing through a VPN like ProtonVPN typically avoids rate limiting
- **Use the Menlo proxy** (`-UseProxy`) — works well on government computers and also avoids direct IP-based rate limits
- **Increase the delay** — set `search.delaySeconds` to `5` or higher in your config file
- **Email addresses as keywords** — queries containing `@` (e.g., `user@domain.com`) trigger DDG's bot detection more aggressively, resulting in 403 errors. The script will automatically retry with exponential backoff, but expect slower scans when using email keywords. Using a VPN or the Menlo proxy helps.

## GenAI Summarization

When a GenAI API token is configured, the scanner sends results **per keyword** to an AI provider for analysis. The script supports two API backends:

| Provider | Config `apiType` | Endpoint | Auth Header |
|---|---|---|---|
| **Ask Sage** (default) | *(omit or leave blank)* | `https://api.genai.army.mil/server/query` | `x-access-tokens` |
| **Grok / OpenAI-compatible** | `"openai-compatible"` | `https://api.x.ai/v1/chat/completions` | `Authorization: Bearer` |

Each keyword section in the HTML report will include:

- Risk assessment
- Key findings summary
- Recommended actions
- Additional sources found by AI

The AI summary appears in a blue callout box below each keyword's results in the report.

Without a token, the scanner runs normally but skips AI summaries.

### Choosing a Provider

Copy the matching example config:

```powershell
# For Ask Sage (army.mil)
Copy-Item config/au13-config.example.asksage.json config/au13-config.json

# For Grok (xAI)
Copy-Item config/au13-config.example.grok.json config/au13-config.json
```

The key difference is the `apiType` field — set it to `"openai-compatible"` for Grok (or any OpenAI-compatible API), or omit it entirely for Ask Sage.

### Getting an API Key

**Ask Sage:**
1. Navigate to [Ask Sage](https://api.genai.army.mil)
2. Go to **Settings** > **Account** tab
3. Scroll to **Manage your API Keys** in the sidebar
4. Generate a new API key

> See the full [Ask Sage API Documentation](https://api.genai.army.mil/documentation/docs/api-documentation/api-documentation.html) for details.

**Grok (xAI):**
1. Navigate to the [xAI API Console](https://console.x.ai/)
2. Create an API key

> **Security:** Treat your API key like a password and rotate it regularly.

### Setting the Environment Variable

Set the token as a persistent Windows user environment variable so the script picks it up automatically (works for both providers):

```powershell
[System.Environment]::SetEnvironmentVariable("GENAI_API_TOKEN", "your-key", "User")
# Restart PowerShell after setting User-level env vars
```

Verify it's set:

```powershell
[System.Environment]::GetEnvironmentVariable("GENAI_API_TOKEN", "User")
```

Alternatively, in **interactive mode** the script will prompt you to paste a token if `$env:GENAI_API_TOKEN` is not set. This is useful for one-off runs without persisting the key.

## Config File

The config file lets you override the script's built-in defaults for GenAI and search settings. **The config file is entirely optional** — if it doesn't exist, the script uses its own hardcoded defaults and runs normally.

### How the Script Resolves Settings

1. The script starts with **built-in defaults** (30-day lookback, 3s delay, all sources, etc.)
2. If a config file exists, any settings in it **override** the matching defaults — settings you omit stay at their default values
3. Command-line parameters (`-DaysBack`, `-Sources`, etc.) **override** both the config file and defaults

The script looks for the config file at `config/au13-config.json` by default. To use a different path:

```powershell
.\Look4Gold13.ps1 -ConfigFile "./my-config.json"
```

### Creating a Config File

Copy the example matching your GenAI provider:

```powershell
# For Ask Sage
Copy-Item config/au13-config.example.asksage.json config/au13-config.json

# For Grok
Copy-Item config/au13-config.example.grok.json config/au13-config.json
```

You don't need to include every setting. For example, to only change the delay:

```json
{
    "search": {
        "delaySeconds": 5
    }
}
```

### All Config Options

**Ask Sage example:**

```json
{
    "genai": {
        "endpoint": "https://api.genai.army.mil/server/query",
        "tokenEnvVar": "GENAI_API_TOKEN",
        "model": "google-gemini-2.5-pro",
        "persona": 5,
        "temperature": 0.7,
        "limit_references": 5,
        "live": 1
    },
    "search": {
        "daysBack": 30,
        "delaySeconds": 5,
        "sources": ["DuckDuckGo", "Paste", "Breach"],
        "webProxyBase": "https://safe.menlosecurity.com"
    }
}
```

**Grok (OpenAI-compatible) example:**

```json
{
    "genai": {
        "endpoint": "https://api.x.ai/v1/chat/completions",
        "tokenEnvVar": "GENAI_API_TOKEN",
        "model": "grok-3",
        "temperature": 0.7,
        "apiType": "openai-compatible"
    },
    "search": {
        "daysBack": 30,
        "delaySeconds": 5,
        "sources": ["DuckDuckGo", "Paste", "Breach"]
    }
}
```

| Setting | Default | Description |
|---|---|---|
| `genai.endpoint` | `https://api.genai.army.mil/server/query` | API endpoint URL |
| `genai.tokenEnvVar` | `GENAI_API_TOKEN` | Environment variable name holding the API key |
| `genai.model` | `google-gemini-2.5-pro` | Model to use for summarization |
| `genai.apiType` | *(blank = Ask Sage)* | Set to `"openai-compatible"` for Grok/OpenAI-style APIs |
| `genai.persona` | `5` | Ask Sage persona ID (Ask Sage only) |
| `genai.temperature` | `0.7` | Response creativity (0.0 = deterministic, 1.0 = creative) |
| `genai.limit_references` | `5` | Max references returned by AI (Ask Sage only) |
| `genai.live` | `1` | Enable web search in AI responses (Ask Sage only, 1 = on, 0 = off) |
| `search.daysBack` | `30` | Default days back for searches |
| `search.delaySeconds` | `5` | Delay between DuckDuckGo requests (5+ recommended to avoid CAPTCHA) |
| `search.sources` | `["DuckDuckGo", "Paste", "Breach"]` | Default sources to scan |
| `search.webProxyBase` | `https://safe.menlosecurity.com` | Web isolation proxy base URL (used with `-UseProxy`) |

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GENAI_API_TOKEN` | Optional | GenAI API key (enables AI summaries + Web UI default mode) |
| `NVD_API_KEY` | Optional | NIST NVD API key (faster CVE queries: 50 req/30s vs 5 req/30s) |

## Output

Results are saved as an **HTML report** with:
- Per-keyword sections showing query, result count, and clickable links
- Severity badges (Critical, High, Medium, Review, Manual-Review)
- Snippet previews for each finding
- AI analysis per keyword (when GenAI token is configured)
- CVE entries with CVSS scores and links to NVD detail pages

Reports are saved to `./Output/AU13_Scan_<timestamp>.html` by default.

## Keywords File

The `config/keywords.txt` file contains your search terms (one per line). It is **gitignored** to prevent accidental disclosure of sensitive organizational terms.

A starter example with common test phrases is provided at `config/keywords.example.txt`.

```powershell
# Copy the example to get started
Copy-Item config/keywords.example.txt config/keywords.txt

# Then add your own terms at the bottom
```

In **Web UI mode**, keywords can also be edited directly in the browser — add, remove, and save without touching the file manually.

## Project Structure

```
Look4Gold13/
├── Look4Gold13.ps1                       # Main script (single-file, no dependencies)
├── README.md                             # This file
├── LICENSE                               # License
├── .gitignore
├── Output/                               # HTML reports (gitignored)
└── config/
    ├── README.txt                        # Configuration instructions
    ├── au13-config.example.asksage.json  # Ask Sage config template
    ├── au13-config.example.grok.json     # Grok (xAI) config template
    ├── au13-config.json                  # Your config (gitignored)
    ├── keywords.example.txt              # Starter keywords with common phrases
    ├── keywords.txt                      # Your keywords (gitignored)
    ├── sources.example.json              # Default search dorks reference
    └── sources.json                      # Editable search dorks
```
