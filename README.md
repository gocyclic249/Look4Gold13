# Look4Gold13 - AU-13 Compliance Scanner

> **CLASSIFICATION: UNCLASSIFIED**
>
> This script and repository are unclassified. However, the **keywords you search for may be sensitive**. The `keywords.txt` file is gitignored to prevent accidental disclosure, but exercise care when choosing search terms — do not include classified or controlled information in your keywords. Once results are generated, the HTML report should be handled according to your organization's data handling policies.

A PowerShell script for monitoring compliance with **NIST SP 800-53 AU-13 (Monitoring for Information Disclosure)**.

AU-13 requires organizations to monitor open-source information and publicly accessible sites for evidence of unauthorized disclosure of organizational information.

## Quick Start

**1. Copy `Look4Gold13.ps1` and set up keywords:**

```powershell
Copy-Item config/keywords.example.txt keywords.txt
# Edit keywords.txt - add your organization-specific search terms
```

**2. (Optional) Set up GenAI token for AI-powered summaries:**

```powershell
[System.Environment]::SetEnvironmentVariable("GENAI_API_TOKEN", "your-key", "User")
```

**3. Run the scanner:**

```powershell
# Interactive mode - prompts for everything
.\Look4Gold13.ps1

# Silent mode - uses defaults, no prompts
.\Look4Gold13.ps1 -Silent
```

## Requirements

- PowerShell 7.0+
- Ask Sage GenAI API token (optional, for AI summaries)
  - Get one from Ask Sage: Settings > Account > Manage API Keys

## Usage

### Interactive Mode (default)

Just run the script. It will prompt for everything:

```powershell
.\Look4Gold13.ps1
```

You'll be asked for:
- GenAI API token (optional, checks `$env:GENAI_API_TOKEN` first)
- Keywords file path
- Days back to search
- Which sources to scan
- Output file path

### Silent Mode

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
| `-Silent` | off | Skip prompts, use flags/defaults |
| `-KeywordFile` | `./keywords.txt` | Path to keywords file |
| `-DaysBack` | 30 | How many days back to search |
| `-Sources` | All | Which sources: `DuckDuckGo`, `Paste`, `Breach` |
| `-OutputFile` | Auto-generated | Path for HTML report |
| `-ConfigFile` | `config/au13-config.json` | Path to config file |
| `-UseProxy` | off | Route searches through Menlo Security proxy (gov computers) |

## Government Network / Menlo Security Proxy

Government computers typically route web traffic through [Menlo Security](https://safe.menlosecurity.com) web isolation. The script supports this with the `-UseProxy` flag, which prefixes all DuckDuckGo URLs with the Menlo Security proxy base.

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

## Sources Scanned

| Source | Method | Auth Required |
|---|---|---|
| **DuckDuckGo** | HTML lite endpoint with grouped `site:` and `filetype:` OR queries (5 queries/keyword) with CAPTCHA detection and retry | No |
| **Paste Sites** | Manual DuckDuckGo search links for 8 paste sites (Pastebin, Paste.ee, Ghostbin, Dpaste, Rentry, JustPaste.it, ControlC, PrivateBin) | No |
| **Breach Info** | DuckDuckGo searches across 15 security/breach sites in 5 groups — only results with actual hits are included | No |

### Security Blogs & Breach Sites Monitored

haveibeenpwned.com, krebsonsecurity.com, bleepingcomputer.com, securityweek.com, therecord.media, databreaches.net, breachdirectory.org, cybernews.com, hackread.com, securityaffairs.com, darkreading.com, thehackernews.com, schneier.com, arstechnica.com, reddit.com/r/netsec, reddit.com/r/cybersecurity

> **Note:** GitHub is searched via DuckDuckGo `site:github.com` dorks, which avoids the strict rate limits of the GitHub Search API. No GitHub token is required.
>
> **Note:** Report links include a "DDG search" link for each finding so you can verify the search that found it. These URLs are also passed to GenAI for context.

## GenAI Summarization

When a GenAI API token is configured, the scanner sends results **per keyword** to [Ask Sage](https://api.genai.army.mil) for AI-powered analysis. Each keyword section in the HTML report will include:

- Risk assessment
- Key findings summary
- Recommended actions

The AI summary appears in a blue callout box below each keyword's results in the report.

Without a token, the scanner runs normally but skips AI summaries.

### Getting an API Key

1. Navigate to [Ask Sage](https://api.genai.army.mil)
2. Go to **Settings** > **Account** tab
3. Scroll to **Manage your API Keys** in the sidebar
4. Generate a new API key

> **Security:** Treat your API key like a password and rotate it regularly. See the full [Ask Sage API Documentation](https://api.genai.army.mil/documentation/docs/api-documentation/api-documentation.html) for details.

### Setting the Environment Variable

Set the token as a persistent Windows user environment variable so the script picks it up automatically:

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

Copy the example to get started:

```powershell
Copy-Item config/au13-config.example.json config/au13-config.json
# Edit config/au13-config.json — only include settings you want to change
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

```json
{
    "genai": {
        "endpoint": "https://api.genai.army.mil/server/query",
        "tokenEnvVar": "GENAI_API_TOKEN",
        "model": "google-claude-45-sonnet",
        "persona": 5,
        "temperature": 0.7,
        "limit_references": 5,
        "live": 1
    },
    "search": {
        "daysBack": 30,
        "delaySeconds": 3,
        "sources": ["DuckDuckGo", "Paste", "Breach"],
        "webProxyBase": "https://safe.menlosecurity.com"
    }
}
```

| Setting | Default | Description |
|---|---|---|
| `genai.endpoint` | `https://api.genai.army.mil/server/query` | Ask Sage API endpoint |
| `genai.tokenEnvVar` | `GENAI_API_TOKEN` | Environment variable name holding the API key |
| `genai.model` | `google-claude-45-sonnet` | Model to use for summarization |
| `genai.persona` | `5` | Ask Sage persona ID |
| `genai.temperature` | `0.7` | Response creativity (0.0 = deterministic, 1.0 = creative) |
| `genai.limit_references` | `5` | Max references returned by AI |
| `genai.live` | `1` | Enable web search in AI responses (1 = on, 0 = off) |
| `search.daysBack` | `30` | Default days back for searches |
| `search.delaySeconds` | `3` | Delay between DuckDuckGo requests (3+ recommended to avoid CAPTCHA) |
| `search.sources` | `["DuckDuckGo", "Paste", "Breach"]` | Default sources to scan |
| `search.webProxyBase` | `https://safe.menlosecurity.com` | Web isolation proxy base URL (used with `-UseProxy`) |

## Output

Results are saved as an **HTML report** with:
- Per-keyword sections showing query, result count, and clickable links
- Severity badges (Critical, High, Medium, Review, Manual-Review)
- Snippet previews for each finding
- AI analysis per keyword (when GenAI token is configured)

Reports are saved to `./Output/AU13_Scan_<timestamp>.html` by default.

## Keywords File

The `keywords.txt` file contains your search terms (one per line). It is **gitignored** to prevent accidental disclosure of sensitive organizational terms.

A starter example with common test phrases is provided at `config/keywords.example.txt`.

```powershell
# Copy the example to get started
Copy-Item config/keywords.example.txt keywords.txt

# Then add your own terms at the bottom
```

## Project Structure

```
Look4Gold13/
├── Look4Gold13.ps1              # Main script (copy this)
├── keywords.txt                 # Your keywords (gitignored)
├── Output/                      # HTML reports (gitignored)
└── config/
    ├── au13-config.example.json # Config template (copy to au13-config.json)
    ├── au13-config.json         # Your config (gitignored)
    └── keywords.example.txt    # Starter keywords with common phrases
```
