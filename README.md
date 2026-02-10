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

## Sources Scanned

| Source | Method | Auth Required |
|---|---|---|
| **DuckDuckGo** | HTML lite endpoint with grouped `site:` and `filetype:` OR queries (4 queries per keyword) with CAPTCHA detection and retry | No |
| **Paste Sites** | psbdmp.ws API + DuckDuckGo-indexed paste sites (Pastebin, Paste.ee, Ghostbin, Dpaste, Rentry, JustPaste.it, ControlC, PrivateBin) | No |
| **Breach Info** | DuckDuckGo searches across 19 security/breach blogs and forums | No |

### Security Blogs & Breach Sites Monitored

haveibeenpwned.com, krebsonsecurity.com, bleepingcomputer.com, securityweek.com, therecord.media, databreaches.net, breachdirectory.org, cybernews.com, hackread.com, securityaffairs.com, darkreading.com, thehackernews.com, schneier.com, grahamcluley.com, csoonline.com, infosecurity-magazine.com, arstechnica.com, reddit.com/r/netsec, reddit.com/r/cybersecurity

> **Note:** GitHub is searched via DuckDuckGo `site:github.com` dorks, which avoids the strict rate limits of the GitHub Search API. No GitHub token is required.

## GenAI Summarization

When a GenAI API token is configured, the scanner sends results **per keyword** to Ask Sage for AI-powered analysis. Each keyword section in the HTML report will include:

- Risk assessment
- Key findings summary
- Recommended actions

The AI summary appears in a blue callout box below each keyword's results in the report.

### Setup

1. Get an API key from [Ask Sage](https://asksage.ai/) (Settings > Account > Manage API Keys)
2. Set the environment variable:
   ```powershell
   [System.Environment]::SetEnvironmentVariable("GENAI_API_TOKEN", "your-key", "User")
   # Restart PowerShell after setting User-level env vars
   ```
3. Or just paste it when prompted in interactive mode

Without a token, the scanner runs normally but skips AI summaries.

## Config File

The config file (`config/au13-config.json`) controls GenAI and search settings. Copy the example to get started:

```powershell
Copy-Item config/au13-config.example.json config/au13-config.json
```

### Config Options

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
        "sources": ["DuckDuckGo", "Paste", "Breach"]
    }
}
```

| Setting | Description |
|---|---|
| `genai.endpoint` | GenAI API URL (change if using a different provider) |
| `genai.tokenEnvVar` | Name of the environment variable holding the API token |
| `genai.model` | Model to use for summarization |
| `genai.persona` | Ask Sage persona ID |
| `genai.temperature` | Response creativity (0.0 = deterministic, 1.0 = creative) |
| `genai.limit_references` | Max references returned by AI |
| `genai.live` | Enable web search in AI responses (1 = on, 0 = off) |
| `search.daysBack` | Default days back for searches |
| `search.delaySeconds` | Delay between DuckDuckGo requests (3+ recommended to avoid CAPTCHA) |
| `search.sources` | Default sources to scan |

All settings have built-in defaults. The config file is optional — only include the settings you want to override.

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
