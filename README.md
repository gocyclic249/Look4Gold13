# Look4Gold13 - AU-13 Compliance Scanner

A PowerShell script for monitoring compliance with **NIST SP 800-53 AU-13 (Monitoring for Information Disclosure)**.

AU-13 requires organizations to monitor open-source information and publicly accessible sites for evidence of unauthorized disclosure of organizational information.

## Quick Start

**1. Copy `Look4Gold13.ps1` and set up keywords:**

```powershell
Copy-Item config/keywords.example.txt keywords.txt
# Edit keywords.txt - add your organization-specific search terms
```

**2. Run the scanner:**

```powershell
# Interactive mode - prompts for all settings
.\Look4Gold13.ps1

# Silent mode - uses flags and defaults, no prompts
.\Look4Gold13.ps1 -Silent -GitHubToken "ghp_xxxx"
```

## Requirements

- PowerShell 7.0+
- GitHub Personal Access Token (required)
  - Create one at https://github.com/settings/tokens with `public_repo` scope

## Usage

### Interactive Mode (default)

Just run the script. It will prompt for everything:

```powershell
.\Look4Gold13.ps1
```

You'll be asked for:
- GitHub token (checks `$env:GITHUB_TOKEN` first)
- Keywords file path
- Days back to search
- Which sources to scan
- Output file path
- Google API key (optional)

### Silent Mode

Use the `-Silent` flag with parameters for automated/scheduled runs:

```powershell
# All defaults (30 days, all sources)
.\Look4Gold13.ps1 -Silent -GitHubToken "ghp_xxxx"

# Token from environment variable
$env:GITHUB_TOKEN = "ghp_xxxx"
.\Look4Gold13.ps1 -Silent

# Custom settings
.\Look4Gold13.ps1 -Silent -GitHubToken "ghp_xxxx" -DaysBack 7 -Sources Google,GitHub

# Specify output path
.\Look4Gold13.ps1 -Silent -GitHubToken "ghp_xxxx" -OutputFile "./my-report.html"
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Silent` | off | Skip prompts, use flags/defaults |
| `-GitHubToken` | `$env:GITHUB_TOKEN` | GitHub Personal Access Token (required) |
| `-KeywordFile` | `./keywords.txt` | Path to keywords file |
| `-DaysBack` | 30 | How many days back to search |
| `-Sources` | All | Which sources: `Google`, `Paste`, `GitHub`, `Breach` |
| `-OutputFile` | Auto-generated | Path for HTML report |
| `-GoogleApiKey` | none | Google Custom Search API key (optional) |
| `-GoogleSearchEngineId` | none | Google Custom Search Engine ID (optional) |

## Setting Up Google Custom Search (Optional)

Google Custom Search is optional but gives automated results for dork queries. Without it, the tool falls back to checking dork URLs directly.

> **Note:** Google's "Search the entire web" option for Programmable Search Engines has been deprecated. You must add specific sites to your search engine. This works fine for AU-13 monitoring since you're searching leak/disclosure sites anyway.

### Step 1: Create a Google Cloud Project and API Key

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project (or pick an existing one)
3. **Enable the Custom Search API** — this is easy to miss and causes 403 errors:
   - Go to **APIs & Services > Library**
   - Search for **"Custom Search API"**
   - Click it, then click **Enable**
4. Go to **APIs & Services > Credentials**
5. Click **Create Credentials > API Key**
6. Copy the key — this is your `-GoogleApiKey`

### Step 2: Create a Programmable Search Engine

1. Go to [Programmable Search Engine](https://programmablesearchengine.google.com/)
2. Click **Add**
3. Under "Sites to search", add the sites relevant to AU-13 monitoring:
   ```
   pastebin.com
   github.com
   trello.com
   paste.ee
   dpaste.org
   ghostbin.com
   haveibeenpwned.com
   krebsonsecurity.com
   bleepingcomputer.com
   securityweek.com
   databreaches.net
   cybernews.com
   ```
4. Give it a name (e.g. "AU13 Scanner") and click **Create**
5. Copy the **Search Engine ID** — this is your `-GoogleSearchEngineId`

### Troubleshooting 403 Forbidden Errors

If you get `403 Forbidden` from the Google API, check these in order:

1. **API not enabled** (most common) — Go to [Custom Search API page](https://console.cloud.google.com/apis/library/customsearch.googleapis.com) and make sure it says "Enabled", not "Enable"
2. **API key restrictions** — Under Credentials > your API key, check if IP or HTTP referrer restrictions are blocking your machine
3. **No billing account** — Some Google Cloud projects require a billing account linked even for free-tier APIs. Go to Billing and link an account (you won't be charged within the free tier)

**Free tier limits:** 100 queries/day. With 9 query templates per keyword, that's roughly 11 keywords/day before hitting the limit.

You can test your setup by pasting this URL in a browser (replace YOUR_KEY and YOUR_CX):
```
https://www.googleapis.com/customsearch/v1?key=YOUR_KEY&cx=YOUR_CX&q=test
```
If it returns JSON with results, you're good. If it returns an error, the message will tell you exactly what's wrong.

## Sources Scanned

| Source | Method | Auth Required |
|---|---|---|
| **Google Dorks** | Google Custom Search API or direct URL checks | Optional (API key) |
| **Paste Sites** | psbdmp.ws API + Google-indexed paste sites | No |
| **GitHub** | Code, commits, and issues via GitHub Search API | Yes (token) |
| **Breach Info** | HIBP breach database + security blog searches | No |

## Output

Results are saved as an **HTML report** with:
- Per-keyword sections showing query, result count, and clickable links
- Severity badges (Critical, High, Medium, Review, Manual-Review)
- Snippet previews for each finding

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
├── config/
│   ├── keywords.example.txt     # Starter keywords with common phrases
│   └── au13-config.example.json # Config template
└── src/                         # Original module files (reference)
```
