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
