Look4Gold13 - Configuration Guide
====================================

This folder contains all configuration files for Look4Gold13.


KEYWORDS FILE (keywords.txt)
------------------------------------
The keywords file controls what the scanner searches for. One keyword or
phrase per line. Lines starting with # are comments and are ignored.

Setup:
  1. Copy the example file:
       Copy-Item config/keywords.example.txt config/keywords.txt

  2. Edit config/keywords.txt and add your organization-specific terms.

  3. keywords.txt is gitignored - it will never be committed to the repo.

IMPORTANT: Choose keywords carefully. Do not include classified or
controlled information. See keywords.example.txt for format examples.


ASK SAGE API KEY
------------------------------------
The AGI query is optional. If the ASK_SAGE_API_KEY environment variable
is set, the script sends your keywords to Ask Sage for AI-powered analysis
with severity ratings. Without it, you still get all the dork results.

Setup:
  1. Get an API key from:
       https://api.genai.army.mil > Settings > Account > Manage API Keys

  2. Set the environment variable:
       $env:ASK_SAGE_API_KEY = "your-key-here"

     Or set it permanently (persists across sessions):
       [System.Environment]::SetEnvironmentVariable("ASK_SAGE_API_KEY", "your-key", "User")
       # Restart PowerShell after setting this


SEARCH SOURCES FILE (sources.json)
------------------------------------
The sources file defines the search dorks used by the scanner. The default
file ships with the repo and works out of the box.

To customize:
  1. Edit config/sources.json directly. Use sources.example.json as a
     reference if you want to reset a section to defaults.

  2. Each section is replaced independently. If you provide ddgDorks, your
     entire list replaces the default DDG dorks. Omit a section (or set it
     to an empty array []) to keep the built-in defaults for that section.

  3. This file is NOT gitignored since it contains non-sensitive search
     patterns. Your changes will be tracked by git.

Sections:
  ddgDorks      DuckDuckGo search dorks including paste sites (label + dork query string)
  breachDorks   Breach/security news dorks (label + dork query string)

Both groups are always included in every scan. Breach dorks run first
since they tend to be the most actionable. Site dorks are automatically
batched into groups of 5 to avoid DDG query length limits.

Example - adding a custom DDG dork:
  Copy the full ddgDorks array from sources.example.json, then append:
    { "label": "My internal site", "dork": "site:internal.example.com" }


SCRIPT PARAMETERS
------------------------------------
-KeywordFile     Path to keywords file (default: config/keywords.txt)
-MaxDorks        Limit to first N dorks; 0 = all (default: 0)
-BaseDelay       Base seconds between DDG requests (default: 60)
-MinJitter       Min random seconds added to delay (default: 5)
-MaxJitter       Max random seconds added to delay (default: 15)
-VerboseOutput   Show extra debug info
-OutputFile      Custom path for CSV export
-NoExport        Suppress all file output (CSV, JSON, HTML)
-Silent          Suppress all console output (files still written)


OUTPUT FILES
------------------------------------
Look4Gold13_Report_<timestamp>.html   Combined HTML report (AGI + dork results)
Look4Gold13_AGI_<timestamp>.json      Structured AGI results with severity
Look4Gold13_Results_<timestamp>.csv   Flat dork results (Title, Summary, URL)


ASK SAGE SETTINGS (for advanced users)
------------------------------------
These settings are hardcoded in the script but documented here for reference:

  Endpoint:     https://api.genai.army.mil/server/query
  Model:        google-gemini-2.5-pro
  Persona:      0 (blank - no persona preamble)
  Temperature:  0.7
  Live search:  2 (live web search enabled)

The AGI prompt requests a JSON array with severity ratings
(Critical, High, Medium, Low, Informational) for each finding.


FILES IN THIS FOLDER
------------------------------------
README.txt                        This file
au13-config.example.asksage.json  Ask Sage config template (reference)
au13-config.example.grok.json     Grok (xAI) config template (reference)
keywords.example.txt              Starter keywords with example phrases
keywords.txt                      Your keywords (gitignored, create from example)
sources.json                      Search dorks and paste site config (editable)
sources.example.json              Default search sources (reference copy)
