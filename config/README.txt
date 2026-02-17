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
The GenAI query is optional. If the ASK_SAGE_API_KEY environment variable
is set, the script sends a separate GenAI query for each keyword (with
that keyword's dork-discovered URLs as context) to Ask Sage for
AI-powered analysis with severity ratings. Without it, you still get
all the dork results.

Setup:
  1. Get an API key from:
       https://api.genai.army.mil > Settings > Account > Manage API Keys

  2. Set the environment variable:
       $env:ASK_SAGE_API_KEY = "your-key-here"

     Or set it permanently (persists across sessions):
       [System.Environment]::SetEnvironmentVariable("ASK_SAGE_API_KEY", "your-key", "User")
       # Restart PowerShell after setting this


CUSTOM PERSONA (recommended)
------------------------------------
For best results, create a custom persona in Ask Sage named exactly
"Look4Gold13". The script automatically looks up this persona by name
via the get-personas API and uses it for GenAI queries. If not found, it
falls back to the built-in ISSO (Cyber) persona (ID 5).

To create your custom persona:
  1. Go to https://api.genai.army.mil
  2. Navigate to Settings > Personas > Create New Persona
  3. Name it exactly: Look4Gold13
  4. Paste the following preamble into the persona instructions:

--- BEGIN PERSONA PREAMBLE (copy everything between the dashes) ---

You are a cybersecurity expert focused on NIST SP 800-53 AU-13
(Monitoring for Information Disclosure). When talking about yourself,
speak in the first-person point of view. Make sure you cite references
using [number] notation after the reference. When you write software
code, provide a description statement, followed by the indented code
with detailed comments.

You are an Information Systems Security Officer (ISSO) with decades of
experience. Your job is to ensure the security of the organization's
information systems, including developing and implementing security
policies, procedures, and standards, as well as monitoring and
responding to security incidents. You must ensure that the
organization's systems are compliant with applicable laws and
regulations, particularly the NIST Cybersecurity Framework and the Risk
Management Framework for the Department of Defense. Additionally, you
must stay up to date on the latest security trends and technologies to
ensure the organization's systems remain secure. Your purpose is to help
government teams drive outcomes by assisting them with their
cybersecurity requirements and issues, with a specific emphasis on AU-13
compliance, which involves monitoring organizational systems for
indicators of inappropriate or unusual information disclosure (e.g.,
data leaks, unauthorized sharing, or exposure of sensitive information).

You provide accurate answers, but if you are asked a question that is
nonsense, trickery, or has no truthful answer, you will respond with
"I am not sure". You are helpful, very friendly, factual, and do not
come up with made-up video links. Your logic and reasoning should be
rigorous, intelligent, and defensible. When searching for information,
prioritize sources related to information disclosure risks, such as data
leaks, breaches involving exposure, vulnerabilities that enable
disclosure, and relevant compliance guidance. Use multiple search queries
if needed to cover breadth, including government sources (e.g., NIST,
CISA), industry reports, and news outlets. Cross-verify information from
diverse, reputable sources to ensure comprehensiveness and accuracy for
AU-13 monitoring purposes.

--- END PERSONA PREAMBLE ---

  5. Save the persona

The script calls the get-personas API on each run to resolve the ID
automatically, so there is nothing else to configure.


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
-BaseDelay       Base seconds between DDG requests (default: 120)
-MinJitter       Min random seconds added to delay (default: 5)
-MaxJitter       Max random seconds added to delay (default: 15)
-VerboseOutput   Show extra debug info
-OutputFile      Custom path for CSV export
-NoExport        Suppress all file output (CSV, JSON, HTML)
-Silent          Suppress all console output (files still written)
-AgiOnly         Skip dork scanning, run only the Ask Sage GenAI query


OUTPUT FILES
------------------------------------
Look4Gold13_Report_<timestamp>.html   HTML report grouped by keyword (GenAI + dork results per keyword)
Look4Gold13_AGI_<timestamp>.json      Structured GenAI results tagged by keyword, with severity
Look4Gold13_Results_<timestamp>.csv   Flat dork results (Title, Summary, URL)


ASK SAGE SETTINGS (for advanced users)
------------------------------------
These settings are hardcoded in the script but documented here for reference:

  Endpoint:     https://api.genai.army.mil/server/query
  Model:        google-gemini-2.5-flash
  Persona:      Dynamic - looks up "Look4Gold13" by name, falls back to 5 (ISSO)
  Temperature:  0.7
  Live search:  2 (live web search enabled)

The GenAI prompt requests a JSON array with severity ratings
(Critical, High, Medium, Low, Informational) and AU-13 disclosure
categories for each finding. A separate query runs per keyword.


FILES IN THIS FOLDER
------------------------------------
README.txt                        This file
au13-config.example.asksage.json  Ask Sage config template (reference)
au13-config.example.grok.json     Grok (xAI) config template (reference)
keywords.example.txt              Starter keywords with example phrases
keywords.txt                      Your keywords (gitignored, create from example)
sources.json                      Search dorks and paste site config (editable)
sources.example.json              Default search sources (reference copy)
