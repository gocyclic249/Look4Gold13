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
that keyword's dork-discovered URLs and CVE findings as context) to
Ask Sage for AI-powered analysis with severity ratings. Without it, you
still get all the dork results and CVE findings.

Setup:
  1. Get an API key from:
       https://chat.genai.army.mil/ > Settings > Account > Manage API Keys

  2. Set the environment variable:
       $env:ASK_SAGE_API_KEY = "your-key-here"

     Or set it permanently (persists across sessions):
       [System.Environment]::SetEnvironmentVariable("ASK_SAGE_API_KEY", "your-key", "User")
       # Restart PowerShell after setting this


NVD API KEY (optional)
------------------------------------
CVE lookups work without an API key but are rate-limited to 5 requests
per 30 seconds. With a free NVD API key, you get 50 requests per 30s.

Setup:
  1. Request a key at:
       https://nvd.nist.gov/developers/request-an-api-key

  2. Set the environment variable:
       $env:NVD_API_KEY = "your-key-here"

     Or set it permanently:
       [System.Environment]::SetEnvironmentVariable("NVD_API_KEY", "your-key", "User")
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
The sources file defines the search dorks used by the scanner.

Setup:
  1. Copy the example file to create your active config:
       Copy-Item config/sources.example.json config/sources.json

  2. Edit config/sources.json to add or remove dorks. Use
     sources.example.json as a reference for the default set.

  3. sources.json is gitignored - your customizations stay local.

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
-DaysBack        Lookback period in days for CVE + GenAI searches (default: 7)
-VerboseOutput   Show extra debug info (NVD pagination, empty DDG results, etc.)
-OutputFile      Custom path for the HTML report
-NoExport        Suppress all file output (HTML, audit logs)
-Silent          Suppress all console output (files still written)
-AgiOnly         Skip dork scanning and CVE, run only Ask Sage GenAI query
-CveOnly         Run only CVE lookup (no dork scanning, no GenAI)
-NoCve           Disable CVE lookup (dorks + GenAI only)
-CveMaxResults   Max CVE results per keyword (default: 100)
-AuditLogFile    Custom path for the NDJSON audit log stream
-NoAuditLog      Disable audit logging (not recommended for compliance)

Mutually exclusive: -CveOnly cannot be combined with -AgiOnly or -NoCve.


OUTPUT FILES
------------------------------------
All outputs are written to: Outputs/Scan_<yyyy-MM-dd_HHmm>/

Look4Gold13_Report_<timestamp>.html     HTML report (GenAI visible, CVE + dorks collapsible)
Look4Gold13_Audit_<timestamp>.json      NIST AU-2/AU-3 audit log (structured JSON with metadata)
Look4Gold13_Audit_<timestamp>.csv       NIST AU-2/AU-3 audit log (Excel-compatible CSV)
Look4Gold13_Audit_<timestamp>.jsonl     Real-time NDJSON event stream (one JSON record per line)


NIST AU-2/AU-3 AUDIT LOGGING
------------------------------------
Every significant scan event is recorded in a structured audit log.

AU-2 (Audit Events) - The following event types are defined:
  AUDIT_LOG_INIT           Audit log file initialized
  SCAN_START / COMPLETE    Scan lifecycle (includes parameters and summary)
  CONFIG_LOAD              Keywords or sources file loaded
  KEYWORD_START / COMPLETE Per-keyword processing
  CVE_QUERY_START / COMPLETE / ERROR   NVD API calls
  GENAI_QUERY / RESPONSE / ERROR       Ask Sage API calls
  CAPTCHA_DETECTED / BLOCKED           DDG rate limiting events
  PERSONA_LOOKUP           Ask Sage persona resolved
  DATA_EXPORT              Output file written
  BROWSER_OPEN / CLOSE     DDG session priming

AU-3 (Content of Audit Records) - Each record contains:
  (a) event_type       What happened
  (b) timestamp        When it happened (ISO 8601 with timezone)
  (c) source_system    Where it happened (Look4Gold13 + hostname)
  (d) source_function  Source module or function name
  (e) outcome          Result: Success, Failure, or Warning
  (f) subject          Who/what was involved (user, keyword, API)


ENVIRONMENT VARIABLES
------------------------------------
ASK_SAGE_API_KEY    (optional) Ask Sage API key for GenAI queries
NVD_API_KEY         (optional) NIST NVD API key for faster CVE lookups


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
categories for each finding. CVE findings are included as additional
context in the GenAI prompt. A separate query runs per keyword.


FILES IN THIS FOLDER
------------------------------------
README.txt                        This file
au13-config.example.asksage.json  Ask Sage config template (reference)
au13-config.example.grok.json     Grok (xAI) config template (reference)
keywords.example.txt              Starter keywords with example phrases
keywords.txt                      Your keywords (gitignored, create from example)
sources.json                      Your search dorks (gitignored, create from example)
sources.example.json              Default search sources (reference copy)
