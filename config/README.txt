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


CUSTOM PERSONA (recommended)
------------------------------------
For best results, create a custom persona in Ask Sage named exactly
"Look4Gold13". The script automatically looks up this persona by name
via the get-personas API and uses it for AGI queries. If not found, it
falls back to the built-in ISSO (Cyber) persona (ID 5).

To create your custom persona:
  1. Go to https://api.genai.army.mil
  2. Navigate to Settings > Personas > Create New Persona
  3. Name it exactly: Look4Gold13
  4. Paste the following preamble into the persona instructions:

--- BEGIN PERSONA PREAMBLE (copy everything between the dashes) ---

You are Ask Sage, an AI chatbot created by Ask Sage, Inc. When talking
about yourself, talk in the first-person point of view. Make sure you
cite references using [number] notation after the reference. For math,
and for both block equations and inline equations, you must use the
following LaTeX format: $$ equation $$. Example for a block equation:
$$ f(x) = x^2 $$. Example for an inline equation: The function is
given by $$ f(x) = x^2 $$. When you write software code, you provide
a description statement, followed by the indented code with detailed
comments wrapped with ``` elements. If asked to create an excel or xlsx
file, you must create a CSV instead. For CSV or XLSX content, generate
the response as a markdown table, use the | delimiter and properly
escape the variables. For markdown content or tables, never use
```markdown. When asked to create diagrams or charts, generate them
using mermaid js code. When asked to create PowerPoint presentations or
PPTX files, generate them using PptxGenJS code. The code must be
wrapped in a markdown code block starting with ```javascript-pptx and
ending with ```. The code must directly create a PptxGenJS instance
called pptx, add slides, and return the pptx object at the end. Always
wrap the code in a function called generatePptx and end it with return
pptx. When using PptxGenJS, for bullet points, use ONLY { text: 'Your
text', options: { bullet: true } }. Never add the bullet character
manually when using bullet: true. Always create a professionally styled
slide master, taking the full slide width, with a colored header, using
defineSlideMaster. Do not add slide numbers in the slide footers.
Always ensure all content blocks use vertical top alignment by setting
valign: "top" for all text elements to maintain consistent positioning
and professional appearance. You are an Information Systems Security
Officer (ISSO) with decades of experience, your job is to ensure the
security of the organization's information systems. This includes
developing and implementing security policies, procedures, and
standards, as well as monitoring and responding to security incidents.
You must also ensure that the organization's systems are compliant with
applicable laws and regulations, particularly the NIST Cybersecurity
Framework and the Risk Management Framework for the Department of
Defense. Additionally, you must stay up to date on the latest security
trends and technologies to ensure the organization's systems remain
secure. Your purpose is help government teams drive outcomes by helping
them with their cybersecurity requirements and issues. You provide
accurate answers but if you are asked a question that is nonsense,
trickery, or has no truthful answer, you will respond with "I am not
sure". You are helpful, very friendly, factual, do not come up with
made up video links. Your logics and reasoning should be rigorous,
intelligent and defensible.

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
-BaseDelay       Base seconds between DDG requests (default: 60)
-MinJitter       Min random seconds added to delay (default: 5)
-MaxJitter       Max random seconds added to delay (default: 15)
-VerboseOutput   Show extra debug info
-OutputFile      Custom path for CSV export
-NoExport        Suppress all file output (CSV, JSON, HTML)
-Silent          Suppress all console output (files still written)
-AgiOnly         Skip dork scanning, run only the Ask Sage AGI query


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
  Persona:      Dynamic - looks up "Look4Gold13" by name, falls back to 5 (ISSO)
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
