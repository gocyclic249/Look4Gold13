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


GENAI CONFIG FILE (au13-config.json)
------------------------------------
The config file is optional. Without it, the script uses built-in defaults.
If present, settings in the config override matching defaults.

Setup:
  1. Copy the example matching your GenAI provider:

     For Ask Sage (army.mil):
       Copy-Item config/au13-config.example.asksage.json config/au13-config.json

     For Grok (xAI):
       Copy-Item config/au13-config.example.grok.json config/au13-config.json

  2. au13-config.json is gitignored - it will never be committed.

  3. Set your API token as an environment variable:
       [System.Environment]::SetEnvironmentVariable("GENAI_API_TOKEN", "your-key", "User")
       # Restart PowerShell after setting this

API Key Sources:
  - Ask Sage: https://api.genai.army.mil > Settings > Account > Manage API Keys
  - Grok/xAI: https://console.x.ai/


SETTINGS REFERENCE
------------------------------------
genai.endpoint        API endpoint URL
genai.tokenEnvVar     Environment variable holding the API key (default: GENAI_API_TOKEN)
genai.model           Model for summarization (default: google-gemini-2.5-pro)
genai.apiType         Set to "openai-compatible" for Grok/xAI; omit for Ask Sage
genai.persona         Ask Sage persona ID (Ask Sage only, default: 5)
genai.temperature     Response creativity 0.0-1.0 (default: 0.7)
genai.limit_references  Max AI references (Ask Sage only, default: 5)
genai.live            Enable AI web search (Ask Sage only, default: 1)

search.daysBack       Days back to search (default: 30)
search.delaySeconds   Delay between DDG requests in seconds (default: 5)
search.sources        Sources to scan: DuckDuckGo, Paste, Breach (default: all three)
search.webProxyBase   Menlo Security proxy URL (default: https://safe.menlosecurity.com)

You don't need to include every setting. Only add the ones you want to
override. Command-line parameters (-DaysBack, -Sources, etc.) override
both the config file and defaults.


FILES IN THIS FOLDER
------------------------------------
README.txt                        This file
au13-config.example.asksage.json  Ask Sage config template
au13-config.example.grok.json     Grok (xAI) config template
au13-config.json                  Your config (gitignored, create from example)
keywords.example.txt              Starter keywords with example phrases
keywords.txt                      Your keywords (gitignored, create from example)
