## 💻 GitHub Dorking

### No API Key Required!
The tool uses GitHub's web interface for searching, so **no API key is needed**. This makes it easy to use without any setup requirements.

### How GitHub Dorking Works
1. **Web Scraping**: Uses GitHub's public search interface
2. **Smart Delays**: Respects rate limits with random delays
3. **Content Verification**: Checks raw files for actual sensitive content
4. **Pattern Detection**: Identifies passwords, API keys, tokens in code

### Basic Syntax
```bash
python3 lazy_dorker.py -d TARGET_DOMAIN [OPTIONS]

##**Scan Modes**
Mode	Command	Description
Google Only (Default)	python3 lazy_dorker.py -d example.com	Comprehensive Google dorking
GitHub Only	python3 lazy_dorker.py -d example.com --github	GitHub code and secrets search
Combined	python3 lazy_dorker.py -d example.com --combined	Both Google & GitHub dorking
Quick Scan	python3 lazy_dorker.py -d example.com --quick	Fast mixed scan with top dorks

#Examples
# Comprehensive Google dorking
python3 lazy_dorker.py -d example.com

# GitHub secrets search only
python3 lazy_dorker.py -d example.com --github

# Complete reconnaissance (Google + GitHub)
python3 lazy_dorker.py -d example.com --combined

# Quick mixed scan
python3 lazy_dorker.py -d example.com --quick

# Custom parameters
python3 lazy_dorker.py -d example.com --combined --max-dorks 5 --min-delay 2 --max-delay 10

# Save to custom file
python3 lazy_dorker.py -d example.com --combined -o my_scan.txt
