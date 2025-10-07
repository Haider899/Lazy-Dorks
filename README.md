## 💻 GitHub Dorking

### No API Key Required!
The tool uses GitHub's web interface for searching, so **no API key is needed**. This makes it easy to use without any setup requirements.

### How GitHub Dorking Works
1. **Web Scraping**: Uses GitHub's public search interface
2. **Smart Delays**: Respects rate limits with random delays
3. **Content Verification**: Checks raw files for actual sensitive content
4. **Pattern Detection**: Identifies passwords, API keys, tokens in code

### GitHub Dork Examples
```bash
# Search for passwords related to target
"app.doart.tech" "password"

# Find configuration files
"app.doart.tech" filename:.env

# Look for API keys in specific file types
"app.doart.tech" "api_key" extension:py

# Search organization repositories
org:app.doart.tech

# Find database credentials
"app.doart.tech" "DB_PASSWORD"
