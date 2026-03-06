# 🕵️ Lazy-Dorks: Advanced Google & GitHub Dorking Tool

![Lazy-Dorks Banner](https://raw.githubusercontent.com/Haider899/Lazy-Dorks/main/assets/lazy_dorks_banner.png) <!-- Placeholder for an attractive banner image -->

## ✨ Overview

Lazy-Dorks is a **powerful and automated Python-based tool** meticulously crafted for security researchers. It streamlines the often tedious process of discovering exposed sensitive information, misconfigurations, and potential vulnerabilities across web assets by intelligently leveraging advanced Google and GitHub search queries. By automating this critical reconnaissance phase, Lazy-Dorks empowers researchers to swiftly pinpoint security risks, significantly reducing manual effort and accelerating the vulnerability assessment lifecycle.

## 🚀 Features

Lazy-Dorks comes packed with a robust suite of features designed for comprehensive and efficient dorking operations:

*   **🚫 No API Key Required**: Experience unparalleled ease of use! The tool intelligently interacts with GitHub's public web interface for searching, completely eliminating the need for complex API key setups. This ensures immediate deployment and accessibility for all users.
*   **📚 Extensive Dork Database**: Dive deep with an impressive collection of **over 300 advanced Google and GitHub dorks**. These are meticulously categorized to target a wide array of sensitive information, including exposed configuration files, database backups, log files, API endpoints, and much more.
*   **⏱️ Smart Rate Limiting**: Operate responsibly and persistently. Lazy-Dorks employs adaptive delays and randomized intervals to gracefully respect search engine rate limits, effectively preventing IP bans and ensuring uninterrupted scanning.
*   **🔍 Intelligent Content Verification**: Go beyond surface-level matches. The tool performs in-depth content verification on retrieved files to confirm the genuine presence of sensitive data, drastically reducing false positives and delivering actionable intelligence.
*   **🎯 Precision Pattern Detection**: Advanced algorithms are at the core of Lazy-Dorks, enabling it to accurately identify critical patterns indicative of passwords, API keys, tokens, and other confidential data embedded within code and text files.
*   **🔄 Multiple Scan Modes**: Enjoy unparalleled flexibility with diverse scanning options, including dedicated Google-only, GitHub-only, powerful combined searches, and rapid quick scan modes. Tailor your reconnaissance efforts precisely to your needs.
*   **🖥️ User-Friendly Interface**: Designed with the researcher in mind, Lazy-Dorks offers a straightforward command-line interface, making complex dorking operations accessible and efficient.

## ⚙️ Installation

Getting Lazy-Dorks up and running is quick and easy:

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/Haider899/Lazy-Dorks.git
    cd Lazy-Dorks
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## 💡 Usage

Lazy-Dorks provides a variety of command-line options to fine-tune your dorking scans. The basic syntax is as follows:

```bash
python3 lazy_dorker.py -d TARGET_DOMAIN [OPTIONS]
```

### Scan Modes

| Mode                    | Command                                                | Description                                    |
| :---------------------- | :----------------------------------------------------- | :--------------------------------------------- |
| **Google Only (Default)** | `python3 lazy_dorker.py -d example.com`                | Comprehensive Google dorking                   |
| **GitHub Only**         | `python3 lazy_dorker.py -d example.com --github`       | GitHub code and secrets search                 |
| **Combined**            | `python3 lazy_dorker.py -d example.com --combined`     | Both Google & GitHub dorking                   |
| **Quick Scan**          | `python3 lazy_dorker.py -d example.com --quick`        | Fast mixed scan with top dorks                 |

### Examples

*   **Comprehensive Google dorking**:
    ```bash
    python3 lazy_dorker.py -d example.com
    ```

*   **GitHub secrets search only**:
    ```bash
    python3 lazy_dorker.py -d example.com --github
    ```

*   **Complete reconnaissance (Google + GitHub)**:
    ```bash
    python3 lazy_dorker.py -d example.com --combined
    ```

*   **Quick mixed scan**:
    ```bash
    python3 lazy_dorker.py -d example.com --quick
    ```

*   **Custom parameters** (e.g., limiting dorks, setting delays):
    ```bash
    python3 lazy_dorker.py -d example.com --combined --max-dorks 5 --min-delay 2 --max-delay 10
    ```

*   **Save results to a custom file**:
    ```bash
    python3 lazy_dorker.py -d example.com --combined -o my_scan.txt
    ```

## 🤝 Contributing

We enthusiastically welcome contributions from the community! Please refer to our [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on how to report bugs, suggest new features, and submit pull requests.

## 📜 Code of Conduct

To ensure a welcoming, inclusive, and respectful environment for all participants, we strictly adhere to a [Code of Conduct](CODE_OF_CONDUCT.md). We kindly request all contributors to review it before engaging with the project.

## ⚖️ License

This project is proudly licensed under the [MIT License](LICENSE), promoting open collaboration and usage.

## ⭐ Support the Project

If Lazy-Dorks has proven valuable in your security research, please consider giving it a star on GitHub! Your support helps us grow and improve.

## 🛠️ Built With

*   Python
*   Requests
*   BeautifulSoup4
*   dnspython

## ❤️ Made with Love

This project was created with ❤️ for the security community. Support open-source security tools!
