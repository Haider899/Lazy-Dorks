# Lazy-Dorks: Advanced Google & GitHub Dorking Tool

![Lazy-Dorks Logo](https://raw.githubusercontent.com/Haider899/Lazy-Dorks/main/lazy_dorks_logo.png) <!-- Placeholder for a potential logo -->

## Overview

Lazy-Dorks is a powerful and automated tool designed for security researchers to efficiently perform Google and GitHub dorking. This Python-based utility streamlines the process of discovering exposed sensitive information, misconfigurations, and vulnerabilities across web assets by leveraging advanced search queries. By automating the reconnaissance phase, Lazy-Dorks enables researchers to quickly identify potential security risks without the need for manual, time-consuming searches.

## Features

Lazy-Dorks offers a robust set of features tailored for comprehensive dorking operations:

*   **No API Key Required**: The tool intelligently utilizes GitHub's public web interface for searching, eliminating the need for complex API key setups and simplifying immediate deployment.
*   **Extensive Dork Database**: Incorporates over 300 advanced Google and GitHub dorks, categorized to target various types of sensitive information, including exposed configuration files, database backups, log files, and API endpoints.
*   **Smart Rate Limiting**: Employs adaptive delays and randomized intervals to respect search engine rate limits, ensuring persistent operation and minimizing the risk of IP bans.
*   **Intelligent Content Verification**: Beyond simple keyword matching, Lazy-Dorks performs content verification on retrieved files to confirm the presence of actual sensitive data, reducing false positives.
*   **Pattern Detection**: Advanced algorithms are used to identify critical patterns indicative of passwords, API keys, tokens, and other confidential data within code and text files.
*   **Multiple Scan Modes**: Provides flexible scanning options, including Google-only, GitHub-only, combined searches, and quick scan modes, allowing users to tailor their reconnaissance efforts.
*   **User-Friendly Interface**: Designed for ease of use, enabling security researchers to execute complex dorking operations with straightforward command-line arguments.

## Installation

To get started with Lazy-Dorks, follow these simple steps:

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/Haider899/Lazy-Dorks.git
    cd Lazy-Dorks
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Lazy-Dorks provides various command-line options to customize your dorking scans. The basic syntax is as follows:

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

## Contributing

We welcome contributions from the community! Please refer to our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to report bugs, suggest features, and submit pull requests.

## Code of Conduct

To ensure a welcoming and inclusive environment, we adhere to a [Code of Conduct](CODE_OF_CONDUCT.md). Please review it before participating.

## License

This project is licensed under the [MIT License](LICENSE).
