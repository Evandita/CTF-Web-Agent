# CTF Web Agent

An AI-powered web agent for automatically solving CTF (Capture The Flag) web challenges using LangChain, LangGraph, Playwright, and Ollama.

## Features

- **Automated Web Exploitation**: Uses LLM reasoning to identify and exploit web vulnerabilities
- **Visual Analysis**: VLM-powered screenshot analysis to understand page layout and challenge type
- **Multi-Source Information Gathering**:
  - DOM extraction for interactive elements
  - Network traffic monitoring
  - Cookie and localStorage inspection
  - HTML source analysis (comments, hidden fields)
- **Common Vulnerability Testing**:
  - SQL Injection
  - XSS (Cross-Site Scripting)
  - Command Injection
  - Path Traversal
  - Authentication Bypass
  - SSTI (Server-Side Template Injection)
- **Human-in-the-Loop**: Request human assistance when stuck
- **Rich Terminal UI**: Beautiful output with Rich library

## Requirements

- Python 3.11+
- [Ollama](https://ollama.ai/) running locally
- Chromium browser (installed by Playwright)

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/example/ctf-web-agent.git
cd ctf-web-agent
```

### 2. Install the package

```bash
pip install -e .
```

### 3. Install Playwright browsers

```bash
playwright install chromium
```

### 4. Install Ollama and required models

Install Ollama from https://ollama.ai/, then pull the required models:

```bash
# Text model for reasoning
ollama pull llama3.1

# Vision model for screenshot analysis
ollama pull llava
```

## Usage

### Basic Usage

```bash
ctf-agent http://challenge.ctf.com/login
```

### With Options

```bash
# Run headless (no visible browser)
ctf-agent http://challenge.ctf.com --headless

# Increase max iterations
ctf-agent http://challenge.ctf.com --max-iterations 50

# Use different models
ctf-agent http://challenge.ctf.com --text-model llama3.1:70b --vision-model llava:34b

# Disable human-in-the-loop prompts
ctf-agent http://challenge.ctf.com --no-hitl

# Verbose output
ctf-agent http://challenge.ctf.com -v
```

### All Options

```
usage: ctf-agent [-h] [--headless] [--max-iterations MAX_ITERATIONS]
                 [--text-model TEXT_MODEL] [--vision-model VISION_MODEL]
                 [--no-hitl] [--timeout TIMEOUT] [--ollama-url OLLAMA_URL] [-v]
                 url

positional arguments:
  url                   URL of the CTF challenge to solve

options:
  -h, --help            show this help message and exit
  --headless            Run browser in headless mode
  --max-iterations MAX_ITERATIONS
                        Maximum iterations (default: 30)
  --text-model TEXT_MODEL
                        Ollama text model (default: llama3.1)
  --vision-model VISION_MODEL
                        Ollama vision model (default: llava)
  --no-hitl             Disable human-in-the-loop
  --timeout TIMEOUT     Browser timeout in seconds (default: 30)
  --ollama-url OLLAMA_URL
                        Ollama server URL (default: http://localhost:11434)
  -v, --verbose         Enable verbose logging
```

## Configuration

You can configure the agent using environment variables or a `.env` file:

```bash
# Copy the example env file
cp .env.example .env

# Edit as needed
```

Available environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CTF_OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `CTF_OLLAMA_TEXT_MODEL` | `llama3.1` | Text model for reasoning |
| `CTF_OLLAMA_VISION_MODEL` | `llava` | Vision model for screenshots |
| `CTF_MAX_ITERATIONS` | `30` | Maximum iterations |
| `CTF_TIMEOUT_SECONDS` | `30` | Browser operation timeout |
| `CTF_HEADLESS` | `false` | Run browser headless |
| `CTF_HITL_ENABLED` | `true` | Enable human-in-the-loop |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CTF Web Agent                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Ollama     │    │  LangGraph   │    │  Playwright  │  │
│  │  (LLM/VLM)   │◄──►│ Orchestrator │◄──►│   Browser    │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                   │                    │          │
│         ▼                   ▼                    ▼          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Vision     │    │    Tools     │    │  Extractors  │  │
│  │  Analysis    │    │  (Actions)   │    │    (DOM)     │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Components

- **Orchestrator**: LangGraph state machine that controls the agent loop
- **Browser Controller**: Playwright wrapper for web automation
- **Tools**: LangChain tools for browser actions (click, fill, navigate, etc.)
- **Extractors**: DOM and page information extraction
- **Vision Analysis**: VLM-powered screenshot analysis
- **Flag Detector**: Regex-based flag pattern matching

### Agent Flow

1. **Analyze**: Gather page state (elements, cookies, hints)
2. **Plan**: LLM decides next action based on analysis
3. **Execute**: Run the chosen tool (click, fill, navigate, etc.)
4. **Check**: Look for flag in page, cookies, network traffic
5. **Repeat**: Continue until flag found or max iterations reached

## Supported Vulnerability Types

The agent can detect and exploit:

- **SQL Injection**: Login bypasses, UNION-based extraction
- **XSS**: Reflected and stored XSS
- **Command Injection**: OS command execution
- **Path Traversal**: File reading via path manipulation
- **LFI/RFI**: Local/Remote file inclusion
- **Authentication Bypass**: Default credentials, logic flaws
- **SSTI**: Server-side template injection
- **Hidden Content**: Comments, robots.txt, .git exposure

## Development

### Install dev dependencies

```bash
pip install -e ".[dev]"
```

### Run tests

```bash
pytest
```

### Code formatting

```bash
ruff check src/ --fix
ruff format src/
```

### Type checking

```bash
mypy src/
```

## Project Structure

```
ctf-web-agent/
├── pyproject.toml          # Package configuration
├── README.md               # This file
├── .env.example            # Example environment variables
├── src/
│   ├── __init__.py
│   ├── main.py             # CLI entry point
│   ├── config.py           # Configuration with pydantic-settings
│   ├── agent/
│   │   ├── __init__.py
│   │   ├── orchestrator.py # LangGraph agent
│   │   ├── prompts.py      # System prompts
│   │   └── state.py        # Agent state definition
│   ├── browser/
│   │   ├── __init__.py
│   │   ├── controller.py   # Playwright wrapper
│   │   ├── extractors.py   # DOM extraction
│   │   ├── payloads.py     # Common CTF payloads
│   │   └── tools.py        # LangChain tools
│   ├── models/
│   │   ├── __init__.py
│   │   ├── ollama_client.py # Ollama setup
│   │   └── vision.py       # VLM analysis
│   └── utils/
│       ├── __init__.py
│       ├── flag_detector.py # Flag pattern matching
│       ├── hitl.py         # Human-in-the-loop
│       └── logger.py       # Rich logging
└── tests/
    ├── __init__.py
    ├── test_browser.py
    └── test_agent.py
```

## Troubleshooting

### Ollama not available

Make sure Ollama is running:
```bash
ollama serve
```

### Models not found

Pull the required models:
```bash
ollama pull llama3.1
ollama pull llava
```

### Browser not working

Reinstall Playwright browsers:
```bash
playwright install chromium --force
```

### Permission errors on Linux

You may need to install additional dependencies:
```bash
playwright install-deps
```

## License

MIT License

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Always obtain proper authorization before testing any system you do not own. The authors are not responsible for any misuse of this tool.
