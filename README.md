# Enricher Agent: LangChain IP Intelligence System

A sophisticated IP address intelligence and threat analysis system built with LangChain, LangGraph, and Google Gemini. This project integrates multiple threat intelligence sources to provide comprehensive security analysis for cybersecurity professionals.

## 🚀 Features

- **Multi-Source Intelligence**: Integrates IPInfo, VirusTotal, Shodan, and AbuseIPDB APIs
- **LangGraph Orchestration**: Sophisticated workflow management with state transitions
- **Gemini LLM Integration**: AI-powered analysis and natural language reporting
- **Comprehensive Threat Scoring**: Advanced risk assessment algorithms
- **Production Ready**: Robust error handling, validation, and monitoring
- **LangSmith Integration**: Complete observability and debugging capabilities

## 📋 Prerequisites

- Python 3.9+
- API Keys for threat intelligence services:
  - [Google AI Studio](https://makersuite.google.com/app/apikey) (Gemini)
  - [IPInfo](https://ipinfo.io/signup)
  - [VirusTotal](https://www.virustotal.com/gui/join-us)
  - [Shodan](https://account.shodan.io/register)
  - [AbuseIPDB](https://www.abuseipdb.com/register)
- [LangSmith Account](https://smith.langchain.com/) (optional, for monitoring)

## 🛠 Installation

1. **Clone the Repository**
   ```bash
   git clone <your-repo-url>
   cd enricher-agent-langchain-integration
   ```
2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Unix/Mac:
   source venv/bin/activate
   ```
3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## ⚙️ Configuration

Create a `.env` file in the project root with the following variables:

```
GOOGLE_API_KEY=your_gemini_api_key
IPINFO_API_KEY=your_ipinfo_key
VIRUSTOTAL_API_KEY=your_virustotal_key
SHODAN_API_KEY=your_shodan_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
# Optional for LangSmith observability
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=your_langsmith_key
LANGCHAIN_PROJECT=ip-intelligence-agent
```

## 🚀 Usage

Run the agent from the command line:

```bash
python main.py
```

You will be prompted to enter a query, e.g.:

```
Enter your query (e.g., 'Analyze IP 8.8.8.8 for threats'): Analyze IP 8.8.8.8 for threats
```

The system will extract the IP, gather intelligence from all sources, and print a comprehensive threat report.

## 🏗 Project Structure

```
enricher-agent-langchain-integration/
├── main.py                # Main entry point (CLI)
├── my_agent/
│   ├── __init__.py
│   ├── agent.py           # LangGraph workflow and tool orchestration
│   └── utils/
│       ├── __init__.py
│       ├── ip_validator.py  # IP validation utilities
│       ├── nodes.py         # Node functions for the workflow
│       ├── state.py         # State definition for the workflow
│       └── tools.py         # API integration tools
├── requirements.txt
├── README.md
└── ...
```

## 🔧 Development

- **Add new tools**: Implement in `my_agent/utils/tools.py` and register in `my_agent/agent.py`.
- **Modify workflow**: Update nodes in `my_agent/utils/nodes.py` and the graph in `my_agent/agent.py`.
- **State changes**: Edit `my_agent/utils/state.py`.
- **IP validation logic**: Update `my_agent/utils/ip_validator.py`.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to your branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Quality Standards
- Add type hints to all functions
- Include comprehensive docstrings
- Follow PEP 8 style guidelines
- Add/maintain tests if you add new features (if/when a test suite is present)

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [LangChain](https://langchain.com/) for the framework
- [LangGraph](https://github.com/langchain-ai/langgraph) for workflow orchestration
- Threat intelligence providers for their APIs
- Open source community for inspiration



