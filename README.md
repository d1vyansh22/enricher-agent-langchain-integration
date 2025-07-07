# LangChain IP Intelligence Agent

A sophisticated IP address intelligence and threat analysis system built with LangChain, LangGraph, and Google Gemini. This project integrates multiple threat intelligence sources to provide comprehensive security analysis for cybersecurity professionals.

## 🚀 Features

- **Multi-Source Intelligence**: Integrates IPInfo, VirusTotal, Shodan, and AbuseIPDB APIs
- **LangGraph Orchestration**: Sophisticated workflow management with state transitions
- **Gemini LLM Integration**: AI-powered analysis and natural language reporting
- **Comprehensive Threat Scoring**: Advanced risk assessment algorithms
- **Production Ready**: Robust error handling, validation, and monitoring
- **LangSmith Integration**: Complete observability and debugging capabilities

## 📋 Prerequisites

- Python 3.9+ (required for LangGraph)
- API Keys for threat intelligence services:
  - [Google AI Studio](https://makersuite.google.com/app/apikey) (Gemini)
  - [IPInfo](https://ipinfo.io/signup) 
  - [VirusTotal](https://www.virustotal.com/gui/join-us)
  - [Shodan](https://account.shodan.io/register)
  - [AbuseIPDB](https://www.abuseipdb.com/register)
- [LangSmith Account](https://smith.langchain.com/) (optional, for monitoring)

## 🛠 Installation

### 1. Clone the Repository
```bash
git clone <your-repo-url>
cd langchain-ip-intelligence-agent
```

### 2. Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
```bash
cp .env.template .env
```

Edit `.env` with your API keys

Required environment variables:

#### Core LLM
```env
GOOGLE_API_KEY=your_gemini_api_key
```

#### Threat Intelligence APIs
```env
IPINFO_API_KEY=your_ipinfo_key
VIRUSTOTAL_API_KEY=your_virustotal_key
SHODAN_API_KEY=your_shodan_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

#### LangSmith (Optional)
```env
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=your_langsmith_key
LANGCHAIN_PROJECT=ip-intelligence-agent
```

## 🚀 Usage

### Simple Analysis
```python
from examples.simple_analysis import analyze_ip

# Analyze a single IP
result = await analyze_ip("8.8.8.8")
print(result)
```

### Batch Analysis
```python
from examples.batch_analysis import analyze_multiple_ips

# Analyze multiple IPs
ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
results = await analyze_multiple_ips(ips)
```

### Custom Workflow
```python
from src.graph.workflow import ip_analysis_app
from src.graph.state import IPAnalysisState

# Create initial state
initial_state: IPAnalysisState = {
    "ip_address": "203.0.113.42",
    "user_query": "Analyze this IP for security threats",
    "messages": [],
    "ip_validation": None,
    "ipinfo_result": None,
    "virustotal_result": None,
    "shodan_result": None,
    "abuseipdb_result": None,
    "threat_analysis": None,
    "final_report": None,
    "next_action": None,
    "error_message": None,
    "completed": False
}

# Execute workflow
result = await ip_analysis_app.ainvoke(initial_state)
print(result["final_report"])
```

## 🏗 Project Structure

```
langchain-ip-intelligence-agent/
├── src/
│   ├── config/        # Configuration management
│   ├── graph/         # LangGraph workflow definition
│   ├── models/        # LLM integration (Gemini)
│   └── tools/         # LangChain tools for APIs
├── tests/             # Comprehensive test suite
├── examples/          # Usage examples
├── requirements.txt   # Dependencies
├── .env.template      # Environment configuration template
└── README.md          # This file
```

## 🧪 Testing

Run the complete test suite:

**All tests**
```bash
pytest
```

**Specific test files**
```bash
pytest tests/test_tools.py
pytest tests/test_workflow.py
```

**With coverage**
```bash
pytest --cov=src tests/
```

**Integration tests only**
```bash
pytest -m integration tests/
```

## 🔧 Development

### Adding New Tools
1. Create new tool in `src/tools/`
2. Inherit from `langchain.tools.BaseTool`
3. Add to workflow in `src/graph/nodes.py`
4. Update tests in `tests/test_tools.py`

### Modifying Workflow
1. Update state schema in `src/graph/state.py`
2. Modify nodes in `src/graph/nodes.py`
3. Update workflow definition in `src/graph/workflow.py`
4. Add tests in `tests/test_workflow.py`

## 📊 Monitoring

This project integrates with LangSmith for comprehensive observability:

- **Trace Workflows**: Monitor complete analysis pipelines
- **Debug Issues**: Inspect individual tool calls and responses
- **Performance Metrics**: Track latency and success rates
- **Error Analysis**: Identify and resolve issues quickly

Access your traces at: https://smith.langchain.com/

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Code Quality Standards
- Add type hints to all functions
- Include comprehensive docstrings
- Maintain test coverage above 90%
- Follow PEP 8 style guidelines
- Add integration tests for new tools

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [LangChain](https://langchain.com/) for the framework
- [LangGraph](https://github.com/langchain-ai/langgraph) for workflow orchestration
- Threat intelligence providers for their APIs
- Open source community for inspiration

## 🆘 Support

- **Issues**: [GitHub Issues](your-repo-url/issues)
- **Discussions**: [GitHub Discussions](your-repo-url/discussions)
- **Documentation**: [Project Wiki](your-repo-url/wiki)

---

**Note**: This is a security tool for defensive purposes. Please use responsibly and in accordance with all applicable laws and regulations.



