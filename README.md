# 🛡️ Local AI Web Threat Analyst

An end-to-end local security orchestration agent built with **LangGraph**, **Playwright**, and **Gradio**. This application accepts a URL from a user, launches a stealth-patched headless browser to capture a visual snapshot of the page, and routes the screenshot and URL text to a local multimodal LLM running on **Ollama** to analyze and flag potential phishing or malicious targets.

---

## 🚀 Features
- **Scraper:** Uses Playwright to scrape through the webpage and capture DOM content & screenshot.
- **LangGraph State Management:** Leverages a structured, deterministic multi-step state graph to pass information seamlessly between nodes.
- **Multimodal Evaluation:** Checks URL text anomalies (typo-squatting, bad TLDs), DOM content and visual branding cues symmetrically.
- **Privacy First:** Entirely self-hosted—your scraped content and metadata never leave your local machine.

---

## 🛠️ Installation & Setup

### Step 1: Install and Configure Ollama
1. Download and install Ollama for your operating system from [ollama.com](https://ollama.com).
2. Start the Ollama background daemon:
    - **Mac/Windows:** Run the desktop application.
    - **Linux/Terminal:** Open a separate terminal shell and run:
      ```bash
      ollama serve
      ```
3. Pull the multimodal Qwen model required for screenshot analysis:
   ```bash
   ollama pull qwen3.5:4b
4. Run the agent and Gradio UI using:
   ```bash
   python3 agent.py