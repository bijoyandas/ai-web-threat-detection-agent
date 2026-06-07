import base64
import json
import time
import gradio as gr
from typing import TypedDict
from langchain_core.messages import HumanMessage
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, START, END
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup

# ==========================================
# 1. Define the Graph State
# ==========================================
# This TypedDict serves as the memory object passed between nodes in LangGraph.
class AgentState(TypedDict):
    url: str
    image_path: str
    dom_summary: str
    is_malicious: bool
    reasoning: str

# ==========================================
# 2. Define Helper Functions and Nodes
# ==========================================
def encode_image(image_path: str) -> str:
    """Encodes an image file to a base64 string."""
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode("utf-8")

def clean_dom(html_content: str) -> str:
    """Parses raw HTML and extracts security-critical semantic infrastructure."""
    soup = BeautifulSoup(html_content, "html.parser")

    # 1. Grab metadata
    title = soup.title.string.strip() if soup.title else "No Title"

    # 2. Extract Form Actions (Where credentials actually go when submitted)
    form_actions = [form.get("action") for form in soup.find_all("form") if form.get("action")]

    # 3. Extract External Script Sources (Looking for sketchy script injection)
    script_srcs = [script.get("src") for script in soup.find_all("script") if script.get("src")]

    # 4. Extract Outbound Hyperlinks (Are they pointing away from the core brand?)
    outbound_links = [a.get("href") for a in soup.find_all("a") if a.get("href") and a.get("href").startswith("http")]

    # Construct a compressed string payload for Qwen
    summary_lines = [
        f"Page Title: {title}",
        f"Form Actions detected: {form_actions}",
        f"External Scripts loaded (First 10): {script_srcs[:10]}",
        f"Outbound Hyperlinks (First 15): {outbound_links[:15]}"
    ]
    return "\n".join(summary_lines)

# ==========================================
# 3. Define State Functions and Nodes
# ==========================================
def capture_website_details_node(state: AgentState) -> AgentState:
    """
    Node 1: Opens a headless browser, navigates to the URL, and captures a screenshot and DOM elements.
    """
    url = state["url"]
    # Generate a unique filename using the current timestamp
    image_path = f"screenshots/screenshot_{int(time.time())}.png"
    dom_summary = ""

    print(f"[*] Launching headless browser to capture: {url}")

    with sync_playwright() as p:
        # Launch chromium headlessly
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        try:
            # wait_until="networkidle" ensures dynamic content and JS finish loading
            page.goto(url, wait_until="domcontentloaded", timeout=15000)

            # Capture a full-page screenshot
            page.screenshot(path=image_path, full_page=True)
            print(f"[*] Screenshot saved successfully at: {image_path}")

            # Capture DOM
            raw_html = page.content()
            dom_summary = clean_dom(raw_html)
            print(f"[*] DOM elements captured")

        except Exception as e:
            print(f"[!] Browser Error: {e}")
            image_path = ""
        finally:
            browser.close()

    # Update the state with the newly created image path
    return AgentState(
        url=url,
        image_path=image_path,
        dom_summary=dom_summary,
        is_malicious=state.get("is_malicious", False),
        reasoning=state.get("reasoning", "")
    )

def analyze_website_node(state: AgentState):
    """
    Node function that passes the URL and image to the local multimodal LLM.
    """
    url = state["url"]
    image_path = state["image_path"]
    dom_summary = state["dom_summary"]

    print("[*] Analyzing screenshot and DOM with Qwen...")
    # If the screenshot failed in the previous node, fail gracefully here
    if not (image_path and dom_summary):
        return AgentState(
            url=url,
            image_path="",
            dom_summary="",
            is_malicious=False,
            reasoning="Capture failed. Cannot analyze."
        )

    # 1. Encode the image into base64
    image_base64 = encode_image(image_path)

    # 2. Define the specific prompt instructions
    prompt_text = f"""
    You are an expert cybersecurity threat hunter. Analyze this website using three inputs: its URL, its visual screenshot layout, and its extracted DOM code infrastructure.

    Target URL: {url}

    Extracted DOM Infrastructure Summary:
    {dom_summary}

    Cross-Reference Tasks:
    1. Check for Brand Mismatch: Does the site look like a known company (e.g., Google login box) but the URL domain or the DOM "Form Actions" route to a non-affiliated external domain?
    2. Check Form Destinations: Inspect the listed 'Form Actions' under the DOM data. If this is a login, profile, or banking portal, do the credentials submit to a matching, valid domain or an anomalous server?
    3. Look for Script Injection: Are external javascript source files being loaded from unrecognizable or high-risk domains?

    Respond STRICTLY in JSON format with exactly these two keys:
    - "is_malicious": boolean (true or false)
    - "reasoning": A technical summary explaining your analysis of the URL string, visual presentation alignment, and anomalies flagged within the DOM.
    """

    # 3. Construct the Multimodal Message
    message = HumanMessage(
        content=[
            {"type": "text", "text": prompt_text},
            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{image_base64}"}}
        ]
    )

    # 4. Invoke the local model (setting format="json" ensures predictable parsing)
    llm = ChatOllama(model="qwen3.5:4b", temperature=0, format="json")
    response = llm.invoke([message])

    # 5. Parse the LLM output and update the state
    try:
        result = json.loads(response.content)
        return AgentState(
            url=state["url"],
            image_path=state["image_path"],
            dom_summary=state["dom_summary"],
            is_malicious=result.get("is_malicious", False),
            reasoning=result.get("reasoning", "No reasoning provided.")
        )
    except json.JSONDecodeError as e:
        print(e)
        return AgentState(
            url=state["url"],
            image_path=state["image_path"],
            dom_summary=state["dom_summary"],
            is_malicious=False,
            reasoning=f"Failed to parse model response: {response.content}"
        )

# ==========================================
# 3. Build and Compile the LangGraph
# ==========================================
# Initialize the graph with our state schema
workflow = StateGraph(AgentState)

# Add our single operational node
workflow.add_node("capture_website_details_node", capture_website_details_node)
workflow.add_node("analyze_website", analyze_website_node)

# Define the execution flow: START -> analyze_website -> END
workflow.add_edge(START, "capture_website_details_node")
workflow.add_edge("capture_website_details_node", "analyze_website")
workflow.add_edge("analyze_website", END)

# Compile into an executable application
malicious_detector_app = workflow.compile()

# ==========================================
# 4. Gradio Interface Wrapper
# ==========================================
def run_threat_agent(url_input):
    """Bridge function connecting Gradio inputs/outputs to LangGraph execution."""
    if not url_input.strip().startswith(("http://", "https://")):
        return None, "⚠️ Invalid Protocol", "Please enter a valid URL starting with http:// or https://"

    initial_state = AgentState(
        url=url_input.strip(),
        image_path="",
        is_malicious=False,
        reasoning=""
    )

    # Run the compiled graph execution
    final_state = malicious_detector_app.invoke(initial_state)

    # Formatting outputs for Gradio display elements
    verdict = "🚨 MALICIOUS" if final_state["is_malicious"] else "✅ SAFE"
    screenshot = final_state["image_path"] if final_state["image_path"] else None
    reasoning_text = final_state["reasoning"]

    return screenshot, verdict, reasoning_text

# Define the Web layout
with gr.Blocks(title="AI Threat Scanner") as demo:
    gr.Markdown("# 🛡️ AI Web Threat Analyst")
    gr.Markdown("Enter a URL to spin up a stealth headless browser, snap a live screenshot, and evaluate safety using local LLMs via Ollama.")

    with gr.Row():
        with gr.Column(scale=2):
            url_box = gr.Textbox(placeholder="https://example.com", label="Target URL Address")
            scan_btn = gr.Button("Analyze URL", variant="primary")

            gr.Markdown("### Analysis Metadata")
            verdict_output = gr.Label(label="Security Assessment Status")
            reasoning_output = gr.Textbox(label="Analyst Verdict Details", lines=6, interactive=False)

        with gr.Column(scale=3):
            image_output = gr.Image(label="Headless Browser Viewport Capture", type="filepath")

    # Connect the UI elements to the processing function
    scan_btn.click(
        fn=run_threat_agent,
        inputs=[url_box],
        outputs=[image_output, verdict_output, reasoning_output]
    )

if __name__ == "__main__":
    # Launch the server locally
    demo.launch(server_name="127.0.0.1", server_port=7860)



# # ==========================================
# # 4. Execute the Agent
# # ==========================================
# if __name__ == "__main__":
#     while True:
#         target_url = input("Enter a URL to analyze (e.g., https://example.com): ")
#
#         initial_state = AgentState(
#             url=target_url,
#             image_path="",
#             is_malicious=False,
#             reasoning=""
#         )
#
#         print("Agent is analyzing the website...")
#         final_state = malicious_detector_app.invoke(initial_state)
#
#         print("\n=== Analysis Results ===")
#         print(f"URL Analyzed: {final_state['url']}")
#         print(f"Is Malicious: {final_state['is_malicious']}")
#         print(f"Reasoning:    {final_state['reasoning']}")
#         continue_or_not = input("Enter choice (q for quitting): ")
#         if (continue_or_not == 'q'):
#             break