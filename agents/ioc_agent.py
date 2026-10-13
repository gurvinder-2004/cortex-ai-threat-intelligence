from tools.ioc_extractor import extract_iocs_regex
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate

def run_ioc_agent(text: str) -> dict:
    print(f"\n[CorteX] Running IOC Extraction Agent...")

    print("[*] Running regex-based IOC extraction...")
    regex_iocs = extract_iocs_regex(text)

    print("[*] Running Ollama LLM-based IOC analysis (local AI)...")
    try:
        llm = OllamaLLM(model="llama3.2")
        prompt = PromptTemplate.from_template("""
You are a cybersecurity threat analyst. Analyze the following text and extract:
1. All threat indicators (IPs, domains, hashes, CVEs)
2. Threat actor names or groups mentioned
3. Malware family names
4. Attack techniques described
5. A brief 2-sentence threat summary

Text: {text}

Respond in this exact format:
THREAT_ACTORS: [list]
MALWARE_FAMILIES: [list]
ATTACK_TECHNIQUES: [list]
SUMMARY: [2 sentences]
""")
        chain = prompt | llm
        llm_analysis = chain.invoke({"text": text[:2000]})
    except Exception as e:
        llm_analysis = f"Ollama unavailable: {str(e)}"

    return {
        "regex_extracted_iocs": regex_iocs,
        "llm_analysis": llm_analysis,
        "total_iocs_found": sum(len(v) for v in regex_iocs.values() if isinstance(v, list))
    }