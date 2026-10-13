from langgraph.graph import StateGraph, END
from typing import TypedDict, Optional
from agents.osint_agent import run_osint_agent
from agents.threat_feed_agent import run_threat_feed_agent
from agents.darkweb_agent import run_darkweb_agent
from agents.ioc_agent import run_ioc_agent
from agents.mitre_agent import run_mitre_agent
from agents.profiling_agent import run_profiling_agent
from agents.report_agent import generate_report

class CorteXState(TypedDict):
    target: str
    target_type: str
    osint_data: Optional[dict]
    threat_data: Optional[dict]
    darkweb_data: Optional[dict]
    ioc_data: Optional[dict]
    mitre_data: Optional[dict]
    profile_data: Optional[dict]
    report_path: Optional[str]

def osint_node(state: CorteXState) -> CorteXState:
    state["osint_data"] = run_osint_agent(state["target"])
    return state

def threat_feed_node(state: CorteXState) -> CorteXState:
    state["threat_data"] = run_threat_feed_agent(state["target"], state["target_type"])
    return state

def darkweb_node(state: CorteXState) -> CorteXState:
    state["darkweb_data"] = run_darkweb_agent(state["target"])
    return state

def ioc_node(state: CorteXState) -> CorteXState:
    combined_text = str(state["osint_data"]) + str(state["threat_data"]) + str(state["darkweb_data"])
    state["ioc_data"] = run_ioc_agent(combined_text)
    return state

def mitre_node(state: CorteXState) -> CorteXState:
    state["mitre_data"] = run_mitre_agent(
        state["osint_data"],
        state["threat_data"],
        state["darkweb_data"]
    )
    return state

def profiling_node(state: CorteXState) -> CorteXState:
    state["profile_data"] = run_profiling_agent(
        state["target"],
        state["osint_data"],
        state["threat_data"],
        state["darkweb_data"],
        state["mitre_data"]
    )
    return state

def report_node(state: CorteXState) -> CorteXState:
    state["report_path"] = generate_report(
        state["target"],
        state["osint_data"],
        state["threat_data"],
        state["darkweb_data"],
        state["mitre_data"],
        state["profile_data"]
    )
    return state

def build_cortex_graph():
    graph = StateGraph(CorteXState)

    graph.add_node("osint", osint_node)
    graph.add_node("threat_feeds", threat_feed_node)
    graph.add_node("darkweb", darkweb_node)
    graph.add_node("ioc_extraction", ioc_node)
    graph.add_node("mitre_mapping", mitre_node)
    graph.add_node("profiling", profiling_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("osint")
    graph.add_edge("osint", "threat_feeds")
    graph.add_edge("threat_feeds", "darkweb")
    graph.add_edge("darkweb", "ioc_extraction")
    graph.add_edge("ioc_extraction", "mitre_mapping")
    graph.add_edge("mitre_mapping", "profiling")
    graph.add_edge("profiling", "report")
    graph.add_edge("report", END)

    return graph.compile()