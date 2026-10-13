from core.cortex_graph import build_cortex_graph
import json

if __name__ == "__main__":
    target = "8.8.8.8"

    print("=" * 60)
    print("  CorteX AI — Autonomous CTI Pipeline")
    print("=" * 60)

    graph = build_cortex_graph()
    result = graph.invoke({
        "target": target,
        "target_type": "ip",
        "osint_data": None,
        "threat_data": None,
        "darkweb_data": None,
        "ioc_data": None,
        "mitre_data": None,
        "profile_data": None,
        "report_path": None
    })

    print("\n✅ Pipeline Complete!")
    print(f"📄 Report saved to: {result['report_path']}")
    print(f"🎯 Threat Rating: {result['profile_data'].get('overall_threat_rating')}")