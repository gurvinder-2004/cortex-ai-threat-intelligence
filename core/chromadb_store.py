import chromadb
from chromadb.utils import embedding_functions
import json
import os

# Use local sentence transformer — no API key needed
ef = embedding_functions.SentenceTransformerEmbeddingFunction(
    model_name="all-MiniLM-L6-v2"
)

client = chromadb.PersistentClient(path="./data/chromadb")
collection = client.get_or_create_collection(
    name="cortex_iocs",
    embedding_function=ef
)

def store_intelligence(target: str, data: dict, source: str):
    """Store threat intelligence in ChromaDB"""
    try:
        text = json.dumps(data)[:2000]
        doc_id = f"{source}_{target}_{hash(text) % 100000}"
        collection.add(
            documents=[text],
            metadatas=[{"target": target, "source": source}],
            ids=[doc_id]
        )
        print(f"[ChromaDB] Stored {source} data for {target}")
    except Exception as e:
        print(f"[ChromaDB] Store error: {e}")

def query_similar_threats(query: str, n_results: int = 5) -> list:
    """Find semantically similar threat intelligence"""
    try:
        results = collection.query(
            query_texts=[query],
            n_results=n_results
        )
        matches = []
        for i, doc in enumerate(results["documents"][0]):
            matches.append({
                "content": doc[:300],
                "metadata": results["metadatas"][0][i],
                "distance": results["distances"][0][i]
            })
        return matches
    except Exception as e:
        return [{"error": str(e)}]