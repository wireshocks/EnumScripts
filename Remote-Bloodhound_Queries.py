from neo4j import GraphDatabase
import json
import re
import requests

# Neo4j connection details
URI = "bolt://localhost:7687"
USERNAME = "neo4j"
PASSWORD = "Neo4j"

# GitHub Raw URL for your Cypher queries
# Replace this with your actual raw URL
QUERY_URL = "https://raw.githubusercontent.com/wireshocks/EnumScripts/refs/heads/main/cypher_queries.txt"

# Query comments mapping
QUERY_COMMENTS = {
    1: "Domain Admins",
    2: "Identifying potential cross-domain attack paths",
    3: "High Value Objects or locations of Tier Zero",
    4: "Principals with DCSync Privileges",
    5: "Foreign Domain Group Membership potentially cross-domain trust abuse",
    6: "Computers where domain users are Local administrators",
    7: "Computers where Domain Users can read LAPS passwords",
    8: "Paths from Domain Users to Tier Zero or High Value targets",
    9: "Computers where Domain Users can RDP",
    10: "Servers where Domain Users can RDP",
    11: "Dangerous privileges for Domain Users groups",
    12: "Domain Admins logon to non-Domain Controllers",
    13: "Kerberoastable members of Tier Zero / High Value groups",
    14: "All Kerberoastable users",
    15: "Kerberoastable users with most admin privileges",
    16: "AS-REP Roastable users",
    17: "Shortest paths to systems trusted for unconstrained delegation",
    18: "Shortest paths to Domain Admins from Kerberoastable users",
    19: "Shortest paths to Tier Zero or High Value targets",
    20: "Shortest paths from Domain Users to Teir Zero or High Value targets",
    21: "Shortest paths to Domain Admins",
    22: "Shortest Paths from Owned Objects to Tier Zero - Run AT YOUR OWN RISK",
    23: "Shortest paths from Owned objects",
    24: "Domains where any user can join or add a computer to the domain",
    25: "DCs vulnerable to NTLM relay to LDAP attacks",
    26: "Computers with the WebClient Running",
    27: "Computers not requiring inbound SMB signing",
    28: "-Custom- Replace keyword with a service type or server name (not FQDN)",
    29: "-Custom- Custom All DNSAdmins",
    30: "-Custom- Computer owners who can obtain LAPS passwords",
    31: "-Custom- Domains affected by Exchange privilege escalation risk",
    32: "-Custom- Kerberos-enabled service account member of built-in Admins groups",
    33: "-Custom- Accounts with clear-text password attributes",
    34: "-Custom- Enabled built-in guest user accounts",
    35: "-Custom- Find Users with outbound object control",
    36: "-Custom-  Find Users with outbound object control to any node",
    37: "-Custom-  Find groups with outbound object control to computers"
}

def read_queries_from_github(url):
    """Fetch and parse Cypher queries from a GitHub raw text URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        content = response.text
        
        # Remove multi-line comments /* ... */
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        
        # Split by semicolons
        raw_queries = [q.strip() for q in content.split(";") if q.strip()]
        
        queries = []
        for q in raw_queries:
            # Remove single-line comments // and #
            q_clean = re.sub(r'(//|#).*$', '', q, flags=re.MULTILINE).strip()
            if q_clean:
                queries.append(q_clean)
        
        print(f"Successfully loaded {len(queries)} queries from GitHub.")
        return queries
    except requests.exceptions.RequestException as e:
        print(f"Error fetching from GitHub: {e}")
        return []
    except Exception as e:
        print(f"Error processing queries: {e}")
        return []

def run_query(driver, query):
    """Execute a Cypher query and return the results."""
    with driver.session() as session:
        result = session.run(query)
        paths = []
        for record in result:
            # Assuming query returns path 'p' as per original script
            path = record.get("p")
            if path:
                path_data = {
                    "nodes": [{"id": node.element_id, "labels": list(node.labels), "properties": dict(node)} for node in path.nodes],
                    "relationships": [{"id": rel.element_id, "type": rel.type, "start_node": rel.start_node.element_id, "end_node": rel.end_node.element_id} for rel in path.relationships]
                }
                paths.append(path_data)
        return paths

def save_to_file(data, filename="bloodhound_output.json"):
    """Save results to JSON."""
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Data saved to {filename}")

def main():
    driver = None
    try:
        # Initialize driver
        driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))
        driver.verify_connectivity() # 2026 Best Practice
        
        # Load queries from GitHub
        queries = read_queries_from_github(QUERY_URL)
        if not queries:
            print("No valid queries found. Exiting.")
            return
        
        all_results = []
        successful_indices = []
        
        for i, query in enumerate(queries, 1):
            try:
                results = run_query(driver, query)
                has_relationships = any(path["relationships"] for path in results)
                all_results.append({"query_index": i, "query": query, "results": results})
                if has_relationships:
                    successful_indices.append(i)
            except Exception as e:
                print(f"Query {i} failed: {e}")
        
        # Output status
        if successful_indices:
            print("\nQueries with relationships found:")
            for idx in successful_indices:
                comment = QUERY_COMMENTS.get(idx, "No description")
                print(f"[{idx}] {comment}")
        
        if all_results:
            save_to_file(all_results)
            
    except Exception as e:
        print(f"Main Error: {e}")
    finally:
        if driver:
            driver.close()
        print("\n-------------------------------------------")
        print("Script execution complete.")
        print("Idea by: Muharram Ali")
        print("-------------------------------------------")

if __name__ == "__main__":
    main()
