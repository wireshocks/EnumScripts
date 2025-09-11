from neo4j import GraphDatabase
import json
import re

# Neo4j connection details
URI = "bolt://localhost:7687"  # Update with your Neo4j instance URI
USERNAME = "neo4j"  # Update with your Neo4j username
PASSWORD = "Neo4j"  # Update with your Neo4j password

# Input file containing Cypher queries
QUERY_FILE = "cypher_queries.txt"

def read_queries(file_path):
    """Read Cypher queries from a text file, ignoring comments and empty lines."""
    queries = []
    try:
        with open(file_path, "r") as f:
            # Read file and split by semicolons
            content = f.read().strip()
            # Split by semicolon, strip whitespace, and filter out empty queries
            raw_queries = [q.strip() for q in content.split(";") if q.strip()]
            # Filter out comments (lines starting with // or #) and empty lines
            for q in raw_queries:
                # Remove any inline comments or trailing whitespace
                q_clean = re.sub(r'//.*$', '', q, flags=re.MULTILINE).strip()
                q_clean = re.sub(r'#.*$', '', q_clean, flags=re.MULTILINE).strip()
                if q_clean and not q_clean.startswith(('//', '#')):
                    queries.append(q_clean)
        return queries
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return []
    except Exception as e:
        print(f"Error reading queries: {e}")
        return []

def run_query(driver, query):
    """Execute a single Cypher query and return the results."""
    with driver.session() as session:
        result = session.run(query)
        # Extract paths and their nodes/relationships
        paths = []
        for record in result:
            path = record["p"]
            path_data = {
                "nodes": [{"id": node.element_id, "labels": list(node.labels), "properties": dict(node)} for node in path.nodes],
                "relationships": [{"id": rel.element_id, "type": rel.type, "start_node": rel.start_node.element_id, "end_node": rel.end_node.element_id} for rel in path.relationships]
            }
            paths.append(path_data)
        return paths

def save_to_file(data, filename="bloodhound_output.json"):
    """Save query results to a JSON file."""
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Data saved to {filename}")

def main():
    try:
        # Initialize Neo4j driver
        driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))
        
        # Read queries from file
        queries = read_queries(QUERY_FILE)
        if not queries:
            print("No valid queries found. Exiting.")
            return
        
        # Store results for all queries
        all_results = []
        successful_queries = []
        
        # Execute each query
        for i, query in enumerate(queries, 1):
            try:
                results = run_query(driver, query)
                # Check if results contain any relationships
                has_relationships = any(path["relationships"] for path in results)
                all_results.append({"query": query, "results": results})
                if has_relationships:
                    successful_queries.append(i)  # Track query number if it has relationships
            except Exception as e:
                print(f"Query {i} failed: {e}")
        
        # Report successful queries (those with relationships)
        if successful_queries:
            print("Queries with relationships:", ", ".join(f"Query {num}" for num in successful_queries))
        else:
            print("No queries returned relationships.")
        
        # Save all results to a file
        if all_results:
            save_to_file(all_results)
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        driver.close()
        print("Idea by Muharram Ali")  # message
        print("-------------------------------------------")  # message
        print("You can now run the command below to view the query you’re interested in!")  # message
        print("-------------------------------------------")  # message
        print("sed -n '/Query 2/,+9p' cypher_queries.txt")  # +9p = Read from line 9 onwards
        print("cat cypher_queries.txt | grep query")  # Read query lines
        print("Read More info on BloodHound's General Tab and Check Layout for table")  # +9p = Read from line 9 onwards
        print("Make sure you have marked owned users and computers before running this script")  # +9p = Read from line 9 onwards
                

if __name__ == "__main__":
    main()
