import os
from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()
uri = os.environ.get("NEO4J_URI")
username = os.environ.get("NEO4J_USERNAME")
password = os.environ.get("NEO4J_PASSWORD")

driver = GraphDatabase.driver(uri, auth=(username, password))
query = """
CREATE (u:User {
    user_id: "dr-patel-4521",
    employee_id: "DR-0001",
    name: "Dr. Rajesh Patel",
    role: "Attending_Physician",
    department: "Cardiology",
    facility: "FAC-001",
    clearance: 4,
    mfa_enabled: true,
    is_active: true
})
"""

try:
    with driver.session() as session:
        session.run(query)
        print("✅ SUCCESS! Dr. Patel's User Node was successfully re-injected into your Neo4j Graph Database!")
except Exception as e:
    print(f"❌ ERROR: {e}")
finally:
    driver.close()
