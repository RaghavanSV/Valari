import os
from crewai import Agent, Task, Crew, Process
from crewai.tools import tool
from langchain_community.llms import Ollama
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI  # ADD THIS
import sqlite3      
import json
from langchain_anthropic import ChatAnthropic
import time
# ==================== LLM CONFIGURATION ====================

#pop the openai api
os.environ.pop("OPENAI_API_KEY",None)
os.environ["OPENAI_API_KEY"] = ""

# Set your Google API key
os.environ["GOOGLE_API_KEY"] = ""  

llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    temperature=0.7,
)

print("✓ Using Gemini Flash as LLM")

# ==================== TOOLS ====================

@tool
def query_cve_database(cve_id: str) -> str:
    """
    Query the CVE database for detailed information about a specific CVE.
    Returns comprehensive CVE data including description, CVSS scores, affected software, and references.
    """
    from cve_gatherer import CVEContextGatherer  # Your previous script
    
    gatherer = CVEContextGatherer("cve_exploits.db")
    data = gatherer.query_cve(cve_id)
    
    if not data:
        return f"No data found for {cve_id}"
    
    cve = data['cve']
    result = f"""
CVE ID: {cve['cve_id']}
Description: {cve['description']}
Vulnerability Type: {cve['vulnerability_type']}
CWE: {cve['cwe_id']} - {cve['cwe_name']}
CVSS v3 Score: {cve['cvss_v3_score']} ({cve['cvss_v3_severity']})
Exploitability Score: {cve['exploitability_score']}
Impact Score: {cve['impact_score']}

Affected Software:
{json.dumps(data['affected_software'], indent=2)}

References:
{json.dumps(data['references'][:5], indent=2)}

Available PoCs:
{json.dumps(data['pocs'], indent=2)}
"""
    return result

@tool
def search_github_pocs(cve_id: str) -> str:
    """
    Search GitHub for proof-of-concept exploits for a given CVE.
    Returns list of relevant repositories.
    """
    import requests
    import time
    
    url = "https://api.github.com/search/repositories"
    params = {
        'q': f'{cve_id} poc OR exploit',
        'sort': 'stars',
        'order': 'desc',
        'per_page': 10
    }
    
    try:
        response = requests.get(url, params=params, timeout=15)
        if response.status_code == 200:
            data = response.json()
            results = []
            for item in data.get('items', []):
                results.append({
                    'name': item['name'],
                    'url': item['html_url'],
                    'stars': item['stargazers_count'],
                    'description': item.get('description', 'N/A')
                })
            return json.dumps(results, indent=2)
        return "Failed to search GitHub"
    except Exception as e:
        return f"Error: {str(e)}"

@tool
def validate_python_code(code: str) -> str:
    """
    Validate Python code for syntax errors and common issues.
    Returns validation results.
    """
    import ast
    import re
    
    issues = []
    
    # Syntax check
    try:
        ast.parse(code)
        issues.append("✓ Syntax is valid")
    except SyntaxError as e:
        issues.append(f"✗ Syntax Error: {e}")
    
    # Check for common imports
    required_imports = ['pwntools', 'socket', 'struct']
    for imp in required_imports:
        if imp in code or imp.replace('tools', '') in code:
            issues.append(f"✓ Found {imp} import")
    
    # Check for error handling
    if 'try:' in code and 'except' in code:
        issues.append("✓ Has error handling")
    else:
        issues.append("⚠ Missing error handling")
    
    # Check for comments
    comment_count = len(re.findall(r'#.*', code))
    if comment_count > 5:
        issues.append(f"✓ Well documented ({comment_count} comments)")
    else:
        issues.append(f"⚠ Needs more comments ({comment_count} found)")
    
    return "\n".join(issues)

@tool
def save_exploit(filename: str, code: str) -> str:
    """
    Save generated exploit code to a file.
    """
    try:
        with open(f"exploits/{filename}", 'w') as f:
            f.write(code)
        return f"✓ Exploit saved to exploits/{filename}"
    except Exception as e:
        return f"✗ Error saving: {e}"

# ==================== AGENTS ====================

# 1. Research Agent
research_agent = Agent(
    role='CVE Research Specialist',
    goal='Gather comprehensive intelligence about CVEs including technical details, PoCs, and vulnerability patterns',
    backstory="""You are an expert security researcher specializing in vulnerability analysis.
    You have deep knowledge of CVE databases, exploit repositories, and security advisories.
    Your job is to gather all relevant information about a CVE to enable exploit development.""",
    tools=[query_cve_database, search_github_pocs],
    llm=llm,
    verbose=True,
    allow_delegation=False
)

# 2. Exploit Generator Agent
exploit_generator = Agent(
    role='Exploit Development Engineer',
    goal='Create working proof-of-concept exploits for known vulnerabilities',
    backstory="""You are a seasoned exploit developer with expertise in RCE, memory corruption, and bypass techniques. You write clean, well-documented Python
    exploits using pwntools and especially creating independent exploits that can work independently and can adapt techniques for different architectures and protections.
    You always consider ASLR, DEP/NX, and stack canaries in your exploits.""",
    tools=[],
    llm=llm,
    verbose=True,
    allow_delegation=False
)

# 3. Code Validator Agent
validator_agent = Agent(
    role='Security Code Reviewer',
    goal='Validate exploit code for correctness, safety, and best practices',
    backstory="""You are a meticulous code reviewer specializing in security tools.
    You check for syntax errors, logic flaws, missing error handling, and ensure
    exploits follow best practices. You provide constructive feedback for improvement.""",
    tools=[validate_python_code],
    llm=llm,
    verbose=True,
    allow_delegation=False
)

# 4. Orchestrator Agent (Crew Manager)
orchestrator = Agent(
    role='Exploit Generation Orchestrator',
    goal='Coordinate the exploit generation process from research to final validated code',
    backstory="""You are the master coordinator of the exploit generation pipeline.
    You analyze requests, plan the workflow, delegate tasks to specialists, and
    ensure high-quality output. You make strategic decisions about which techniques
    to use and how to handle edge cases.""",
    tools=[save_exploit],
    llm=llm
,
    verbose=True,
    allow_delegation=True
)

# ==================== TASKS ====================

def create_exploit_generation_tasks(cve_id: str, num_variants: int = 3):
    """Create task pipeline for exploit generation"""
    
    # Task 1: Research CVE
    research_task = Task(
        description=f"""
        Research {cve_id} thoroughly:
        1. Query the CVE database for complete details
        2. Search GitHub for existing PoCs
        3. Identify the vulnerability type and exploitation approach
        4. Summarize key technical details needed for exploit development
        
        Provide a comprehensive research report.
        """,
        agent=research_agent,
        expected_output="Detailed CVE research report with vulnerability analysis"
    )
    
    # Task 2: Generate Exploits
    exploit_tasks = []
    strategies = [
        "ROP-based exploit with minimal payload",
        "ret2libc approach for DEP bypass",
        "Heap spray technique with shellcode",
        "Format string exploitation",
        "Race condition exploitation"
    ]
    
    for i in range(num_variants):
        strategy = strategies[i % len(strategies)]
        exploit_task = Task(
            description=f"""
            Based on the research from the previous task, generate a working Python exploit for {cve_id}.
            
            Strategy: {strategy}
            
            Requirements:
            - Complete Python script using pwntools
            - Handle common mitigations (ASLR, DEP/NX)
            - Include detailed comments explaining each step
            - Add error handling and debugging output
            - Make it variant #{i+1} - make it different from other variants
            
            Output the complete exploit code.
            """,
            agent=exploit_generator,
            expected_output=f"Complete working Python exploit code (variant {i+1})",
            context=[research_task]
        )
        exploit_tasks.append(exploit_task)
    
    # Task 3: Validate all exploits
    validation_tasks = []
    for i, exploit_task in enumerate(exploit_tasks):
        validation_task = Task(
            description=f"""
            Review and validate exploit variant #{i+1}:
            1. Check Python syntax
            2. Verify logic and approach
            3. Ensure proper error handling
            4. Check for security best practices
            5. Suggest improvements if needed
            
            Provide detailed validation report.
            """,
            agent=validator_agent,
            expected_output=f"Validation report for variant {i+1}",
            context=[exploit_task]
        )
        validation_tasks.append(validation_task)
    
    # Task 4: Final synthesis
    synthesis_task = Task(
        description=f"""
        Review all generated exploits and validations for {cve_id}.
        
        1. Summarize what was created
        2. Highlight the best variant and why
        3. Save each exploit to files: {cve_id}_variant_1.py, {cve_id}_variant_2.py, etc.
        4. Provide final recommendations
        
        Create a comprehensive final report.
        """,
        agent=orchestrator,
        expected_output="Final summary with saved exploit files",
        context=exploit_tasks + validation_tasks
    )
    
    return [research_task] + exploit_tasks + validation_tasks + [synthesis_task]

# ==================== CREW ====================

def generate_exploits_with_agents(cve_id: str, num_variants: int = 3):
    """Main function to generate exploits using CrewAI agents"""
    
    # Create output directory
    os.makedirs("exploits", exist_ok=True)
    
    # Create tasks
    tasks = create_exploit_generation_tasks(cve_id, num_variants)
    
    # Create crew
    crew = Crew(
        agents=[research_agent, exploit_generator, validator_agent, orchestrator],
        tasks=tasks,
        process=Process.sequential,  # Tasks run in order
        verbose=True
    )
    
    # Execute
    print(f"\n{'='*60}")
    print(f"Starting exploit generation for {cve_id}")
    print(f"Generating {num_variants} variants")
    print(f"{'='*60}\n")
    
    try:
        result = crew.kickoff()
        
        print(f"\n{'='*60}")
        print("FINAL RESULT")
        print(f"{'='*60}")
        print(result)
        
        return result
    except Exception as e:
        print(f"Error Occured :{e}")
        import traceback
        traceback.print_exc()

# ==================== USAGE ====================

if __name__ == "__main__":
    # First, ensure CVE data is in database
    from cve_gatherer import CVEContextGatherer
    
    gatherer = CVEContextGatherer("cve_exploits.db")
    
    # Gather some CVEs if not already in DB
    test_cves = ["CVE-2021-44228", "CVE-2017-0144"]
    
    print("Checking database for CVE data...")
    for cve in test_cves:
        data = gatherer.query_cve(cve)
        if not data:
            print(f"Gathering {cve}...")
            gatherer.gather_cve_context(cve)
    
    # Now generate exploits using agents
        result = generate_exploits_with_agents(
            cve_id=cve,  # Log4Shell
            num_variants=3
        )
        time.sleep(60)