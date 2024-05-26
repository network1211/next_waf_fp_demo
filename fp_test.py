import requests
import time
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define the base URL of your test web server
base_url = input("Please enter the base URL of the test web server: ").strip()

# List of advanced test scenarios with payloads similar to common attacks but not real attacks
test_scenarios = [
    # 1-3. HTTP Methods Test
    {"path": "/put", "method": "PUT", "data": {"key": "value"}},
    {"path": "/delete", "method": "DELETE"},
    {"path": "/patch", "method": "PATCH", "data": {"key": "value"}},
    
    # 4-6. HTTP Status Code Test
    {"path": "/status/415", "method": "GET"},
    {"path": "/status/490", "method": "GET"},
    {"path": "/status/511", "method": "GET"},
    
    # 7-8. XSS-like payloads
    {"path": "/anything", "method": "POST", "data": {"input": "<scrpt>('XSS_test')</scrpt>"}},
    {"path": "/anything", "method": "POST", "data": {"input": "img src=x_onerror=(1)>"}},
    
    # 9-10. SQL Injection-like payloads
    {"path": "/anything", "method": "POST", "data": {"username": "admin_OR_1=1_test", "password": "password"}},
    {"path": "/anything", "method": "POST", "data": {"query": "SELECT_*_FROM_user = 1_test;"}},
    
    # 11-12. SSRF-like payloads
    {"path": "/anything", "method": "POST", "data": {"url": "http://localhost:8080_test/admin"}},
    {"path": "/anything", "method": "POST", "data": {"url": "http://127.0.0.1_test:80"}},
    
    # 13-14. Path traversal-like payloads
    {"path": "/anything", "method": "POST", "data": {"file": ".../.../etc/passwd_test"}},
    {"path": "/anything", "method": "POST", "data": {"file": "/etc_2/hosts_test"}},
    
    # 15-16. Command Injection-like payloads
    {"path": "/anything", "method": "POST", "data": {"cmd_test": "echo hello_test && rm-rf_/test"}},
    {"path": "/anything", "method": "POST", "data": {"cmd_test": "ping_127.0.0.1_test"}},
    
    # 17-18. LDAP Injection-like payloads
    {"path": "/anything", "method": "POST", "data": {"username": "admin_test_password=*)"}},
    {"path": "/anything", "method": "POST", "data": {"username": "admin*_objectClass=*))_test"}},
    
    # 19-20. XML External Entity (XXE)-like payloads
    {"path": "/anything", "method": "POST", "data": {"xml": "<?xml version='1.0'?><!DOCTYPE_root_[ENTITY_test SYSTEM 'file://_/etc/passwd_test'>]><root>&test;</root>"}},
    {"path": "/anything", "method": "POST", "data": {"xml": "<!DOCTYPE foo [<!ELEMENT_foo_ANY ><!ENTITY_xxe_SYSTEM 'file:_///etc/shadow_test' >]><foo>&xxe;</foo>"}},
    
    # 21-22. JSON Injection-like payloads
    {"path": "/anything", "method": "POST", "json": {"key": "value", "injection": "{\"$ne_test\":null}"}},
    {"path": "/anything", "method": "POST", "json": {"key": "value", "injection": "{\"$gt_test\": \"\"}"}},
    
    # 23-24. HTTP Parameter Pollution-like payloads
    {"path": "/anything?param1=value1&param1=value2_test", "method": "GET"},
    {"path": "/anything?param1=value1&param2=value2&param2=value3_test", "method": "GET"},
    
    # 25-26. HTTP Response Splitting-like payloads
    {"path": "/anything", "method": "POST", "data": {"header": "Set-Cookie: mycookie=myvalue_test\r\nSet_Cookie: anothercookie=anothervalue_test"}},
    {"path": "/anything", "method": "POST", "data": {"header": "Content-Length: 0_test\r\n\r\nHTTP/1.1 200 OK\r\nContent_Length: 0_test"}},
    
    # 27-28. Remote File Inclusion-like payloads
    {"path": "/anything", "method": "POST", "data": {"include": "http://example.com_/shell_test.php"}},
    {"path": "/anything", "method": "POST", "data": {"include": "http://example.com_/malware_test.txt"}},
    
    # 29-31. Hidden file Access-lise payloads
    {"path": "/anything/.png", "method": "GET"},
    {"path": "/anything/.img", "method": "GET"},
    {"path": "/anything/.jpg", "method": "GET"},

    # 32. Case with the header has an empty value // Protocol Compliance
    {"path": "/anything", "method": "GET", "headers": {"X-Custom-Key": ""}},

    # 33. Case with 30+ custom headers
    {"path": "/anything", "method": "GET", "headers": {f"X-Custom-Header-{i}": f"Value-{i}" for i in range(1, 35)}},

    # 34. Case with 'Referer' header set to 'SQL Injection Similar'
    {"path": "/anything", "method": "GET", "headers": {"Referer": "https://www.example.com/personal/credit-cards/select-krongtest-point.page?utm_medium\u003dpost\u0026kkk_source\u003dsocialmedia\u0026utm_testnet\u003dABCDE\u0026s_cid\u003dPFS:cc:paid:soc:socialmedia:post:ABCDES:240213-alwayson:aaa:aaa\u0026fbclid\u003dAJco5-ek6tVy0xa4EM_aem_AJAXVJBMlXEEGV4k0_kMhkK2Z"}},

    # 35-37. XSS FPs (source: reddit community)
    {"path": "/anything/airports?query=TORONTO%2C+ON&verbose=true", "method": "GET"},
    {"path": "/anything/countries/CA/subdivisions?query=Ottawa%2C+Ontario%2C&verbose=true", "method": "GET"},
    {"path": "/anything/files", "method": "GET"},

    # 38-39. SQL Injection FPs (source: reddit community)
    {"path": "/anything/places?query=48+RUE+THIERS%2C+BEAUNE+COTE-D%27OR+21200&sort=-population&limit=1&verbose=true", "method": "GET"},
    {"path": "/anything/airports?query=48+rue+Thiers%2C+Beaune+Cote-d%27OR+21200&verbose=true", "method": "GET"},

    # 40-41. XSS FPs (source: reddit community)
    {"path": "/anything", "method": "POST", "data": {"include": "data/dBV6+ON23vgWCNw=="}},
    {"path": "/anything", "method": "POST", "data": {"include": "data/m18Vm/OneccWI51Yz=="}},

    # 42. Generic FP (source: Mod Security site)
    {"path": "/anything/wp_post=\u003ch1\u003eWelcome+To+My+Blog\u003c\u002fh1\u003e", "method": "GET"},

    # 43. Generic FP (source: Microsoft Website)
    {"path": "/anything", "method": "POST", "data": {"email":"useremail","password":"userpassword"}},

    # 44-50. Generic Community FP Cases (source: Google search)
    {"path": "/anything/drupal/sites/default/files/js/js_BKcMdIbOMdbTdLn9dkUq3KCJfIKKo2SvKoQ1AnB8D-g.js", "method": "GET"},
    {"path": "/anything/drupal/sites/default/files/css/css_kFrQ9wBoa2QH_pCSVdx-TU3BRT7bRUtR7jqEdVsVvWI.css?0", "method": "GET"},
    {"path": "/anything/drupal/sites/default/files/css/css_0ZeUtppA-1bysY8TdQeTGIFxj-OQMRnHUsUAGsuDmAM.css?0", "method": "GET"},
    {"path": "/anything/drupal/core/themes/stable/images/core/icons/000000/file.svg", "method": "GET"},
    {"path": "/anything/drupal/index.php/admin/content", "method": "GET"},
    {"path": "/anything/drupal/sites/default/files/js/js_4dBqy56Ono841PF1xRJp91pgw4cdjG_XbDhG6T3KYTk.js", "method": "GET"},
    {"path": "/anything/drupal/index.php/contextual/render", "method": "POST", "data": "ids%5B%5D=block%3Ablock%3Dbartik_breadcrumbs%3Alangcode%3Den&ids%5B%5D=block%3Ablock%3Dbartik_local_tasks%3Alangcode%3Den"}
]

# Function to perform HTTP requests based on the test scenarios
def run_test_scenario(scenario, test_number):
    url = base_url + scenario["path"]
    method = scenario["method"]
    data = scenario.get("data")
    json_data = scenario.get("json")
    headers = scenario.get("headers", {})
    
    response = None
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, verify=False)
        elif method == "POST":
            if data:
                response = requests.post(url, data=data, headers=headers, verify=False)
            elif json_data:
                response = requests.post(url, json=json_data, headers=headers, verify=False)
        elif method == "PUT":
            response = requests.put(url, data=data, headers=headers, verify=False)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, verify=False)
        elif method == "PATCH":
            response = requests.patch(url, data=data, headers=headers, verify=False)
        # Check if the response contains a non-standard status code and handle it
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            print(f"Test {test_number}: {scenario}")
            print(f"Non-Standard HTTP Status Code: {response.status_code}\n")
            return response

        # Print the test number, scenario, and status code
        print(f"Test {test_number}: {scenario}")
        if response:
            print(f"Response Code: {response.status_code}\n")

    except requests.RequestException as e:
            print(f"Request failed: {e}")
    
    return response

# Run the test scenarios and calculate the FP rate
def run_tests_and_calculate_fp_rate():
    total_tests = len(test_scenarios)
    false_positives = 0
    total_time = 30  # total time in seconds
    delay = total_time / total_tests  # delay between each request

    for i, scenario in enumerate(test_scenarios):
        response = run_test_scenario(scenario, i + 1)
        if response is None or (response is not None and response.status_code == 503):
            false_positives += 1
        time.sleep(delay)  # Delay between each request

    fp_rate = (false_positives / total_tests) * 100
    print(f"Total tests run: {total_tests}")
    print(f"False Positives: {false_positives}")
    print(f"False Positive Rate: {fp_rate:.2f}%")

# Run the tests and display the FP rate
if __name__ == "__main__":
    run_tests_and_calculate_fp_rate()
