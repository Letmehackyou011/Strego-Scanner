import os
import subprocess
import time
from cryptography.fernet import Fernet

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    api_key = input("Enter your OpenAI API key If available: ").strip()

openai.api_key = api_key

def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

def encrypt_message(message):
    key = load_key()
    encoded_message = message.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)
    return encrypted_message

def decrypt_message(encrypted_message):
    key = load_key()
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()

def banner():
    print("""

 ░▒▓███████▓▒░▒▓████████▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░  
░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░   ░▒▓█▓▒░   ░▒▓███████▓▒░░▒▓██████▓▒░░▒▓█▓▒▒▓███▓▒░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░  
                                                                                                                                                            
   A automatic vulnerability scanner with Nmap made by https://github.com/Letmehackyou011.\n
   This tool is for educational and ethical hacking purposes only. Unauthorized scanning is illegal.\n
   If you want to change or modify this tool. Please atleast give me credit :)""")

tools = {
    # Web Vulnerability Scanners
    "sqlmap": "sqlmap -u http://{target} --batch --dbs --risk=3 --level=5",
    "xsstrike": "xsstrike -u http://{target}",
    "nikto":"nikto -h {target}",
    "wapiti": "wapiti -u http://{target}",
    "gobuster": "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt",
    "dirb": "dirb http://{target} /usr/share/wordlists/dirb/common.txt",
    "wfuzz": "wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc 404 http://{target}/FUZZ",
    "commix": "commix -u http://{target}",
    "skipfish": "skipfish -o output_dir http://{target}",
    "vega": "vega http://{target}",
    "arachni": "arachni http://{target}",
    "owasp-zap": "zap-cli quick-scan -spider -sc -r -o -u http://{target}",
    "burp-suite": "java -jar burpsuite.jar --project-file=burp_project.burp --config-file=burp_config.json",
    "wpscan": "wpscan --url http://{target} --enumerate p,t,u",
    "joomscan": "joomscan -u http://{target}",
    "droopescan": "droopescan scan drupal -u http://{target}",
    "cmsmap": "cmsmap -t http://{target}",
    "whatweb": "whatweb http://{target}",
    "eyewitness": "eyewitness --web --single http://{target}",
    "retire.js": "retire --path http://{target}",
    "sslyze": "sslyze --regular {target}",
    "testssl": "testssl.sh {target}",
    "nuclei": "nuclei -u http://{target}",
    "gitleaks": "gitleaks --repo-url=http://{target}",

    # Network Scanners
    "masscan": "masscan -p1-65535 {target}",
    "rustscan": "rustscan -a {target}",
    "amass": "amass enum -d {target}",
    "sublist3r": "sublist3r -d {target}",
    "sn1per": "sn1per -t {target}",
    "nessus": "nessus -s {target}",
    "openvas": "openvas -t {target}",
    "acunetix": "acunetix -t {target}",
    "netsparker": "netsparker -t {target}",

    # Brute-Forcing Tools
    "hydra": "hydra -L users.txt -P passwords.txt {target} ftp -V",
    "patator": "patator ftp_login host={target} user=FILE0 password=FILE1 0=users.txt 1=passwords.txt",
    "medusa": "medusa -h {target} -U users.txt -P passwords.txt -M ftp",
    "ncrack": "ncrack -U users.txt -P passwords.txt {target}",
    "crowbar": "crowbar -b rdp -s {target} -u users.txt -C passwords.txt",

    # Enumeration Tools
    "enum4linux": "enum4linux -a {target}",
    "smbmap": "smbmap -H {target}",
    "smbclient": "smbclient -L //{target}",
    "ldapsearch": "ldapsearch -x -h {target}",
    "rpcclient": "rpcclient -U '' {target}",
    "snmpwalk": "snmpwalk -c public -v1 {target}",
    "onesixtyone": "onesixtyone {target}",
    "nbtscan": "nbtscan {target}",
    "ike-scan": "ike-scan {target}",
    "dnsenum": "dnsenum {target}",
    "dnsrecon": "dnsrecon -d {target}",
    "dnswalk": "dnswalk {target}",
    "fierce": "fierce --domain {target}",
    "theharvester": "theharvester -d {target} -b all",
    "recon-ng": "recon-ng -w {target}",
    "metagoofil": "metagoofil -d {target}",
    "maltego": "maltego -t {target}",
}

def run_nmap(target):
    print(f"[+] Scanning {target} with Nmap...")
    nmap_cmd = f"nmap -sS -sV -p- --script=vuln {target}"
    result = subprocess.getoutput(nmap_cmd)
    print(result)
    return result

def check_vulnerabilities(scan_output):
    vulnerabilities = []
    if "80/tcp open" in scan_output or "443/tcp open" in scan_output:
        vulnerabilities.append("[!] Possible Web Exploit: Running SQLmap & XSStrike...")
    if "21/tcp open" in scan_output:
        vulnerabilities.append("[!] FTP Open: Trying Anonymous Login...")
    if "139/tcp open" in scan_output or "445/tcp open" in scan_output:
        vulnerabilities.append("[!] SMB Open: Running Enum4Linux & Metasploit...")
    if "3306/tcp open" in scan_output:
        vulnerabilities.append("[!] MySQL Open: Trying Default Credentials...")
    if "3389/tcp open" in scan_output:
        vulnerabilities.append("[!] RDP Open: Brute-forcing with Hydra...")
    return vulnerabilities

def run_tool(tool_name, target):
    if tool_name in tools:
        print(f"[+] Running {tool_name} on {target}...")
        subprocess.run(tools[tool_name], shell=True)
    else:
        print(f"[-] Tool '{tool_name}' not found in the tool list.")

def ai_recommend_tools(scan_output):
    """
    Use AI to recommend tools based on Nmap scan output.
    """
    prompt = f"Based on the following Nmap scan results, recommend the best tools to use:\n\n{scan_output}\n\nRecommended tools:"
    response = openai.Completion.create(
        engine="text-davinci-003",
        prompt=prompt,
        max_tokens=100,
        temperature=0.7,
    )
    return response.choices[0].text.strip()

def ai_chat(query):
    """
    Use AI to process user queries and provide responses.
    """
    response = openai.Completion.create(
        engine="text-davinci-003",
        prompt=query,
        max_tokens=150,
        temperature=0.7,
    )
    return response.choices[0].text.strip()

def display_menu():
    print("\n===== Main Menu =====")
    print("1. Scan Target with Nmap")
    print("2. Run a Specific Tool")
    print("3. AI Tool Recommendations")
    print("4. AI Chat")
    print("0. Exit")

def main():
    generate_key()  # Ensure the key is generated
    banner()
    target = input("Enter target IP or domain: ")

    while True:
        display_menu()
        choice = input("\nEnter your choice (0-4): ").strip()

        if choice == "0":
            print("[+] Exiting...")
            break
        elif choice == "1":
            # Run Nmap scan
            scan_output = run_nmap(target)
            vulnerabilities = check_vulnerabilities(scan_output)
            for vuln in vulnerabilities:
                print(vuln)
        elif choice == "2":
            # Run a specific tool
            print("\n===== Tool Menu =====")
            print("1. SQLmap")
            print("2. XSStrike")
            print("3. Nikto")
            print("4. Wapiti")
            print("5. Gobuster")
            print("6. Dirb")
            print("7. Wfuzz")
            print("8. Commix")
            print("9. Skipfish")
            print("10. Vega")
            print("11. Arachni")
            print("12. OWASP ZAP")
            print("13. Burp Suite")
            print("14. WPScan")
            print("15. JoomScan")
            print("16. Droopescan")
            print("17. CMSmap")
            print("18. WhatWeb")
            print("19. EyeWitness")
            print("20. Retire.js")
            print("21. SSLyze")
            print("22. TestSSL")
            print("23. Nuclei")
            print("24. Gitleaks")
            print("25. Masscan")
            print("26. RustScan")
            print("27. Amass")
            print("28. Sublist3r")
            print("29. Sn1per")
            print("30. Nessus")
            print("31. OpenVAS")
            print("32. Acunetix")
            print("33. Netsparker")
            print("34. Hydra")
            print("35. Patator")
            print("36. Medusa")
            print("37. Ncrack")
            print("38. Crowbar")
            print("39. Enum4Linux")
            print("40. SMBmap")
            print("41. SMBclient")
            print("42. LDAPsearch")
            print("43. RPCclient")
            print("44. SNMPwalk")
            print("45. OneSixtyOne")
            print("46. NBTscan")
            print("47. IKE-scan")
            print("48. DNSenum")
            print("49. DNSrecon")
            print("50. DNSwalk")
            print("51. Fierce")
            print("52. TheHarvester")
            print("53. Recon-ng")
            print("54. Metagoofil")
            print("55. Maltego")
            print("0. Back to Main Menu")

            tool_choice = input("\nEnter the number of the tool to run (0 to go back): ").strip()
            if tool_choice == "0":
                continue
            elif tool_choice.isdigit() and 1 <= int(tool_choice) <= 55:
                tool_list = list(tools.keys())
                tool_name = tool_list[int(tool_choice) - 1]
                run_tool(tool_name, target)
            else:
                print("[-] Invalid choice. Please try again.")
        elif choice == "3":
            # AI Tool Recommendations
            scan_output = run_nmap(target)
            recommendations = ai_recommend_tools(scan_output)
            print(f"\nAI Recommendations: {recommendations}\n")
        elif choice == "4":
            # AI Chat
            query = input("Enter your query: ")
            response = ai_chat(query)
            print(f"\nAI Response: {response}\n")
        else:
            print("[-] Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
