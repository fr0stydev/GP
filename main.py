import requests
import argparse
import sys
from subprocess import check_output
import re
from bs4 import BeautifulSoup, SoupStrainer
from tqdm import tqdm
from termcolor import colored, cprint
import tabulate


# Returns Dictionary with Key being name of service and value being version number
def get_version(url: str) -> dict:
    wappylyzer_url = "http://localhost:3000/extract?url="
    lookup_url = wappylyzer_url + url
    assets = {}
    r = requests.get(lookup_url)
    data = r.json()
    for vuln in tqdm(data['technologies'], desc="Revealing the technology stack..."):
        if vuln['name'] not in assets:
            if vuln['version'] == None:
                continue
            elif len(vuln['version']) != 0:
                assets[vuln['name']] = vuln['version']
            else:
                assets[vuln['name']] = None

    for key, value in assets.items():
        cprint("Detected {} {} \n".format(key, value), 'green')
    return assets
    

#Executes Searchsploit and returns the output of command as a string
def searchsploit(assets: dict) -> dict:
    output = []
    if len(assets) == 0:
        return  []
    for key, value in assets.items():
        if value == None:
            continue
        else:
            out = check_output(["searchsploit", "-w", "--colour", key, value]).decode("utf-8")
            cprint("Checking results for {} {}".format(key, value), 'red')
            #split output ['Exploit: ------------', 'URL: -------------------', '']
            print(out)
             
            def CVE_search():

                regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"

                url = re.findall(regex,out)
                
                if len(url) == 0:
                    print('No exploits found for {} {}\n'.format(key, value))

                
                url_list = [x[0] for x in url]
                headers = {'User-Agent': 'Mozilla/5.0'}
                for i in url_list:
                    not_accurate = False
                    exploit_database = {}
                    cve_id = []
                    cve_url = []
                    cvss = []
                    banned_words = ['component', 'theme', 'plugin', 'extension', 'tomcat', 'struts', 'mod_ssl', 'couchedb']
                    page = requests.get(i, headers=headers)
                    soup = BeautifulSoup(page.text, 'html.parser')
                    soup.prettify()
                    title = soup.find('title').string
                    split_title = title.split()
                    #Skip CVE-Search for non exact match example: SilverStripe != Stripe so it skips it
                    if key not in split_title:
                        continue

                    #If current third party wapp name neighboring word is in banned_words. Skip it
                    #For example Wordpress Plugin does not equal Wordpress so skip it
                    for y in range(len(split_title)):
                        if split_title[y] == key:
                            if split_title[y + 1].lower() in banned_words:
                                not_accurate = True
                                break 

                    if not_accurate:
                        continue

                    #Finds all link with domain nvd.nist.gov and makes it into a list
                    all_links = soup.find_all('a', href = re.compile(r'https://nvd.nist.gov/vuln/detail.*'))
                    for elem in all_links:
                        ID = ""
                        link = elem['href']
                        cve_url.append(link)
                        ID += link.rsplit('/', 1)[-1]
                        cve_id.append(ID) 

                    #For each exploit, assign CVE-ID, CVE-URL, Title
                    #However if there is no CVE-ID, skip it and don't add it to the results
                    if len(cve_id) == 0:
                        cprint("No details found for {}".format(i), 'white', 'on_red')
                        continue
                    
                    cve_api = "https://cve.circl.lu/api/cve/"

                    r = requests.get(cve_api + cve_id[0])
                    cve_data = r.json()
                    cvss = cve_data['cvss']
                    summary = cve_data['summary']

                    exploit_database['Summary'] = summary
                    exploit_database["CVSS-SCORE"] = cvss
                    exploit_database["CVE-ID"] = cve_id
                    exploit_database["CVE-URLs"] = cve_url
                    exploit_database["Title"] = title
                    exploit_database["Exploit-URL"] = i

                    
                    
                    output.append(exploit_database)
        

            CVE_search()
    return output    

                
#Takes the output of SearchSploit and looks for the CVE-ID of the exploit if it exists
#Output should be [{"CVE-ID": "CVE-1024", "Name": "Exploit Title", "URL":, "https://exploit-db/24324", "CVE-SCore": 7.8}]

#Takes the data generated in CVE_Search() and ranks the exploit by CVSS
#Filters the data and removes any inaccuracy EX: Wordpress does not equal Wordpress Plugin
def filter(database: dict) -> dict:
    data = []

    #Removes items that have CVSS-Score rated as below medium
   
    for item in database:
        if item['CVSS-SCORE'] < 3.9:
            continue
        else:
            data.append(item)

    #Sorts CVSS-SCORE from greatest to least
    return sorted(data, key = lambda i: i['CVSS-SCORE'], reverse=True)

def print_to_table(data: list):
    header = data[0].keys()
    rows = [x.values() for x in data]
    return tabulate.tabulate(rows, header)

def to_file(data: str):
    text_file = open("output.txt" , "w")
    text_file.write(data)
    text_file.close()
    cprint('Created a report in the current directory named output.txt', 'green')

def main(url: str):
    components = get_version(url)
    exploits = searchsploit(components)
    if len(exploits) == 0:
        cprint("Cannot find any existing exploits on the site's technology stack!", 'green')
        return
    else:
        sort_exploits = filter(exploits)
        table = print_to_table(sort_exploits)
        to_file(table)


if __name__ == "__main__":
    print("""
 __          __                   _____         _         _  _   
 \ \        / /                  / ____|       | |       (_)| |  
  \ \  /\  / /__ _  _ __   _ __ | (___   _ __  | |  ___   _ | |_ 
   \ \/  \/ // _` || '_ \ | '_ \ \___ \ | '_ \ | | / _ \ | || __|
    \  /\  /| (_| || |_) || |_) |____) || |_) || || (_) || || |_ 
     \/  \/  \__,_|| .__/ | .__/|_____/ | .__/ |_| \___/ |_| \__|
                   | |    | |           | |                      
                   |_|    |_|           |_|                      """)
    parser = argparse.ArgumentParser(description="Scans URL for components with exploits in Exploit-DB")
    parser.add_argument("url", help="URL to scan")
    args = parser.parse_args()
    url = args.url
    main(url)
