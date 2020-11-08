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
    wappalyzer_url = "http://localhost:3000/extract?url="
    lookup_url = wappalyzer_url + url
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

#Only Checks for CMS but even if no version is detected it will save to dictionary
#Ex: assets = {'Grav': None, 'WordPress': 5.0.0}

def cms_checker(url: str) -> dict:
    wappalyzer_url = "http://localhost:3000/extract?url="
    lookup_url = wappalyzer_url + url
    assets = {}
    r = requests.get(lookup_url)
    data = r.json()
    for vuln in tqdm(data['technologies'], desc="Revealing the technology stack..."):
        if vuln['categories'][0]['name'] == 'CMS':
            if vuln['name'] not in assets:
                if vuln['version'] == None:
                    assets[vuln['name']] = 'CMS'
                else:
                    assets[vuln['name']] = vuln['version']
    for key, value in assets.items():
        if key == None:
            cprint("Detected {} but couldn't detect version".format(key), 'green')
        else:
            cprint("Detected {} {} \n".format(key, value), 'green')
    return assets
        

#Executes Searchsploit and returns the output of command as a string
def searchsploit(assets: dict) -> list:
    output = []
    if len(assets) == 0:
        return  []
    for key, value in assets.items():
        #If CMS does not include a version
        if value == 'CMS':
            cms_out = check_output(["searchsploit", "-w", "--colour", key]).decode("utf-8")
            cprint("Checking results for {} {}".format(key, value), 'red')
            print(cms_out)
            exploits = CVE_search(out, key, value)
            #Loop through output from CVE_search [{'Summary': 'etc', 'CVSS-ID': 3.5}, {'Summary': 'etc1', 'CVSS-ID': 3.8}]
            for i in exploits:
                output.append(i) #output = [{'Summary': 'etc', 'CVSS-ID': 3.5}, {'Summary': 'etc1', 'CVSS-ID': 3.8}]
        #CMS with versions comes here with other services
        else:
            out = check_output(["searchsploit", "-w", "--colour", key, value]).decode("utf-8")
            cprint("Checking results for {} {}".format(key, value), 'red')
            #split output ['Exploit: ------------', 'URL: -------------------', '']
            print(out)
            exploits = CVE_search(out, key, value)
            for i in exploits:
                output.append(i)
    return output

#out = output from searchsploit, key = Name, value = Version
def CVE_search(out: str, key: str, value: str):
    output = []
    exploit_database = {}
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"

    url = re.findall(regex,out)

    if len(url) == 0:
        if value == 'CMS':
            cprint('No exploits found for {}'.format(key), 'green')
        else:
            cprint('No exploits found for {} {}\n'.format(key, value), 'green')


    url_list = [x[0] for x in url]
    headers = {'User-Agent': 'Mozilla/5.0'}
    for i in url_list:
        not_accurate = False
        cve_id = []
        cve_url = []
        cvss = []
        banned_words = ['component', 'theme', 'plugin', 'extension', 'tomcat', 'struts', 'mod_ssl', 'couchedb', 'module']
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
        
    #output sample [{'Summary': 'etc', 'CVSS-ID': 3.5}, {'Summary': 'etc1', 'CVSS-ID': 3.8}]
    return output      
#Takes the output of SearchSploit and looks for the CVE-ID of the exploit if it exists
#Output should be [{"CVE-ID": "CVE-1024", "Name": "Exploit Title", "URL":, "https://exploit-db/24324", "CVE-SCore": 7.8}]

#Takes the data generated in CVE_Search() and ranks the exploit by CVSS
#Filters the data and removes any inaccuracy EX: Wordpress does not equal Wordpress Plugin
def filter(database: list, remove=True) -> list:
    data = []

    #Removes items that have CVSS-Score rated as below medium
    if remove == True:
        for item in database:
            if len(item) == 0:
                continue
            elif item['CVSS-SCORE'] < 3.9:
                continue
            else:
                data.append(item)

    #Sorts CVSS-SCORE from greatest to least
    return sorted(data, key = lambda i: i['CVSS-SCORE'], reverse=True)

#Creates a table using the data generated by previous functions
def print_to_table(data: list):
    header = data[0].keys()
    rows = [x.values() for x in data]
    return tabulate.tabulate(rows, header)

#Writes to a file
def to_file(data: str, url=None):
    text_file = open("output.txt" , "w")
    if url == None:
        text_file.write(data)
        text_file.close()
    else:
        text_file.write("Report for {} \n {} \n".format(url, data))
        text_file.close()
    cprint('Created a report in the current directory named output.txt', 'green')




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
    parser = argparse.ArgumentParser(description="Scans URL for components with exploits in Exploit-DB if version is detected")
    parser.add_argument("-url", help="URL to scan")
    parser.add_argument("-cms", help="Scans only for CMS with no version check", action='store_true')
    parser.add_argument("-f", help="Removes filtering of exploits with a CVSS lower than 3.9")
    parser.add_argument("-iL", type=open, help="Multiple scans on different URLs defined in a file separated by spaces")
    args = parser.parse_args()
    if args.iL:
        url_list = [x for x in args.iL.readlines()]
        if args.cms:
            for i in url_list:
                components = cms_checker(i)
                exploits = searchsploit(components)
                if len(exploits) == 0:
                    cprint("Cannot find any existing exploits on the URL {}".format(i), 'green')
                else:
                    if args.f:
                        sort_exploits = filter(exploits, False)
                        table = print_to_table(sort_exploits)
                        to_file(table, i)
                    else:
                        sort_exploits = filter(exploits)
                        table = print_to_table(sort_exploits)
                        to_file(table, i)
                
        else:
            for i in url_list:
                components = get_version(i)
                exploits = searchsploit(components)
                if len(exploits) == 0:
                    cprint("Cannot find any existing exploits on the URL {}".format(i), 'green')
                else:
                    if args.f:
                        sort_exploits = filter(exploits, False)
                        table = print_to_table(sort_exploits)
                        to_file(table, i)
                    else:
                        sort_exploits = filter(exploits)
                        table = print_to_table(sort_exploits)
                        to_file(table, i)
        
    else:
        url = args.url
        if args.cms:
            components = cms_checker(url)
        else:
            components = get_version(url)
        exploits = searchsploit(components)
        if len(exploits) == 0:
            cprint("Cannot find any existing exploits on the site's technology stack!", 'green')
        else:
            if args.f:
                sort_exploits = filter(exploits, False)
                table = print_to_table(sort_exploits)
                to_file(table)
            else:
                sort_exploits = filter(exploits)
                table = print_to_table(sort_exploits)
                to_file(table)