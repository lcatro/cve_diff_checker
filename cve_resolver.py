
import json
import os

from bs4 import BeautifulSoup

import main


def load_diff_from_cve_file(cve_file_path):
    file = open(cve_file_path,encoding='utf-8',errors='ignore')
    html = file.read()

    file.close()

    soup = BeautifulSoup(html, 'lxml')
    vuln = soup.find_all('vulnerability')

    print('Vuln Record:',len(vuln))

    patch_url_list = {}


    for vuln_index in vuln:
        title = vuln_index.find('title').text
        description = vuln_index.find('notes').find('note').text
        reference = vuln_index.find('references')
        all_url = reference.find_all('url')
        url_list = []

        for url in all_url:
            if main.check_diff_link(url.text):
                url_list.append(url.text)

        if url_list:
            patch_url_list[title] = url_list # (description,url_list)

        #print(title)
        #print(url_list)
        #exit()

    #print(json.dumps(patch_url_list,indent=2))

    return patch_url_list

def try_download(cve_file_path = '.\\cve_list\\allitems-cvrf-year-2015.xml'):
    patch_url_list = load_diff_from_cve_file(cve_file_path)
    error_list = []

    for cve,url_list in patch_url_list.items():
        for url in url_list:
            try:
                print('Download',cve,url)
                main.diff_download(url)
            except:
                print('ohfuck')
                error_list.append(url)

    if error_list:
        print('Error:')
        print(json.dumps(error_list,indent=2))

def make_esixt_cve_diff_record(all_cve_list):
    result = {}

    for cve_file in all_cve_list:
        patch_url_list = load_diff_from_cve_file(cve_file)
        
        for cve,url_list in patch_url_list.items():
            for url in url_list:
                print(cve,url)
                current_dir = os.path.dirname(os.path.abspath(__file__))
                diff_dir = os.path.join(current_dir,'diff')

                if not os.path.exists(diff_dir):
                    os.mkdir(diff_dir)

                file_path = os.path.join(diff_dir,main.diff_local_loader.coverte_url_to_file(url))

                if not os.path.exists(file_path):
                    continue

                if not result.get(cve):
                    result[cve] = [file_path]
                else:
                    result[cve].append(file_path)

    file = open('.\\diff\\cve_diff_map.txt','w')
    file.write(json.dumps(result,indent=2))
    file.close()

    return result

all_cve_list = [
    '.\\cve_list\\allitems-cvrf-year-2015.xml' ,
    '.\\cve_list\\allitems-cvrf-year-2016.xml' ,
    '.\\cve_list\\allitems-cvrf-year-2018.xml' ,
    '.\\cve_list\\allitems-cvrf-year-2019.xml' ,
    '.\\cve_list\\allitems-cvrf-year-2020.xml' ,
    '.\\cve_list\\allitems-cvrf-year-2021.xml' 
]

#for cve_index in all_cve_list:
#    try_download(cve_index)

make_esixt_cve_diff_record(all_cve_list)

