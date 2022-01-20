
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
            patch_url_list[title] = url_list

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
                current_dir = os.path.dirname(os.path.abspath(__file__))
                diff_dir = os.path.join(current_dir,'diff')

                if not os.path.exists(diff_dir):
                    os.mkdir(diff_dir)

                file_path = os.path.join(diff_dir,main.diff_local_loader.coverte_url_to_file(url))

                if not os.path.exists(file_path):
                    continue

                print('Search New CVE Patch Record ==>>',cve,url)

                if not result.get(cve):
                    result[cve] = [file_path]
                else:
                    result[cve].append(file_path)

    cve_diff_map = os.path.join('diff','cve_diff_map')

    file = open(cve_diff_map,'w')
    file.write(json.dumps(result,indent=2))
    file.close()

    return result


if __name__ == '__main__':
    cve_list_file = os.listdir('./cve_list')
    all_cve_list = []

    for cve_file in cve_list_file:
        if not cve_file.startswith('allitem'):
            continue

        all_cve_list.append(os.path.join('cve_list',cve_file))

    make_esixt_cve_diff_record(all_cve_list)

