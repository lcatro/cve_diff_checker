
import json
import os
import re
import sys

from urllib.parse import urlparse
from urllib.parse import urlunparse

from bs4 import BeautifulSoup

import requests


IS_DEBUG_MODE = True


def trace_output(output_format,**kwargs):
    if IS_DEBUG_MODE:
        print(output_format,kwargs)


class diff_mode:

    SNAP_CHECK = 0
    DELTA_CHECK = 1

class diff_status:

    IS_MODIFY_STATUS = 0
    IS_REMOVE_STATUS = 1
    IS_IGNORE_STATUS = 2

class diff_code_part:

    def __init__(self,file_path,code_part,diff_status = diff_status.IS_MODIFY_STATUS):
        self.file_path = file_path
        self.code_part = code_part
        self.diff_status = diff_status

    def get_file_path(self):
        return self.file_path

    def get_code_part(self):
        return self.code_part

    def get_diff_status(self):
        return self.diff_status

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        if self.diff_status == diff_status.IS_MODIFY_STATUS:
            modify_mode = 'IS_MODIFY_STATUS'
        elif self.diff_status == diff_status.IS_REMOVE_STATUS:
            modify_mode = 'IS_REMOVE_STATUS'

        result = '''>>>>>> %s (%s) <<<<<<\n%s\n''' % (self.file_path,modify_mode,self.code_part)
        return result

class diff_delta:

    def __init__(self,file_path,diff_delta = [],diff_status = diff_status.IS_MODIFY_STATUS):
        self.file_path = file_path
        self.diff_status = diff_status
        self.diff_delta = diff_delta

    def get_file_path(self):
        return self.file_path

    def get_diff_status(self):
        return self.diff_status

    def get_diff_delta(self):
        return self.diff_delta

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        if self.diff_status == diff_status.IS_MODIFY_STATUS:
            modify_mode = 'IS_MODIFY_STATUS'
        elif self.diff_status == diff_status.IS_REMOVE_STATUS:
            modify_mode = 'IS_REMOVE_STATUS'
        elif self.diff_status == diff_status.IS_IGNORE_STATUS:
            modify_mode = 'IS_IGNORE_STATUS'

        result = '''>>>>>> %s (%s) <<<<<<\n%s\n''' % (self.file_path,modify_mode,self.diff_delta)
        return result

class diff_code_object:

    def __init__(self,file_path,diff_code_part,diff_code_delta):
        self.file_path = file_path
        self.code_part = diff_code_part
        self.code_delta = diff_code_delta

    def get_file_path(self):
        return self.file_path

    def diff_code_part(self):
        return self.code_part

    def diff_code_delta(self):
        return self.code_delta
        
    def __repr__(self):
        result = '  Code Part:\n%s\n  Code Delta\n%s\n' % (str(self.code_part),str(self.code_delta))

        return result

class diff_code_pair:
    
    def __init__(self,file_path,old_code_object,new_code_object):
        self.old_code_object = old_code_object
        self.new_code_object = new_code_object
        self.file_path = file_path

    def get_file_path(self):
        return self.file_path

    def get_old_code_object(self):
        return self.old_code_object

    def get_new_code_object(self):
        return self.new_code_object

    def __repr__(self):
        result = '%s\n%s' % (str(self.old_code_object),str(self.new_code_object))

        return result

class diff_code_list(list):

    def __repr__(self):
        result = '===== diff_code_list ====='

        for index in self:
            result+= str(index)

        result += '---------------------\n'

        return result

class diff_context:

    def __init__(self,diff_content):
        self.is_parse_success = False
        self.diff_code_list = diff_code_list()
        
        temp_content_block = diff_context.get_content_block(diff_content)

        if len(temp_content_block) < 2:
            return

        temp_file_list = temp_content_block[0].strip().split('\n')
        find_first_empty_line = 0

        while find_first_empty_line < len(temp_file_list) :
            if not temp_file_list[find_first_empty_line].strip():
                break

            find_first_empty_line += 1

        temp_file_list = temp_file_list[:find_first_empty_line - 1]

        for file_index in temp_file_list:
            file_path = file_index.split('|')[0].strip()

        temp_code_block = temp_content_block[1:]

        for code_index in temp_code_block:
            code_index = code_index.strip()
            _,code_pair_list = diff_context.get_code_block(code_index,file_path)

            if code_pair_list:
                self.diff_code_list += code_pair_list

        self.is_parse_success = True

    def get_code_object(self):
        return self.diff_code_list

    @staticmethod
    def get_content_block(diff_content):
        temp_diff_content = diff_content.split('diff --git ')

        return temp_diff_content

    @staticmethod
    def get_code_block(diff_code_content,file_path):
        result = diff_code_list()
        temp_diff_code_content = diff_code_content.split('\n@@ ')
        temp_diff_file_content = temp_diff_code_content[0]

        temp_diff_code_content.pop(0)

        for diff_code_index in temp_diff_code_content:
            new_diff_code_lines,new_diff_mode = diff_context.preprocess_diff_code(diff_code_index,True)
            old_diff_code_lines,old_diff_mode = diff_context.preprocess_diff_code(diff_code_index,False)
            new_detal,new_delta_mode = diff_context.preprocess_detal_code(diff_code_index,True)
            old_detal,old_delta_mode = diff_context.preprocess_detal_code(diff_code_index,False)

            new_code_part = diff_code_part(file_path,new_diff_code_lines,new_diff_mode)
            old_code_part = diff_code_part(file_path,old_diff_code_lines,old_diff_mode)
            new_diff_delta = diff_delta(file_path,new_detal,new_delta_mode)
            old_diff_delta = diff_delta(file_path,old_detal,old_delta_mode)

            result.append(diff_code_pair(file_path,
                diff_code_object(file_path,old_code_part,old_diff_delta),
                diff_code_object(file_path,new_code_part,new_diff_delta)
            ))

        #  a/arch/powerpc/kvm/book3s_rtas.c
        file_path = temp_diff_file_content.split('\n')[0]
        file_path = file_path.split(' ')[0].strip()
        file_path = file_path[file_path.find('/') + 1:].strip()

        return file_path,result

    @staticmethod
    def preprocess_detal_code(diff_code,is_new_diff_code):
        temp_diff_code = diff_code.split('\n')[1:]
        line_index = 0
        diff_mode = diff_status.IS_IGNORE_STATUS
        diff_delta_list = []

        if is_new_diff_code:
            pop_flag = '+'
        else:
            pop_flag = '-'

        while line_index < len(temp_diff_code):
            if temp_diff_code[line_index].startswith(pop_flag):
                diff_mode = diff_status.IS_MODIFY_STATUS

                diff_delta_list.append(temp_diff_code[line_index][1:])
                temp_diff_code.pop(line_index)
            else:
                diff_delta_list.append('@')
                line_index += 1
        
        line_index = 0

        while line_index < len(diff_delta_list):  #  Clean Left @
            if '@' == diff_delta_list[line_index]:
                diff_delta_list.pop(line_index)
            else:
                break

        line_index = len(diff_delta_list) - 1

        while line_index >= 0:  #  Clean Right @
            if '@' == diff_delta_list[line_index]:
                diff_delta_list.pop(line_index)

                line_index -= 1
            else:
                break

        line_index = 0

        while line_index < len(diff_delta_list):  #  Clean Mutil @
            if '@' == diff_delta_list[line_index]:
                if diff_delta_list[line_index + 1] == '@':
                    diff_delta_list.pop(line_index)

                    continue
                    
            line_index += 1

        result = []
        temp_data = ''
        now_mode = 0

        for diff_delta_index in diff_delta_list:
            if '@' == diff_delta_index:
                if now_mode != 1:
                    if temp_data:
                        result.append(temp_data)
                    temp_data = ''
                    now_mode = 1

                temp_data = '@'
            else:
                if now_mode != 2:
                    if temp_data:
                        result.append(temp_data)
                    temp_data = ''
                    now_mode = 2

                temp_data += diff_delta_index + '\n'

        if temp_data:
            temp_data = temp_data[:-1]

            result.append(temp_data)

        return result,diff_mode


    @staticmethod
    def preprocess_diff_code(diff_code,is_new_diff_code):
        temp_diff_code = diff_code.split('\n')[1:]
        line_index = 0
        diff_mode = diff_status.IS_REMOVE_STATUS
        result = ''

        if is_new_diff_code:
            pop_flag = '-'
        else:
            pop_flag = '+'

        while line_index < len(temp_diff_code):
            if temp_diff_code[line_index].startswith(pop_flag):
                temp_diff_code.pop(line_index)

                continue
            
            diff_mode = diff_status.IS_MODIFY_STATUS
            temp_diff_code[line_index] = temp_diff_code[line_index][1:]
            line_index += 1

        for index in temp_diff_code:
            result += '%s\n' % index

        return result,diff_mode

    @staticmethod
    def factory(diff_context_data):
        new_object = diff_context(diff_context_data)

        if new_object.is_parse_success:
            return new_object

        return None

class diff_resolver:

    def __init__(self,diff_string,cve_id = None):
        self.cve_id = cve_id
        self.diff_date = ''
        self.diff_subject_title = ''
        self.diff_update_code = None
        self.is_ready = False

        if self.try_resolve(diff_string):
            self.is_ready = True

    def try_resolve(self,diff_string):
        temp_diff_string = diff_string
        diff_header_data = temp_diff_string.split('\n---\n')[0]
        diff_content_data = temp_diff_string.split('\n---\n')[1]

        re_date = re.search(r'Date: (.*)',diff_header_data,re.M|re.I)

        if re_date:
            self.diff_date = re_date.group(1)
        else:
            trace_output('Lost Diff Date')

            return False

        re_subject_title = re.search(r'Subject: (.*)',diff_header_data,re.M|re.I)

        if re_subject_title:
            self.diff_subject_title = re_subject_title.group(1)
        else:
            trace_output('Lost Diff Subject Data')

            return False

        if diff_content_data:
            if not diff_content_data.rfind('-- \ncgit') == -1:  ###  git.kernel.org
                diff_content_data = diff_content_data[:diff_content_data.rfind('\n-- \ncgit')]
            elif not diff_content_data.rfind('-- \nGitLab') == -1:  ###  gitlab
                diff_content_data = diff_content_data[:diff_content_data.rfind('\n-- \nGitLab')]

        self.diff_update_code = diff_context.factory(diff_content_data)

        if not self.diff_update_code:
            trace_output('Resolve Diff Content Error')

            return False

        return True

    def get_cve_id(self):
        return self.cve_id

    def get_diff_id(self):
        return self.diff_id

    def get_diff_date(self):
        return self.diff_date
        
    def get_diff_subject_title(self):
        return self.diff_subject_title

    def get_diff_update_code(self):
        return self.diff_update_code

class diff_local_loader:

    def __init__(self,url):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        diff_dir = os.path.join(current_dir,'diff')

        if not os.path.exists(diff_dir):
            os.mkdir(diff_dir)

        self.file_path = os.path.join(diff_dir,diff_local_loader.coverte_url_to_file(url))
        self.is_load_success = False
        self.data = ''

        print(self.file_path)
        if os.path.exists(self.file_path):
            self.data = diff_local_loader.read_file(self.file_path)

            if self.data:
                self.is_load_success = True

    def get_diff_data(self):
        return self.data

    @staticmethod
    def read_file(file_path):
        file = open(file_path,encoding='UTF-8',errors='strict')
        data = file.read()

        file.close()

        return data

    @staticmethod
    def coverte_url_to_file(url):
        scheme, netloc, path, params, query, fragment = urlparse(url)
        file_name = (netloc + path + query)
        file_name = file_name.replace('/','_')
        file_name = file_name.replace('\\','_')
        file_name = file_name.replace('=','_')
        file_name += '.diff'

        return file_name

    @staticmethod
    def factory(url):
        new_object = diff_local_loader(url)

        if new_object.is_load_success:
            return new_object

        return None

class diff_local_saver:

    def __init__(self,url,data):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        diff_dir = os.path.join(current_dir,'diff')

        if not os.path.exists(diff_dir):
            os.mkdir(diff_dir)

        self.file_path = os.path.join(diff_dir,diff_local_loader.coverte_url_to_file(url))

        diff_local_saver.write_file(self.file_path,data)

    @staticmethod
    def write_file(file_path,file_data):
        file = open(file_path,'w',encoding='UTF-8',errors='strict')

        file.write(file_data)

        file.close()

class diff_download:

    CODE_REPOSIOTR_GIT_KERNEL_ORG = 'git.kernel.org'
    CODE_REPOSIOTR_GITHUB = 'github.com'
    CODE_REPOSIOTR_GITLAB = 'gitlab'
    CODE_REPOSIOTR_CGIT = 'cgit'

    def __init__(self,url):
        local_loader = diff_local_loader.factory(url)

        if local_loader:
            self.data = local_loader.get_diff_data()
        else:
            url_data = urlparse(url)
            url_host = url_data.netloc

            if not url_host.find(diff_download.CODE_REPOSIOTR_GIT_KERNEL_ORG) == -1:
                self.data = diff_download.load_from_git_kernel_org(url)
            elif not url_host.find(diff_download.CODE_REPOSIOTR_GITHUB) == -1:
                self.data = diff_download.load_from_github(url)
            elif not url_host.find(diff_download.CODE_REPOSIOTR_GITLAB) == -1:
                self.data = diff_download.load_from_github(url)
            elif not url_host.find(diff_download.CODE_REPOSIOTR_CGIT) == -1:
                self.data = diff_download.load_from_git_kernel_org(url)
            else:
                self.data = diff_download.load_from_git_kernel_org(url)

            diff_local_saver(url,self.data)

    def get_diff_data(self):
        return self.data

    @staticmethod
    def load_from_git_kernel_org(url):
        scheme, netloc, path, params, query, fragment = urlparse(url)
        path = path.replace('/commit','/patch')
        real_patch_text_message_url = urlunparse((scheme, netloc, path, params, query, fragment))
        responed = requests.get(real_patch_text_message_url)

        return responed.text

    @staticmethod
    def load_from_github(url):
        scheme, netloc, path, params, query, fragment = urlparse(url)
        path = path + '.patch'
        real_patch_text_message_url = urlunparse((scheme, netloc, path, params, query, fragment))
        responed = requests.get(real_patch_text_message_url)

        return responed.text

class diff_check_status:

    IS_NO_FIX = 0
    IS_ALL_FIX = 1
    IS_SOME_FIX = 2
    IS_CODE_EVOLUTAION = 3
    IS_NO_EXIST = 4

class diff_fix_detail:

    def __init__(self,bingo_code_part,file_path = '<NoPath>'):
        self.file_path = file_path

    def get_file_path(self):
        return self.file_path
        
    def get_code_part(self):
        return self.file_path
        
class diff_check:

    def __init__(self,diff_resolver,local_code_file_base_path):
        self.bug_is_fix = diff_check_status.IS_NO_EXIST
        self.fix_list = []
        self.nofix_list = []
        self.code_evolutaion_list = []

        if not diff_resolver.is_ready:
            trace_output('Diff Resolver is fail')

        update_code_list = diff_resolver.get_diff_update_code().get_code_object()
        old_code_bingo_list = []
        new_code_bingo_list = []
        code_evolutaion_list = []

        for update_code_object in update_code_list:   #   多个Diff点
            check_file_path = update_code_object.get_file_path()
            real_code_file_path = os.path.join(local_code_file_base_path,check_file_path)

            if not os.path.exists(real_code_file_path):   #  Check diff file not exist
                self.bug_is_fix = diff_check_status.IS_NO_EXIST

                return

            real_code = diff_check.load_code_file(real_code_file_path)

            old_code_object = update_code_object.get_old_code_object()
            old_update_code = old_code_object.diff_code_part().get_code_part()
            old_delta_code = old_code_object.diff_code_delta().get_diff_delta()
            old_code_is_esixt = diff_check.try_code_part_check(old_update_code,real_code)
            old_code_delta_check = diff_check.try_delta_check(old_delta_code,real_code)

            new_code_object = update_code_object.get_new_code_object()
            new_update_code = new_code_object.diff_code_part().get_code_part()
            new_delta_code = new_code_object.diff_code_delta().get_diff_delta()
            new_code_is_esixt = diff_check.try_code_part_check(new_update_code,real_code)
            new_code_delta_check = diff_check.try_delta_check(new_delta_code,real_code)

            '''
            if diff_status.IS_REMOVE_STATUS == old_code_object.diff_code_part().get_diff_status():  #  old code remove
                if old_code_is_esixt:  #  在diff中旧代码理应被删除,但是在源码中匹配到,说明旧代码存在
                    old_code_bingo_list.append(old_code_object)
                else:  #  被删除的代码在源码中找不到了,说明旧代码不存在
                    pass
            elif diff_status.IS_MODIFY_STATUS == old_code_object.diff_code_part().get_diff_status():  #  old code modify
                if old_code_is_esixt:
                    old_code_bingo_list.append(old_code_object)
                else:
                    pass
            elif diff_status.IS_REMOVE_STATUS == new_code_object.diff_code_part().get_diff_status():  #  new code remove
                if new_code_is_esixt:
                    new_code_bingo_list.append(new_code_object)
                else:
                    pass
            elif diff_status.IS_MODIFY_STATUS == new_code_object.diff_code_part().get_diff_status():  #  new code remove
                if new_code_is_esixt:
                    new_code_bingo_list.append(new_code_object)
                else:
                    pass
            else:  #  新旧代码都不存在
                code_evolutaion_list.append(update_code_object)
            '''  #   逻辑合并
            if old_code_is_esixt:
                old_code_bingo_list.append(old_code_object)
            elif new_code_is_esixt:
                new_code_bingo_list.append(new_code_object)
            else:
                code_evolutaion_list.append(update_code_object)


            #trace_output(real_code_file_path)
            #trace_output(update_code)
            #trace_output('>>>>>>')
            #trace_output('old_code_is_esixt ' + str(old_code_is_esixt))
            #trace_output('new_code_is_esixt ' + str(new_code_is_esixt))
            #trace_output(new_code_object.diff_code_delta().get_diff_status())
            #exit()
            #trace_output(new_code_is_esixt)
            #trace_output(new_code_object.diff_code_part().get_diff_status())
            #trace_output('>>>>>>')
            #trace_output(old_code_delta_check)
            #trace_output(new_code_delta_check)
            #trace_output(old_code_object.diff_code_delta())
            #trace_output(new_code_object.diff_code_delta())

            '''
            #  New Code Diff Must Esixt
            if diff_status.IS_MODIFY_STATUS == new_code_object.diff_code_part().get_diff_status() and \
                new_code_is_esixt:  #  Fix Code Must Esixt in Code File
                self.fix_list.append(new_code_object.diff_code_part())
            elif diff_status.IS_REMOVE_STATUS == new_code_object.diff_code_part().get_diff_status() and \
                old_code_is_esixt:  #  Old Code Must No-Esixt
                self.fix_list.append(new_code_object.diff_code_part())
            elif diff_status.IS_MODIFY_STATUS == new_code_object.diff_code_delta().get_diff_status() and \
                new_code_delta_check:  #  Fix Code Must Esixt in Code File
                ##  Test Case https://cgit.freedesktop.org/virglrenderer/commit/?id=114688c526fe45f341d75ccd1d85473c3b08f7a7
                self.fix_list.append(new_code_object.diff_code_delta())

            #  Old Code Diff Must No-Esixt
            elif old_code_is_esixt:
                self.nofix_list.append(old_code_object)

            #  Old Code and New Code Diff No-Esixt it ..
            #  Maybe code evolution
            else:
                self.code_evolutaion_list.append(old_code_object)
            '''

        #  基础判断:
        #  旧代码不存在,新代码存在 => 漏洞已经修复
        #  旧代码存在,新代码不存在 => 漏洞未修复
        #  旧代码不存在,新代码不存在 => 漏洞不存在(代码演进)
        #  旧代码存在,新代码存在 => 漏洞不存在(代码演进)
        #  
        #  进一步推论:
        #  旧代码存在,新代码不存在 => 漏洞未修复
        #  旧代码部分存在,新代码不存在 => 漏洞未修复(部分代码被演进了,旧漏洞不一定存在)
        #  旧代码不存在,新代码存在 => 漏洞已经修复
        #  旧代码不存在,新代码部分存在 => 漏洞已经修复(部分代码被演进了)
        #  旧代码部分存在,新代码部分存在 => 漏洞不存在
        #    (因为代码演进,原有的漏洞有概率不存在,如果漏洞还在,很有可能是引入了修复代码,如果还能触发漏洞应该就是新漏洞[Fix Bypass])
        #  旧代码存在,新代码存在 => 漏洞不存在(代码演进)
        #  
        #  全部删除的代码不应该find
        #  

        #trace_output(old_code_bingo_list)
        #trace_output(new_code_bingo_list)

        if old_code_bingo_list and new_code_bingo_list:
            self.bug_is_fix = diff_check_status.IS_CODE_EVOLUTAION
        elif old_code_bingo_list:
            self.bug_is_fix = diff_check_status.IS_NO_FIX
        elif new_code_bingo_list:
            self.bug_is_fix = diff_check_status.IS_ALL_FIX

        '''
        if self.code_evolutaion_list:
            self.bug_is_fix = diff_check_status.IS_CODE_EVOLUTAION
        elif self.fix_list and self.nofix_list:
            self.bug_is_fix = diff_check_status.IS_SOME_FIX
        elif self.fix_list and not self.nofix_list:
            self.bug_is_fix = diff_check_status.IS_ALL_FIX
        '''

    def get_fix_detail(self):
        return self.fix_list

    def get_nofix_detail(self):
        return self.nofix_list

    def is_fix(self):
        return self.bug_is_fix

    @staticmethod
    def load_code_file(code_file_path):
        file = open(code_file_path,encoding='UTF-8',errors='strict')
        data = file.read()

        file.close()

        return data

    @staticmethod
    def try_code_part_check(diff_code_part,code):
        return not code.find(diff_code_part) == -1

    @staticmethod
    def try_delta_check(diff_delta,code):     #     <<<<<<<  No use ....
        temp_code = code
        result = False
        offset = -1
        
        for delta_index in diff_delta:
            if '@' == delta_index:
                continue
            else:
                offset = temp_code.find(delta_index)
                code_len = len(delta_index)

                if offset == -1:
                    return False

                temp_code = temp_code[ offset + code_len : ]

        if offset > -1:
            result = True

        return result


def check_diff_link(url):
    if not url.find('/commit') == -1:
        return True

    return False


class cve_find_from_circl:

    def __init__(self,url):
        responed = requests.get(url)

        self.cve_list = cve_find_from_circl.resolve_cve_search_page(responed.text)
        self.cve_diff_list = cve_find_from_circl.get_cve_detail(self.cve_list)    

    @staticmethod
    def resolve_cve_search_page(page_data):
        soup = BeautifulSoup(page_data)
        table_element = soup.find('tbody')
        tr_list = table_element.findAll('tr')
        result = {}

        for cve_index in tr_list:
            a_element = cve_index.find('a')
            link = 'https://cve.circl.lu/%s' % a_element['href']
            cve_id = a_element.get_text()
            result[cve_id] = link

        return result

    @staticmethod
    def resolve_cve_detail_page(page_data):
        soup = BeautifulSoup(page_data)
        a_element_list = soup.findAll('a',target='_blank')
        link_list = []

        for element_index in a_element_list:
            http_link = element_index.get_text()
            
            if http_link.startswith('http:') or http_link.startswith('https:'):
                link_list.append(http_link)

        return link_list

    @staticmethod
    def get_cve_detail(cve_list):
        result = {}

        for cve_index,cve_detail_link in cve_list.items():
            responed = requests.get(cve_detail_link)
            reference_links = cve_find_from_circl.resolve_cve_detail_page(responed.text)

            if reference_links:
                for link_index in reference_links:
                    if check_diff_link(link_index):
                        result[cve_index] = link_index

                        break
            else:
                trace_output('CVE Link %s Lost Reference URL' % cve_detail_link)

        return result

    def get_cve_diff_list(self):
        return self.cve_diff_list


class cve_checker:

    def __init__(self,check_code_dir_path,cve_diff_record_data = {}):
        self.code_dir = check_code_dir_path
        self.cve_data = cve_diff_record_data
        self.running_state = False
        self.check_result = []

    def start_check(self,thread_number = 0,is_syn = True):
        self.running_state = True
        
        fix_result = []
        no_fix_result = []
        some_fix_result = []
        code_evolutation_result = []

        for cve_id,diff_link_list in self.cve_data.items():
            for diff_link in diff_link_list:  #   一个CVE多个diff部分修复的检测逻辑以后再弄吧
                #print(diff_link)
                diff_data = diff_local_loader.read_file(diff_link)
                try:
                    diff_tester = diff_resolver(diff_data)
                    cve_chcker = diff_check(diff_tester,self.code_dir)

                    if cve_chcker.is_fix() == diff_check_status.IS_NO_FIX:
                        if not cve_id in no_fix_result:
                            no_fix_result.append(cve_id)
                    elif cve_chcker.is_fix() == diff_check_status.IS_ALL_FIX:
                        if not cve_id in fix_result:
                            fix_result.append(cve_id)
                    #elif cve_chcker.is_fix() == diff_check_status.IS_SOME_FIX:
                    #    if not cve_id in some_fix_result:
                    #        some_fix_result.append(cve_id)
                    elif cve_chcker.is_fix() == diff_check_status.IS_CODE_EVOLUTAION:
                        if not cve_id in code_evolutation_result:
                            code_evolutation_result.append(cve_id)
                    else:  #  diff_check_status.IS_NO_EXIST
                        #print(cve_chcker.is_fix())
                        pass
                except:
                    pass

        self.running_state = False

        return (fix_result,no_fix_result,code_evolutation_result)

    def get_result(self):
        return self.check_result

    def is_running(self):
        return self.running_state

    @staticmethod
    def __check_thread(input_queue,output_queue):
        pass

    @staticmethod
    def load_cve_diff_record():
        current_dir = os.path.dirname(os.path.abspath(__file__))
        diff_dir = os.path.join(current_dir,'diff')
        cve_diff_record_file_path = os.path.join(diff_dir,'cve_diff_map.txt')
        file = open(cve_diff_record_file_path,'r')
        record_data = file.read()
        record_data = json.loads(record_data)

        file.close()

        return record_data

    @staticmethod
    def factory(check_code_dir_path,cve_list = []):
        if not os.path.exists(check_code_dir_path):
            return None

        current_dir = os.path.dirname(os.path.abspath(__file__))
        diff_dir = os.path.join(current_dir,'diff')

        if not os.path.exists(diff_dir):
            #  try {} raise {}   add raise except later
            return None

        we_want_check_diff_list = {}
        cve_diff_record_data = cve_checker.load_cve_diff_record()

        if cve_list:  #  it could check the diff you want
            for cve_index in cve_list:
                if not cve_diff_record_data.get(cve_index,None):
                    continue

                we_want_check_diff_list[cve_index] = cve_diff_record_data[cve_index]

            if not we_want_check_diff_list:
                #  try {} raise {}   add raise except later
                return None
        else:
            we_want_check_diff_list = cve_diff_record_data

        return cve_checker(check_code_dir_path,we_want_check_diff_list)


if __name__ == '__main__':
    if not 2 == len(sys.argv):
        print('Using:')
        print('  python cve_diff_check.py check_code_dir_path')

    code_checker = cve_checker.factory(sys.argv[1]) ##,['CVE-2018-20784']) #,['CVE-2015-0275']) #,['CVE-2016-5195','CVE-2021-42836'])

    if not code_checker:
        print('Load Code Dir Error')
        print('  Dir Path:',sys.argv[1])
        exit()

    fix_result,no_fix_result,_ = code_checker.start_check()

    print('fix_result')
    print(fix_result)
    print('no_fix_result')
    print(no_fix_result)
