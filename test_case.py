
import main

def test_case_1():
    test_url = 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f62f3c20647ebd5fb6ecb8f0b477b9281c44c10a'
    diff_data = main.diff_download(test_url).get_diff_data()
    diff_tester = main.diff_resolver(diff_data)

    print(diff_tester.get_diff_subject_title())
    print(diff_tester.get_diff_update_code().get_code_object())

    test_url = 'https://github.com/freedesktop/virglrenderer/commit/029303e9fde8af7fa28c747c0e801adf46320add'
    diff_data = diff_download(test_url).get_diff_data()
    diff_tester = diff_resolver(diff_data)

    print(diff_tester.get_diff_subject_title())
    print(diff_tester.get_diff_update_code().get_code_object())
    
def test_case_2():
    diff_data = '''From 029303e9fde8af7fa28c747c0e801adf46320add Mon Sep 17 00:00:00 2001
From: Chia-I Wu <olvaffe@gmail.com>
Date: Wed, 21 Jul 2021 10:03:30 -0700
Subject: [PATCH] vrend: check for NULL in vrend_renderer_get_meminfo

Discovered by the fuzzer.

Signed-off-by: Chia-I Wu <olvaffe@gmail.com>
Reviewed-by: Ryan Neph <ryanneph@google.com>
---
 src/vrend_renderer.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/src/vrend_renderer.c b/src/vrend_renderer.c
index ccd7cb2..29958b3 100644
--- a/src/vrend_renderer.c
+++ b/src/vrend_renderer.c
@@ -11342,6 +11342,10 @@ void vrend_renderer_get_meminfo(struct vrend_context *ctx, uint32_t res_handle)
    struct virgl_memory_info *info;
 
    res = vrend_renderer_ctx_res_lookup(ctx, res_handle);
+   if (!res) {
+      vrend_report_context_error(ctx, VIRGL_ERROR_CTX_ILLEGAL_RESOURCE, res_handle);
+      return;
+   }
 
    info = (struct virgl_memory_info *)res->iov->iov_base;
 '''
    diff_tester = main.diff_resolver(diff_data)
    cve_123123 = main.diff_check(diff_tester,'.\\test_code\\virglrenderer-virglrenderer-0.9.1')

    print('BugVersion check status => %d' % cve_123123.is_fix())
    
    cve_123123 = main.diff_check(diff_tester,'.\\test_code\\virglrenderer-master')

    print('NoBugVersion check status => %d' % cve_123123.is_fix())

def test_case_3():
    cve_finder = main.cve_find_from_circl('https://cve.circl.lu/search/virglrenderer_project/virglrenderer')

    print(cve_finder.get_cve_diff_list())
    
def test_case_4(path = '.\\test_code\\virglrenderer-master'):
    cve_data = {'CVE-2017-5957': 'https://cgit.freedesktop.org/virglrenderer/commit/?id=926b9b3460a48f6454d8bbe9e44313d86a65447f', 'CVE-2016-10163': 'https://cgit.freedesktop.org/virglrenderer/commit/?id=747a293ff6055203e529f083896b823e22523fe7', 'CVE-2016-10214': 'https://cgit.freedesktop.org/virglrenderer/commit/?id=40b0e7813325b08077b6f541b3989edb2d86d837', 'CVE-2017-6210': 'https://cgit.freedesktop.org/virglrenderer/commit/?id=0a5dff15912207b83018485f83e067474e818bab', 'CVE-2017-5937': 'https://cgit.freedesktop.org/virglrenderer/commit/?id=48f67f60967f963b698ec8df57ec6912a43d6282', 'CVE-2017-5994': 'https://cgit.freedesktop.org/virglrenderer/commit/?id=114688c526fe45f341d75ccd1d85473c3b08f7a7', 'CVE-2017-6386': 'https://cgit.freedesktop.org/virglrenderer/commit/?id=737c3350850ca4dbc5633b3bdb4118176ce59920', 'CVE-2017-6317': 'https://cgit.freedesktop.org/virglrenderer/commit/?id=a2f12a1b0f95b13b6f8dc3d05d7b74b4386394e4', 'CVE-2019-18391': 'https://gitlab.freedesktop.org/virgl/virglrenderer/commit/2abeb1802e3c005b17a7123e382171b3fb665971', 'CVE-2017-6209': 'https://cgit.freedesktop.org/virglrenderer/commit/?id=e534b51ca3c3cd25f3990589932a9ed711c59b27', 'CVE-2019-18389': 'https://gitlab.freedesktop.org/virgl/virglrenderer/commit/cbc8d8b75be360236cada63784046688aeb6d921', 'CVE-2019-18388': 'https://gitlab.freedesktop.org/virgl/virglrenderer/commit/0d9a2c88dc3a70023541b3260b9f00c982abda16', 'CVE-2017-5993': 'https://cgit.freedesktop.org/virglrenderer/commit/?id=6eb13f7a2dcf391ec9e19b4c2a79e68305f63c22', 'CVE-2017-5580': 'https://cgit.freedesktop.org/virglrenderer/commit/src/gallium/auxiliary/tgsi/tgsi_text.c?id=28894a30a17a84529be102b21118e55d6c9f23fa', 'CVE-2017-5956': 'https://cgit.freedesktop.org/virglrenderer/commit/?id=a5ac49940c40ae415eac0cf912eac7070b4ba95d', 'CVE-2019-18390': 'https://gitlab.freedesktop.org/virgl/virglrenderer/commit/24f67de7a9088a873844a39be03cee6882260ac9', 'CVE-2020-8003': 'https://gitlab.freedesktop.org/virgl/virglrenderer/commit/f9b079ccc319c98499111f66bd654fc9b56cf15f?merge_request_iid=340'}
    #cve_data = {
    #    'CVE-2017-5580': 'https://cgit.freedesktop.org/virglrenderer/commit/src/gallium/auxiliary/tgsi/tgsi_text.c?id=28894a30a17a84529be102b21118e55d6c9f23fa',
    #    'CVE-2017-5994': 'https://cgit.freedesktop.org/virglrenderer/commit/?id=114688c526fe45f341d75ccd1d85473c3b08f7a7',
    #    'CVE-2019-18389': 'https://gitlab.freedesktop.org/virgl/virglrenderer/commit/cbc8d8b75be360236cada63784046688aeb6d921'
    #}
    fix_result = []
    no_fix_result = []
    some_fix_result = []
    code_evolutation_result = []

    for cve_id,diff_link in cve_data.items():
        diff_data = main.diff_download(diff_link).get_diff_data()
        diff_tester = main.diff_resolver(diff_data)
        cve_chcker = main.diff_check(diff_tester,path)

        #print(cve_id,diff_tester.get_diff_subject_title())
        #print(diff_tester.get_diff_update_code().get_code_object())
        #print(cve_id,cve_chcker.is_fix())
        #print('>>>>>>>>>>>>>>>>>>>>>')

        if cve_chcker.is_fix() == main.diff_check_status.IS_NO_FIX:
            no_fix_result.append(cve_id)
        elif cve_chcker.is_fix() == main.diff_check_status.IS_ALL_FIX:
            fix_result.append(cve_id)
        elif cve_chcker.is_fix() == main.diff_check_status.IS_SOME_FIX:
            some_fix_result.append(cve_id)
        elif cve_chcker.is_fix() == main.diff_check_status.IS_CODE_EVOLUTAION:
            code_evolutation_result.append(cve_id)

    print('Analyis Result ====>>')
    print('  fix_result')
    print(fix_result)
    print('  no_fix_result')
    print(no_fix_result)
    print('  some_fix_result')
    print(some_fix_result)
    print('  code_evolutation_result')
    print(code_evolutation_result)

def test_case_5():
    main.trace_output('0.7.0')
    test_case_4('.\\test_code\\virglrenderer-virglrenderer-0.7.0')
    main.trace_output('0.9.1')
    test_case_4('.\\test_code\\virglrenderer-virglrenderer-0.9.1')
    main.trace_output('master')
    test_case_4('.\\test_code\\virglrenderer-master')





if __name__ == '__main__':
    test_case_1()
    test_case_2()
    test_case_3()
    test_case_4()
    test_case_5()
