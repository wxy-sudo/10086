import subprocess
import time

def search(keyword):
    cmd="/home/karloz/Desktop/cryptoTech/search/bin/search "+keyword
    ret = subprocess.run(cmd, shell=True, capture_output=True, encoding='utf-8') #调用子进程执行搜索程序
    code = ret.returncode
    if code == 0:
        res = sorted(ret.stdout.split('\n'),key=lambda x:(len(x),x))
        print('\n'.join(res[1:]))
    else :
        print('error! not found.')

if __name__ == '__main__':
    keyword='key1'
    start=time.time()
    search(keyword)
    end=time.time()
    print('time:%.3fs\n' % (end-start))
    # keyword='key2'
    # search(keyword)
    # keyword='key3'
    # search(keyword)