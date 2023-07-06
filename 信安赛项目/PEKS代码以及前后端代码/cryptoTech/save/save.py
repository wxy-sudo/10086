import subprocess

def save(filename, keyword):
    cmd="/home/karloz/Desktop/cryptoTech/save/bin/save %s %s" % (filename, keyword)
    ret = subprocess.run(cmd, shell=True, capture_output=True, encoding='utf-8')
    #print(ret.stdout)
    #print(ret.returncode)

if __name__ == '__main__':
    for i in range(10):
        keyword='key'+str(i)
        for j in range(100):
            filename=keyword+"_%d" % j
            save(filename, keyword)