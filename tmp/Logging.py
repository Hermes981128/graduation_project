# -*- encoding: utf-8 -*-
"""
@File    : Logging.py
@Time    : 2020/11/16 下午4:42
@Author  : hermes
@Email   : yun981128@gmail.com
@Software: PyCharm
"""
import logging,os,time
def log(name=''):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)  # Log等级总开关
    rq = time.strftime('%Y%m%d', time.localtime(time.time()))
    logfile = 'log/' + rq + ".log"
    current_path=os.getcwd()
    path=current_path+"/log"
    print("log文件夹路径为：",path)
    if not os.path.exists(path):
        print("创建log文件夹")
        os.makedirs(path)
    else:
        print("log文件夹已存在")
    fh = logging.FileHandler(logfile, mode='a+',encoding='utf-8')
    fh.setLevel(logging.DEBUG)  # 输出到file的log等级的开关
    formatter = logging.Formatter("%(levelname)s : %(asctime)s - %(filename)s[line:%(lineno)d]: %(message)s")
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger