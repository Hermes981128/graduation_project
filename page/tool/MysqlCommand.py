# -*- encoding: utf-8 -*-
"""
@File    : MysqlCommand.py
@Time    : 2020/12/9 下午9:15
@Author  : hermes
@Email   : yun981128@gmail.com
@Software: PyCharm
"""
import pymysql


class MysqlCommand():
    def __init__(self):
        self.host = "gz-cynosdbmysql-grp-gg0yl71t.sql.tencentcdb.com"
        self.user = "root"
        self.password = "Wang720521"
        self.database = "graduation_design"
        self.port = 20504

    def connect(self):
        db = pymysql.connect(host=self.host, user=self.user, password=self.password, database=self.database,
                             port=self.port)
        return db

    def execute_without_return(self, command):
        db = self.connect()
        cursor = db.cursor()
        try:
            cursor.execute(command)
            db.commit()
            return True
        except:
            db.rollback()
        finally:
            cursor.close()
            db.close()

    def execute_with_return(self, command):
        db = self.connect()
        cursor = db.cursor()
        try:
            cursor.execute(command)
            db.commit()
            return cursor.fetchall()
        except:
            db.rollback()
            return False
        finally:
            cursor.close()
            db.close()

    def creat_datatable(self):
        pass


class MysqlCommandKeepAlive():
    def __init__(self):
        self.host = "gz-cynosdbmysql-grp-gg0yl71t.sql.tencentcdb.com"
        self.user = "root"
        self.password = "Wang720521"
        self.database = "graduation_design"
        self.port = 20504
        self.db = pymysql.connect(host=self.host, user=self.user, password=self.password, database=self.database,
                                  port=self.port)

    def execute_without_return(self, command):
        cursor = self.db.cursor()
        try:
            cursor.execute(command)
            self.db.commit()
            return True
        except:
            self.db.rollback()
        finally:
            cursor.close()

    def execute_with_return(self, command):
        cursor = self.db.cursor()
        try:
            cursor.execute(command)
            self.db.commit()
            return cursor.fetchall()
        except:
            self.db.rollback()
            return False
        finally:
            cursor.close()

    def close_connect(self):
        self.db.close()

    def creat_datatable(self):
        pass


if __name__ == '__main__':
    pass
