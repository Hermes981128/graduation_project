# -*- coding: utf-8 -*-
# @Time : 2022年04月06日 11时16分
# @Email : yun981128@gmail.com
# @Author : 王从赟
# @Project :论文
# @File : DatabaseClass.py
# @notice :
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, ForeignKey, TIMESTAMP, TEXT
from sqlalchemy.orm import relationship, sessionmaker

Base = declarative_base()


class OriginalData(Base):
    __tablename__ = 'original_data'
    ID = Column(Integer, primary_key=True)
    version = Column(Integer)
    ihl = Column(Integer)
    tos = Column(Integer)
    len = Column(Integer)
    flags = Column(String(255))
    frag = Column(Integer)
    ttl = Column(Integer)
    proto = Column(String(255))
    chksum = Column(Integer)
    src = Column(String(255))
    dst = Column(String(255))
    sport = Column(Integer)
    dport = Column(Integer)
    seq = Column(Integer)
    ack = Column(Integer)
    dataofs = Column(Integer)
    reserved = Column(Integer)
    window = Column(Integer)
    urgptr = Column(Integer)
    RawData = Column(String(255))

    def __repr__(self):
        return "<original_data(ID='%s', version='%s', ihl='%s', tos='%s', len='%s', flags='%s', frag='%s', ttl='%s', proto='%s', chksum='%s', src='%s', dst='%s', sport='%s', dport='%s', seq='%s', ack='%s', dataofs='%s', reserved='%s', window='%s', urgptr='%s', RawData='%s')>" % (
            self.ID, self.version, self.ihl, self.tos, self.len, self.flags, self.frag, self.ttl, self.proto,
            self.chksum,
            self.src, self.dst, self.sport, self.dport, self.seq, self.ack, self.dataofs, self.reserved, self.window,
            self.urgptr, self.RawData)


class SourceData(Base):
    __tablename__ = 'source_data'
    ID = Column(Integer, primary_key=True, Autoincrement=True)
    Time = Column(TIMESTAMP)
    Source = Column(String(255))
    Destination = Column(String(255))
    Protocol = Column(Integer)
    Length = Column(Integer)
    Info = Column(String(255))
    RawData = Column(TEXT)

    def __repr__(self):
        return f"<source_data(ID='%s', Time='%s', Source='%s', Destination='%s', Protocol='%s', Length='%s', Info='%s', RawData='%s')>" % (
        self.ID, self.Time, self.Source, self.Destination, self.Protocol, self.Length, self.Info, self.RawData)


class DataBase:
    def __init__(self):
        conn_str = "mysql+pymysql://{user}:{pwd}@{host}:{port}/{db_name}"
        connect_info = conn_str.format(user='root',
                                       pwd='Wang720521',
                                       host="gz-cynosdbmysql-grp-gg0yl71t.sql.tencentcdb.com",
                                       port=20504,
                                       db_name='graduation_design')

        engine = create_engine(connect_info, max_overflow=5, echo=True)
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine)()
