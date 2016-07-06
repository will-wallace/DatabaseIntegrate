__author__ = 'williamwallace'

import sqlite3
import hashlib
import binascii
from subprocess import PIPE, Popen
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
import os
import urllib.parse


url_list = ['https://mypay.dfas.mil/', 'https://www.us.army.mil/', 'https://iperms.hrc.army.mil/',
            'https://myaccess.dmdc.osd.mil/', 'https://www.my.af.mil/', 'https://jkodirect.jten.mil/'
            'https://fsaid.ed.gov/', 'https://fafsa.ed.gov/', 'https://www.healthcare.gov/',
            'https://studentloans.gov/', 'https://www.usajobs.gov/', 'https://www.sam.gov/', 'https://www.fbo.gov/',
            'https://www.medicare.gov/', 'https://ceac.state.gov/genniv/', 'https://petitions.whitehouse.gov/',
            'https://www.data.gov/', 'https://www.cia.gov/', 'https://www.usps.gov/', 'https://www.congress.gov/',
            'https://www.ebenefits.va.gov/']

def get_certs(url):
    cmd = 'openssl s_client -verify 0 -showcerts -connect ' + url + ":443"
    p = Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=PIPE, shell=True)
    #time.sleep(5)
    out, err = p.communicate(bytes('GET / HTTP/1.0\r\n\r\n', "UTF-8"))

    out = out.decode()
    print(out)
    buf = StringIO(out)

    line2 = buf.readline()
    incert = 0
    cert = ""
    certs = []
    while line2 != '':
        if "BEGIN CERTIFICATE" in line2:
            incert = 1
        if incert == 1:
            cert += line2 + '\n';

        if "END CERTIFICATE" in line2:
            incert = 0
            certs.append(cert)
            cert = ""
        line2 = buf.readline().strip('\n\r')
    return certs


def get_subject(url):
    cmd = 'openssl s_client -verify 0 -showcerts -connect ' + url + ":443"
    p = Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=PIPE, shell=True)
    #time.sleep(5)
    out, err = p.communicate(bytes('GET / HTTP/1.0\r\n\r\n', "UTF-8"))

    out = out.decode()
    print(out)
    buf = StringIO(out)

    line2 = buf.readline()
    untrimmed = ""
    subject = ""
    while line2 != '':
        if "subject=" in line2:
            untrimmed += line2
            subject = untrimmed[7:]
        line2 = buf.readline().strip('\n\r')
    return subject


def insert_cert(conn, cert_text, url):
    cursor=conn.cursor()
    cert_text = cert_text.encode('utf-8')
    cert_hash = hashlib.sha1()
    cert_hash.update(cert_text)
    cert_digested = cert_hash.digest()
    l = len(cert_digested)
    cert_asciihash = binascii.b2a_hex(cert_digested)
    cert_subject = get_subject(url)
    sql = '''INSERT INTO certs
    (cert, cert_hash, cert_subject)
    VALUES(?, ?, ?);'''
    cursor.execute(sql,[sqlite3.Binary(cert_text), cert_asciihash, cert_subject])
    conn.commit()
    print(cursor.lastrowid)
    return cursor.lastrowid

def check_cert(conn, cert_text):
    cert_text = cert_text.encode('utf-8')
    cert_hash = hashlib.sha1()
    cert_hash.update(cert_text)
    cert_digested = cert_hash.digest()
    cert_asciihash = binascii.b2a_hex(cert_digested)

    sql = 'SELECT IDX FROM certs WHERE cert_hash = ?;'
    c = conn.cursor()
    c.execute(sql,[cert_asciihash])
    all_rows = c.fetchall()

    if all_rows:
        row = all_rows.pop()
        in_database = row[0]
    else:
        in_database = None
    return in_database

def check_url(conn, URL_text):
    sql = 'SELECT IDX FROM URLs WHERE URL = ?;'
    c = conn.cursor()
    c.execute(sql,[URL_text])
    all_rows = c.fetchall()

    if all_rows:
        row = all_rows.pop()
        in_database = row[0]
    else:
        in_database = None
    return in_database

def insert_URL(conn, url_text):
    cursor=conn.cursor()
    pr = urllib.parse.urlparse(url_text)
    host = pr.netloc
    port = pr.port

    if 'https' != pr.scheme:
        return

    if not port and 'https' == pr.scheme:
        port = 443

    sql = '''INSERT INTO URLs
    (URL, HOSTNAME, PORT)
    VALUES(?, ?, ?);'''
    cursor.execute(sql,[url_text, host, port])
    conn.commit()
    return cursor.lastrowid

def check_relationship(conn, cert_idx, url_idx):
    sql = 'SELECT * FROM ret_certs WHERE URL_IDX = ? AND cert_IDX = ?;'
    c = conn.cursor()
    c.execute(sql,[url_idx, cert_idx])
    all_rows = c.fetchall()
    if all_rows:
        in_database = True
    else:
        in_database = False
    return in_database

def insert_relationship(conn,cert_idx,url_idx):
    cursor=conn.cursor()
    sql = '''INSERT INTO ret_certs
    (URL_IDX, cert_IDX)
    VALUES(?, ?);'''
    cursor.execute(sql,[url_idx, cert_idx])
    conn.commit()

def create_or_open_db(db_file):
    db_is_new = not os.path.exists(db_file)
    conn = sqlite3.connect(db_file)
    if db_is_new:
        print('Creating schema')
        sql = '''create table if not exists URLs(
        IDX INTEGER PRIMARY KEY,
        URL TEXT,
        HOSTNAME TEXT,
        PORT INTEGER);
        create table if not exists certs(
        IDX integer primary key,
        cert_hash text,
        cert blob,
        cert_subject text
        );
        create table if not exists ret_certs(
        URL_IDX integer,
        cert_IDX integer
        )'''
        conn.execute(sql) # shortcut for conn.cursor().execute(sql)
    else:
        print('Schema exists\n')
    return conn


def main():

    url = "https://www.google.com"
    pr = urllib.parse.urlparse(url)
    host = pr.netloc
    port = pr.port

    if 'https' != pr.scheme:
        return

    if not port and 'https' == pr.scheme:
        port = 443

    db_file = "/Users/williamwallace/searchtables.db"
    conn = create_or_open_db(db_file)
    path = "/Users/williamwallace/devel/GetServerCertsScript/google.com/"
    dirs = os.listdir( path )
    counter = 0
    #for file in dirs: #goes through each file in the folder
    for url in url_list:
        #full_path = path + file


        url_idx = check_url(conn, url)
        if not url_idx:
            url_idx = insert_URL(conn, url)

        pr = urllib.parse.urlparse(url)
        host = pr.netloc

        certs = get_certs(host)


        if url_idx:
            for cert in certs:
                cert_idx = check_cert(conn, cert)
                if not cert_idx:
                    cert_idx = insert_cert(conn, cert, host)
                if cert_idx:
                    rel_in_database = check_relationship(conn,cert_idx,url_idx)
                    if not rel_in_database:
                        insert_relationship(conn,cert_idx,url_idx)

    conn.close()

if __name__ == '__main__':
    main()