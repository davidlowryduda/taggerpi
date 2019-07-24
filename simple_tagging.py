"""
Simple tagging system.

WIP
"""

import sqlite3
import hashlib


def create_tag_table(conn=None):
    c = conn.cursor()
    c.execute(
        'CREATE TABLE IF NOT EXISTS tag_table'
        '( '
        'tag_id INTEGER PRIMARY KEY, '
        'name STRING NOT NULL UNIQUE, '
        'description STRING'
        ');'
    )
    conn.commit()

def create_entry_table(conn=None):
    c = conn.cursor()
    c.execute(
        'CREATE TABLE IF NOT EXISTS entry_table'
        '( '
        'entry_id INTEGER PRIMARY KEY, '
        'name STRING NOT NULL UNIQUE, '
        'hash INTEGER NOT NULL, '
        'description STRING'
        ');'
    )
    conn.commit()

def create_mapping_table(conn=None):
    c = conn.cursor()
    c.execute(
        'CREATE TABLE IF NOT EXISTS mapping_table'
        '( '
        'entry_reference INTEGER REFERENCES entry_table(entry_id) ON UPDATE CASCADE ON DELETE CASCADE, '
        'tag_reference INTEGER REFERENCES tag_table(tag_id) ON UPDATE CASCADE ON DELETE CASCADE, '
        'UNIQUE (entry_reference, tag_reference) '
        ');'
    )
    conn.commit()


def md5(filename):
    hash_md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return int(hash_md5.hexdigest(), 16)


def add_entry(name, description='', conn=None):
    c = conn.cursor()
    filehash = md5(name) % 2**32
    c.execute(
        'INSERT INTO entry_table (name, hash, description) '
        'VALUES (?, ?, ?)', (name, filehash, description)
    )
    conn.commit()


def add_tag(name, description='', conn=None):
    c = conn.cursor()
    c.execute(
        'INSERT INTO tag_table (name, description) '
        'VALUES (?, ?)', (name, description)
    )
    conn.commit()

def entryid_from_entryname(name, conn=None):
    c = conn.cursor()
    c.execute('SELECT entry_id FROM entry_table WHERE name=?', (name, ))
    v = c.fetchone()
    return v[0]

def tagid_from_tagname(name, conn=None):
    c = conn.cursor()
    c.execute('SELECT tag_id FROM tag_table WHERE name=?', (name, ))
    v = c.fetchone()
    return v[0]

def tag_entry(entry, tag, conn=None):
    c = conn.cursor()
    entryid = entryid_from_entryname(entry)
    tagid = tagid_from_tagname(tag)
    c.execute('INSERT INTO mapping_table (entry_reference, tag_reference) VALUES (?, ?)', (entryid, tagid))
    conn.commit()

def remove_entry(name, conn=None):
    c = conn.cursor()
    c.execute('DELETE FROM entry_table WHERE name=?', (name, ))
    conn.commit()

def remove_tag(name, conn=None):
    c = conn.cursor()
    c.execute('DELETE FROM tag_table WHERE name=?', (name, ))
    conn.commit()

def untag_entry(entry, tag, conn=None):
    c = conn.cursor()
    entryid = entryid_from_entryname(entry)
    tagid = tagid_from_tagname(tag)
    c.execute('DELETE FROM mapping_table WHERE entry_reference = ? AND tag_reference = ?',
              (entryid, tagid))
    conn.commit()

def update_entry_desc(entry, description, conn=None):
    c = conn.cursor()
    c.execute('UPDATE entry_table SET description = ? WHERE name = ?',
              (description, entry))
    conn.commit()

def update_tag_desc(tag, description, conn=None):
    c = conn.cursor()
    c.execute('UPDATE tag_table SET description = ? WHERE name = ?',
              (description, tag))
