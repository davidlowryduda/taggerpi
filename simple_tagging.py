"""
simple_tagging.py --- a simple tagging system

simple_tagging.py is a tool for annotating files (or precise topics) in a
database, but within the simplest possible way.

Right now, simple_tagging.py is a work in progress. It is just useful enough to
perform its most basic functionality.


Author Info
-----------

This tool was written by David Lowry-Duda <david@lowryduda.com>.


License Info
------------

This is released under the MIT License.


Copyright (c) 2019 David Lowry-Duda <david@lowryduda.com>.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


import argparse
import hashlib
import os
import sqlite3
import sys


def create_entry_table(conn=None):
    """
    Create entry_table (if it doesn't exist) in sqlite db connection `conn`.

    The entry_table has the following schema:

        :entry_table:
        entry_id     INTEGER  PRIMARY KEY
        name         STRING   UNIQUE
        hash         INTEGER
        description  STRING

    The string and hash cannot be empty. The hash is an md5 of the contents of
    the file (or a default value if it is not a file).
    """
    cursor = conn.cursor()
    cursor.execute(
        'CREATE TABLE IF NOT EXISTS entry_table'
        '( '
        'entry_id INTEGER PRIMARY KEY, '
        'name STRING NOT NULL UNIQUE, '
        'hash INTEGER NOT NULL, '
        'description STRING'
        ');'
    )
    conn.commit()


def create_tag_table(conn=None):
    """
    Create tag_table (if it doesn't exist) in sqlite db connection `conn`.

    The tag_table has the following schema:

        :tag_table:
        tag_id       INTEGER  PRIMARY KEY
        name         STRING   UNIQUE
        description  STRING
    """
    cursor = conn.cursor()
    cursor.execute(
        'CREATE TABLE IF NOT EXISTS tag_table'
        '( '
        'tag_id INTEGER PRIMARY KEY, '
        'name STRING NOT NULL UNIQUE, '
        'description STRING'
        ');'
    )
    conn.commit()


def create_mapping_table(conn=None):
    """
    Creat mapping_table (if it doesn't exist) in sqlite db connection `conn`.

    The mapping_table has the following schema:

        :mapping_table:
        entry_reference  INTEGER
        tag_reference    INTEGER

    The mapping_table is a basic associative table holding relationships between
    entries and tags. An entry_reference is an integer holding the entry_id of
    an entry in the entry_table, and a tag_reference is an integer holding the
    tag_id of an entry in the tag_table. (These are enforced by the database,
    with cascading changes on update and delete).
    """
    cursor = conn.cursor()
    cursor.execute(
        'CREATE TABLE IF NOT EXISTS mapping_table'
        '( '
        'entry_reference INTEGER REFERENCES entry_table(entry_id)'
        ' ON UPDATE CASCADE ON DELETE CASCADE, '
        'tag_reference INTEGER REFERENCES tag_table(tag_id)'
        ' ON UPDATE CASCADE ON DELETE CASCADE, '
        'UNIQUE (entry_reference, tag_reference) '
        ');'
    )
    conn.commit()


def initialize_db(conn=None):
    """
    Set up three tables (if they don't exist) in sqlite db connection `conn`.

    This should only be called when the database needs to be created for the
    first time.
    """
    print("Creating database...")
    create_tag_table(conn=conn)
    create_entry_table(conn=conn)
    create_mapping_table(conn=conn)
    print("Done.")


def md5(filename):
    hash_md5 = hashlib.md5()
    try:
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return int(hash_md5.hexdigest(), 16)
    except FileNotFoundError:
        print("File {} not found. Using default hash value.".format(filename))
        return 1


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

def tags_for_entry(entry, conn=None):
    c = conn.cursor()
    entryid = entryid_from_entryname(entry, conn=conn)
    c.execute('SELECT tag_reference FROM mapping_table WHERE entry_reference=?', (entryid, ))
    taglist = []
    for res in c.fetchall():
        cursor2 = conn.cursor()
        cursor2.execute('SELECT name FROM tag_table WHERE tag_id=?', (int(res[0]), ))
        taglist.append(cursor2.fetchone()[0])
    return taglist

def describe_entry(entry, conn=None):
    c = conn.cursor()
    c.execute('SELECT name, description FROM entry_table WHERE name=?', (entry, ))
    tags = tags_for_entry(entry, conn=conn)
    res = c.fetchone()
    if not res:
        return
    name, description = res
    print_description(name, description, tags)

def describe_tag(tag, conn=None):
    c = conn.cursor()
    c.execute('SELECT name, description FROM tag_table WHERE name=?', (tag, ))
    res = c.fetchone()
    if not res:
        return
    name, description = res
    print_description(name, description, [])

def list_all_entries(conn=None):
    c = conn.cursor()
    print("Known entries:")
    for res in c.execute('SELECT entry_id, name FROM entry_table'):
        print("  {}".format(res[1]))
        #print("  id: {}   entry: {}".format(*res))

def list_all_tags(conn=None):
    c = conn.cursor()
    print("Known tags:")
    for res in c.execute('SELECT name FROM tag_table'):
        print("  {}".format(res[0]))

def print_description(name, description, tags):
    tagstring = ", ".join(tags)
    if tagstring:
        tagstring = "| tags: " + tagstring
    print("")
    print("# {} {}".format(name, tagstring))
    print("")
    print("  {}".format(description))
    print("")

def tag_entry(entry, tag, conn=None):
    c = conn.cursor()
    entryid = entryid_from_entryname(entry, conn=conn)
    tagid = tagid_from_tagname(tag, conn=conn)
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


def _build_parser():
    usage = "%(prog)s [--dir DIR] [--db DB] [options] [TEXT]"
    epilog = (
        "Author: David Lowry-Duda <david@lowryduda.com>."
        "\nPlease report any bugs to https://github.com/davidlowryduda/taggerpy"
    )
    parser = argparse.ArgumentParser(usage=usage, epilog=epilog)
    parser.add_argument("text", nargs='*', metavar="TEXT")

    actions = parser.add_argument_group(
        'Actions',
        "If no actions are specified, print the description of entry given by TEXT."
    )
    actions.add_argument("-a", "--add",
                         dest="add_entry_name", default="",
                         help="add ENTRY with description given by TEXT",
                         metavar="ENTRY")
    actions.add_argument("--add-tag",
                         dest="add_tag_name", default="",
                         help="add TAG with description given by TEXT",
                         metavar="TAG")
    actions.add_argument("--tag-entry",
                         dest="tag_entry_tag", default="",
                         help="add TAG to entry specified by TEXT",
                         metavar="TAG")
    actions.add_argument("--list-entries",
                         dest="list_entries", default=False,
                         action="store_true",
                         help="List all entries known to database. This might be large.")
    actions.add_argument("--list-tags",
                         dest="list_tags", default=False,
                         action="store_true",
                         help="List all tags known to database. This might be large.")
    actions.add_argument("--tag-info",
                         dest="tag_info", default="",
                         help="Print description for TAG.",
                         metavar="TAG")
    actions.add_argument("--remove-tag",
                         dest="remove_tag", default="",
                         help="Remove TAG.",
                         metavar="TAG")

    config = parser.add_argument_group("Configuration Options")
    config.add_argument("--dir",
                        dest="dbdir", default=".",
                        help="Use database in DIR",
                        metavar="DIR")
    config.add_argument("--db",
                        dest="dbname", default="tagpy.db",
                        help="Use database DB", metavar="DB")
    config.add_argument("--stdin",
                        dest="stdin", default=False,
                        action="store_true",
                        help="Read TEXT from stdin.")
    return parser


def main(input_args=None):
    args = _build_parser().parse_args(args=input_args)

    dbdir = os.path.expanduser(args.dbdir)
    dbname = args.dbname
    path = os.path.join(os.path.realpath(dbdir), dbname)
    if os.path.isdir(path):
        raise IOError("Invalid database file. File is a directory.")

    # repeat conn because sqlite3.connect creates a file if it doesn't exist.
    if not os.path.isfile(path):
        conn = sqlite3.connect(path)
        initialize_db(conn)
    else:
        conn = sqlite3.connect(path)

    text = ' '.join(args.text).strip()
    if args.stdin:
        text = ''.join(sys.stdin.readlines()).strip()

    if args.add_entry_name:
        add_entry(args.add_entry_name, description=text, conn=conn)
    elif args.add_tag_name:
        add_tag(args.add_tag_name, description=text, conn=conn)
    elif args.tag_entry_tag:
        tag_entry(text, args.tag_entry_tag, conn=conn)
    elif args.list_entries:
        list_all_entries(conn=conn)
    elif args.list_tags:
        list_all_tags(conn=conn)
    elif args.tag_info:
        describe_tag(args.tag_info, conn=conn)
    elif args.remove_tag:
        remove_tag(args.remove_tag, conn=conn)
    else:
        if text:
            describe_entry(text, conn=conn)
        else:
            _build_parser().print_help()


if __name__ == "__main__":
    main()
