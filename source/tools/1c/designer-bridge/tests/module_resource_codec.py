"""Bounded independent readers for plain Format15 and managed form trees.

No extraction or output of source contents. A matched string alone is never
accepted as a module: the caller must use a reviewed structural field.
"""
import re
import struct

END=0x7fffffff
MAX=4*1024*1024
PAGE=re.compile(rb'\r\n([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) \r\n')


def entries(data):
    if type(data) is not bytes or not 16<len(data)<=MAX:raise ValueError('RESOURCE_SIZE')
    free,page,count,reserved=struct.unpack_from('<4I',data)
    if free!=END or page!=512 or count not in (1,2) or reserved:raise ValueError('RESOURCE_HEADER')
    blocks={};cursor=16
    while cursor<len(data):
        m=PAGE.match(data,cursor)
        if not m or len(blocks)>=8192:raise ValueError('RESOURCE_PAGE')
        size,capacity,next_at=(int(m[i],16) for i in (1,2,3));last=cursor+31+capacity
        if not capacity or size>MAX or last>len(data):raise ValueError('RESOURCE_PAGE_BOUND')
        blocks[cursor]=(size,capacity,next_at);cursor=last
    used=set()
    def stream(address):
        result=bytearray();total=None
        while address!=END:
            if address not in blocks or address in used:raise ValueError('RESOURCE_CHAIN')
            used.add(address);size,capacity,following=blocks[address]
            if total is None:total=size
            elif len(result)>=total:raise ValueError('RESOURCE_CONTINUATION')
            take=min(capacity,total-len(result));result.extend(data[address+31:address+31+take]);address=following
        if total is None or len(result)!=total:raise ValueError('RESOURCE_TRUNCATED')
        return bytes(result)
    toc=stream(16)
    if not len(toc) or len(toc)%12 or len(toc)>8*12:raise ValueError('RESOURCE_TOC')
    result={}
    for offset in range(0,len(toc),12):
        a,b,sentinel=struct.unpack_from('<3I',toc,offset)
        if sentinel!=END:raise ValueError('RESOURCE_SENTINEL')
        raw=stream(a)
        if not 24<=len(raw)<=128 or raw[-4:]!=bytes(4):raise ValueError('RESOURCE_NAME')
        try:name=raw[20:-4].decode('utf-16-le').rstrip('\0')
        except UnicodeError:raise ValueError('RESOURCE_NAME_ENCODING')
        if not re.fullmatch('[a-z][a-z0-9]{0,31}',name) or name in result:raise ValueError('RESOURCE_NAME_SCOPE')
        result[name]=stream(b)
    if used!=set(blocks):raise ValueError('RESOURCE_UNOWNED')
    return result


class Atom(str):
    """Unquoted serialization atom, distinct from a text field."""


def form_tree(data):
    if type(data) is not bytes or not 0<len(data)<=MAX:raise ValueError('FORM_TREE_SIZE')
    try:text=data.decode('utf-8-sig')
    except UnicodeError:raise ValueError('FORM_TREE_ENCODING')
    cursor=0;count=0
    def value(depth):
        nonlocal cursor,count
        count+=1
        if depth>64 or count>200000:raise ValueError('FORM_TREE_BOUND')
        while cursor<len(text) and text[cursor].isspace():cursor+=1
        if cursor>=len(text):raise ValueError('FORM_TREE_TRUNCATED')
        if text[cursor]=='{':
            cursor+=1;result=[]
            while True:
                while cursor<len(text) and text[cursor].isspace():cursor+=1
                if cursor>=len(text):raise ValueError('FORM_TREE_TRUNCATED')
                if text[cursor]=='}':cursor+=1;return result
                result.append(value(depth+1))
                while cursor<len(text) and text[cursor].isspace():cursor+=1
                if cursor>=len(text) or text[cursor] not in ',}':raise ValueError('FORM_TREE_SEPARATOR')
                if text[cursor]=='}':cursor+=1;return result
                cursor+=1
        if text[cursor]=='"':
            cursor+=1;parts=[];start=cursor
            while cursor<len(text):
                if text[cursor]!='"':cursor+=1;continue
                parts.append(text[start:cursor]);cursor+=1
                if cursor<len(text) and text[cursor]=='"':parts.append('"');cursor+=1;start=cursor;continue
                return ''.join(parts)
            raise ValueError('FORM_TREE_QUOTE')
        start=cursor
        while cursor<len(text) and text[cursor] not in ',{}"':cursor+=1
        if cursor==start:raise ValueError('FORM_TREE_ATOM')
        return Atom(text[start:cursor].strip())
    result=value(0)
    if text[cursor:].strip() or type(result) is not list:raise ValueError('FORM_TREE_TRAILING')
    return result


def module_text(data,kind):
    """Read the reviewed exact module field, preserving whitespace and quotes.

    Document/manager: Format15 info+text. Ordinary form: form+module entries.
    Managed form v3/v4: ten root fields, module at root[2]; no string search.
    """
    if kind not in ('document','form'):raise ValueError('MODULE_RESOURCE_KIND')
    if type(data) is not bytes or not 0<len(data)<=MAX:raise ValueError('MODULE_RESOURCE_SIZE')
    if data[:4]==struct.pack('<I',END):
        values=entries(data)
        wanted={'info','text'} if kind=='document' else {'form','module'}
        if set(values)!=wanted:raise ValueError('MODULE_RESOURCE_ENTRIES')
        if kind=='document':
            if not 0<len(values['info'])<=1024:raise ValueError('MODULE_RESOURCE_INFO')
            values['info'].decode('utf-8-sig');raw=values['text'];profile='document-format15'
        else:
            form_tree(values['form']);raw=values['module'];profile='ordinary-form-format15'
        try:text=raw.decode('utf-8-sig')
        except UnicodeError:raise ValueError('MODULE_RESOURCE_ENCODING')
    elif kind=='form':
        tree=form_tree(data)
        if (len(tree)!=10 or type(tree[0]) is not Atom or tree[0] not in ('3','4')
            or type(tree[1]) is not list or not tree[1]
            or tree[1][0]!=('38' if tree[0]=='3' else '49') or type(tree[2]) is not str):
            raise ValueError('MODULE_RESOURCE_MANAGED_SCHEMA')
        text=tree[2];profile='managed-form-v'+tree[0]
    else:raise ValueError('MODULE_RESOURCE_FORMAT')
    if len(text)>1048576:raise ValueError('MODULE_RESOURCE_TEXT_BOUND')
    return text,profile


def loader_projection(text,profile):
    """Observed 8.3.18 ordinary-form reader projection, never resource rewriting.

    Three real unchanged own-copy forms expose CRCRLF as CRLF through the
    published helper. Preserve raw text/hash separately. No spaces, comments,
    quotes or other line breaks are discarded; unobserved triple CR rejects.
    """
    if type(text) is not str:raise ValueError('MODULE_PROJECTION_TYPE')
    if profile=='ordinary-form-format15':
        if '\r\r\r\n' in text:raise ValueError('MODULE_PROJECTION_UNREVIEWED_CR')
        text=text.replace('\r\r\n','\r\n')
    return text.replace('\r\n','\n').replace('\r','\n')
