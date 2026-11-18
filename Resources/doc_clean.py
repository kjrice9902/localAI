# Runs inside the sandbox, before the Word/RTF reader. Word and RTF can mark text
# "hidden" (Font > Hidden): it doesn't show on screen or paper, but a plain text
# reader would still hand it to the model. This empties every hidden run and
# writes a cleaned copy (same for OpenDocument .odt files).
# Usage: doc_clean.py in.docx|in.rtf|in.odt out  -> prints {"hidden": N}
import json, re, sys, zipfile

MAIN = (b"http://schemas.openxmlformats.org/wordprocessingml/2006/main", b"http://purl.oclc.org/ooxml/wordprocessingml/main")
TAG = re.compile(rb"<(/?)([A-Za-z_][\w.\-]*):([A-Za-z]+)((?:\s[^<>]*?)?)(/?)>", re.S)   # [^<>]: an unclosed tag stops at the next one (no slow rescans)
VAL = re.compile(rb'[\w.\-]+:val\s*=\s*["\']([^"\']*)["\']')
SID = re.compile(rb'[\w.\-]+:styleId\s*=\s*["\']([^"\']*)["\']')
HIDE = (b"vanish", b"specVanish", b"webHidden")
DEFAULT = re.compile(rb'[\w.\-]+:default\s*=\s*["\']\s*(1|true|on)\s*["\']', re.I)
STYPE = re.compile(rb'[\w.\-]+:type\s*=\s*["\']([^"\']*)["\']')
# Keys in the style table for what applies when nothing names a style (no real style id starts with a NUL byte).
BASE, PARA, CHAR = b"\x00base", b"\x00para", b"\x00char"
TEXT = (b"t", b"delText", b"instrText")


def prefixes(data):
    found = set()
    for uri in MAIN:
        if re.search(rb'xmlns\s*=\s*["\']' + re.escape(uri), data):
            raise SystemExit(5)                       # unprefixed Word markup: not something Word writes
        for m in re.finditer(rb'xmlns:([A-Za-z_][\w.\-]*)\s*=\s*["\']' + re.escape(uri) + rb'["\']', data):
            found.add(m.group(1))
    return found


def val_on(attrs):
    m = VAL.search(attrs or b"")
    return m is None or m.group(1).strip().lower() not in (b"0", b"false", b"off")


def val_of(attrs):
    m = VAL.search(attrs or b"")
    return m.group(1) if m else None


def style_table(data):
    """style id -> True/False (says hidden / says not hidden), following basedOn.
    Also what applies with no style named: BASE (the document defaults), PARA
    (the default paragraph style) and CHAR (the default character style)."""
    wp = prefixes(data)
    own, parent, cur, in_rpr = {}, {}, None, 0
    ids, defaults, in_dd, dd_rpr, base = set(), {}, False, 0, None
    for m in TAG.finditer(data):
        close, pre, name, attrs, selfc = m.groups()
        if pre not in wp:
            continue
        if name == b"docDefaults":
            in_dd, dd_rpr = (not close and not selfc), 0
        elif in_dd:
            # <w:docDefaults><w:rPrDefault><w:rPr><w:vanish/>: every run starts out hidden.
            if name == b"rPr":
                dd_rpr += -1 if close else (0 if selfc else 1)
            elif name in HIDE and not close and dd_rpr > 0:
                base = val_on(attrs)
        elif name == b"style":
            if close:
                cur = None
            elif not selfc:
                s = SID.search(attrs or b"")
                cur, in_rpr = (s.group(1) if s else None), 0
                if cur is not None:
                    ids.add(cur)
                    kind = STYPE.search(attrs or b"")
                    if DEFAULT.search(attrs or b"") and kind:
                        defaults.setdefault({b"paragraph": PARA, b"character": CHAR}.get(kind.group(1).strip().lower()), cur)
        elif cur is not None:
            if name == b"basedOn" and not close:
                parent[cur] = val_of(attrs)
            elif name == b"rPr":
                in_rpr += -1 if close else (0 if selfc else 1)
            elif name in HIDE and not close and in_rpr > 0:
                own[cur] = val_on(attrs)
    out = {}
    for sid in set(own) | set(parent) | ids:
        seen, s = set(), sid
        while s is not None and s not in seen:
            seen.add(s)
            if s in own:
                out[sid] = own[s]
                break
            s = parent.get(s)
        if sid not in out and base is not None:
            out[sid] = base                           # no style in the chain says: the document default decides
    if base is not None:
        out[BASE] = base
    for key in (PARA, CHAR):
        if defaults.get(key) in out:
            out[key] = out[defaults[key]]
    return out


def clean_part(data, styles):
    wp = prefixes(data)
    if not wp:
        return data, 0
    cuts, hidden, paras, runs = [], 0, [], []
    for m in TAG.finditer(data):
        close, pre, name, attrs, selfc = m.groups()
        if pre not in wp:
            continue
        if name == b"p":
            if close:
                if paras:
                    paras.pop()
            elif not selfc:
                paras.append([styles.get(PARA)])          # no style named yet: the default paragraph style applies
        elif name == b"pStyle" and not close and paras and not runs:
            paras[-1][0] = styles.get(val_of(attrs), styles.get(BASE))
        elif name == b"r":
            if close:
                if runs:
                    r = runs.pop()
                    verdict = next((v for v in (r["own"], r["style"], paras[-1][0] if paras else None,
                                                styles.get(CHAR), styles.get(BASE)) if v is not None), None)
                    if verdict and r["spans"]:
                        if any(b > a for a, b in r["spans"]):
                            hidden += 1
                        cuts.extend(r["spans"])
            elif not selfc:
                runs.append({"own": None, "style": None, "spans": [], "rpr": 0, "t": None})
        elif runs:
            r = runs[-1]
            if name == b"rPr":
                r["rpr"] += -1 if close else (0 if selfc else 1)
            elif name == b"rPrChange":
                r["rpr"] += 10 if not close and not selfc else (-10 if close else 0)     # old formatting of a tracked change: not what shows
            elif r["rpr"] == 1 and not close:
                if name in HIDE:
                    r["own"] = val_on(attrs)
                elif name == b"rStyle":
                    r["style"] = styles.get(val_of(attrs))
            if name in TEXT:
                if close:
                    if r["t"] is not None:
                        r["spans"].append((r["t"], m.start()))
                        r["t"] = None
                elif not selfc:
                    r["t"] = m.end()
    if not cuts:
        return data, 0
    cuts.sort()
    out, pos = [], 0
    for a, b in cuts:
        if a >= pos:
            out.append(data[pos:a])
            pos = b
    out.append(data[pos:])
    return b"".join(out), hidden


RTF_TOKEN = re.compile(rb"\\([A-Za-z]+)(-?\d+)? ?|\\'[0-9A-Fa-f]{2}|\\[^A-Za-z]|[{}]|[^\\{}]+", re.S)


def rtf_hidden_styles(data):
    """Style numbers whose stylesheet entry says hidden (\\v), following \\sbasedon."""
    own, parent, depth, sheet, cur = {}, {}, 0, None, None
    for m in RTF_TOKEN.finditer(data):
        tok = m.group(0)
        if tok == b"{":
            depth += 1
            if sheet is not None and depth == sheet + 1:
                cur = None
        elif tok == b"}":
            if sheet is not None and depth == sheet:
                break                                   # end of the stylesheet
            depth -= 1
        elif m.group(1):
            word, num = m.group(1), m.group(2)
            if word == b"stylesheet" and sheet is None:
                sheet = depth
            elif sheet is not None and depth == sheet + 1:
                if word in (b"s", b"cs", b"ds", b"ts") and cur is None:
                    cur = (word, int(num or 0))
                elif word == b"v" and cur is not None:
                    own[cur] = num != b"0"
                elif word == b"sbasedon" and cur is not None:
                    parent[cur] = int(num or 0)
    out = set()
    for key in set(own) | set(parent):
        seen, k = set(), key
        while k is not None and k not in seen:
            seen.add(k)
            if k in own:
                if own[k]:
                    out.add(key)
                break
            p = parent.get(k)
            k = (k[0], p) if p is not None else None
    return out


def clean_rtf(data):
    """Drop hidden text: \\v ... \\v0, and text in a style the stylesheet marks hidden."""
    hidden_styles = rtf_hidden_styles(data)
    out, stack, runs, was = [], [], 0, False
    v, cs, ps = None, False, False                      # direct \\v, char-style hidden, para-style hidden
    for m in RTF_TOKEN.finditer(data):
        tok = m.group(0)
        hid = v if v is not None else (cs or ps)
        if tok == b"{":
            stack.append((v, cs, ps))
            out.append(tok)
        elif tok == b"}":
            v, cs, ps = stack.pop() if stack else (None, False, False)
            out.append(tok)
        elif m.group(1):
            word, num = m.group(1), m.group(2)
            if word == b"v":
                v = num != b"0"
                out.append(tok)
            elif word == b"plain":
                v, cs = None, False
                out.append(tok)
            elif word == b"pard":
                ps = False
                out.append(tok)
            elif word == b"cs":
                cs = (b"cs", int(num or 0)) in hidden_styles
                out.append(tok)
            elif word == b"s":
                ps = (b"s", int(num or 0)) in hidden_styles
                out.append(tok)
            elif hid and word in (b"u", b"tab", b"emdash", b"endash", b"bullet", b"lquote", b"rquote", b"ldblquote", b"rdblquote"):
                pass                                    # characters written as control words
            else:
                out.append(tok)
        elif hid:
            if not was and tok.strip():
                runs += 1
            if tok in (b"\\\n", b"\\\r") or (tok[:1] != b"\\" and b"\n" in tok and not tok.strip()):
                out.append(tok)                         # keep line structure
            was = True
            continue
        else:
            out.append(tok)
        was = False if not hid else was
    return b"".join(out), runs


ODF_TEXT = b"urn:oasis:names:tc:opendocument:xmlns:text:1.0"
ODF_STYLE = b"urn:oasis:names:tc:opendocument:xmlns:style:1.0"
XTOK = re.compile(rb"<!--.*?(?:-->|\Z)|<!\[CDATA\[.*?(?:\]\]>|\Z)|<\?.*?(?:\?>|\Z)|"   # unclosed: runs to the end once
                  rb"<(/?)([A-Za-z_][\w.\-]*:)?([A-Za-z_][\w.\-]*)((?:\s+[\w.\-:]+\s*=\s*(?:\"[^\"]*\"|'[^']*'))*)\s*(/?)>", re.S)
XATTR = re.compile(rb"([\w.\-]+:)?([\w.\-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)')")


def odf_prefixes(data, uri):
    if re.search(rb'xmlns\s*=\s*["\']' + re.escape(uri), data):
        raise SystemExit(5)
    return set(m.group(1) + b":" for m in re.finditer(rb'xmlns:([A-Za-z_][\w.\-]*)\s*=\s*["\']' + re.escape(uri) + rb'["\']', data))


def xattrs(blob):
    return dict(((m.group(1) or b"") + m.group(2), m.group(3) if m.group(3) is not None else m.group(4)) for m in XATTR.finditer(blob or b""))


def odf_styles(parts):
    """style name -> True when text in that style is not shown (text:display none/condition), following parents."""
    own, parent = {}, {}
    for data in parts:
        tp, sp, cur = odf_prefixes(data, ODF_TEXT), odf_prefixes(data, ODF_STYLE), None
        for m in XTOK.finditer(data):
            if m.group(3) is None:
                continue
            close, pre, name, blob, selfc = m.groups()
            if pre not in sp:
                continue
            if name in (b"style", b"default-style"):
                if close:
                    cur = None
                else:
                    at = xattrs(blob)
                    cur = next((at[k + b"name"] for k in sp if k + b"name" in at), None)
                    par = next((at[k + b"parent-style-name"] for k in sp if k + b"parent-style-name" in at), None)
                    if cur is not None and par is not None:
                        parent[cur] = par
                    if selfc:
                        cur = None
            elif name == b"text-properties" and not close and cur is not None:
                at = xattrs(blob)
                for k in tp:
                    if k + b"display" in at:
                        own[cur] = at[k + b"display"].strip().lower() != b"true"
    out = {}
    for sid in set(own) | set(parent):
        seen, cur = set(), sid
        while cur is not None and cur not in seen:
            seen.add(cur)
            if cur in own:
                out[sid] = own[cur]
                break
            cur = parent.get(cur)
    return set(k for k, v in out.items() if v)


def clean_odf(data, hidden_styles):
    """Cut the text of everything that is not shown: spans/paragraphs in a hidden
    style and sections marked text:display none (or shown only on a condition)."""
    tp = odf_prefixes(data, ODF_TEXT)
    if not tp:
        return data, 0
    out, stack, pos, runs = [], [], 0, 0
    for m in XTOK.finditer(data):
        gap = data[pos:m.start()]
        hid = bool(stack and stack[-1])
        if m.group(3) is None:                         # comment, CDATA or processing instruction
            if hid:
                if gap.strip() or m.group(0).startswith(b"<![CDATA["):
                    runs += 1
            else:
                out.append(gap)
                tok = m.group(0)
                if tok.endswith((b"-->", b"]]>", b"?>")):
                    out.append(tok)
                else:
                    runs += 1                          # never closed: the rest of the file is dropped, not passed on unchecked
            pos = m.end()
            continue
        if hid:
            if gap.strip():
                runs += 1
        else:
            out.append(gap)
        out.append(m.group(0))                         # markup stays, so the file is still well formed
        pos = m.end()
        close, pre, name, blob, selfc = m.groups()
        if close:
            if stack:
                stack.pop()
        elif not selfc:
            mine = False
            if pre in tp:
                at = xattrs(blob)
                disp = next((at[k + b"display"] for k in tp if k + b"display" in at), None)
                style = next((at[k + b"style-name"] for k in tp if k + b"style-name" in at), None)
                mine = (disp is not None and disp.strip().lower() != b"true") or (style in hidden_styles)
            stack.append(hid or mine)
    tail = data[pos:]
    if stack and stack[-1]:                             # file ends inside a hidden part: drop the rest
        if tail.strip():
            runs += 1
    else:
        out.append(tail)
    return b"".join(out), runs


def main_odt(src, dst):
    zin = zipfile.ZipFile(src)
    infos = zin.infolist()
    if len(infos) > 5000 or sum(i.file_size for i in infos) > 400 << 20:
        raise SystemExit(4)
    parts = {}
    for name in ("content.xml", "styles.xml"):
        try:
            parts[name] = zin.read(name)
        except KeyError:
            continue
        if b"<!DOCTYPE" in parts[name][:4096] or b"<!ENTITY" in parts[name][:65536]:
            raise SystemExit(5)
    if "content.xml" not in parts:
        raise SystemExit(5)
    hidden_styles = odf_styles(parts.values())
    total = 0
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in infos:
            if info.is_dir() or info.filename.startswith("/") or ".." in info.filename.split("/"):
                continue
            data = parts.get(info.filename)
            if data is None:
                data = zin.read(info.filename)
                if info.filename.lower().endswith(".xml") and (b"<!DOCTYPE" in data[:4096] or b"<!ENTITY" in data[:65536]):
                    raise SystemExit(5)               # no entity tricks in any part, not only the two read above
            else:
                data, n = clean_odf(data, hidden_styles)
                total += n
            zout.writestr(info.filename, data, zipfile.ZIP_STORED if info.filename == "mimetype" else zipfile.ZIP_DEFLATED)
    sys.stdout.write(json.dumps({"hidden": total}))


def main():
    src, dst = sys.argv[1], sys.argv[2]
    if src.lower().endswith(".odt"):
        return main_odt(src, dst)
    if src.lower().endswith(".rtf"):
        with open(src, "rb") as fh:
            data = fh.read((64 << 20) + 1)
        if len(data) > 64 << 20:
            raise SystemExit(4)                       # too big to check fully: refuse rather than cut it off silently
        data, n = clean_rtf(data)
        with open(dst, "wb") as fh:
            fh.write(data)
        sys.stdout.write(json.dumps({"hidden": n}))
        return
    zin = zipfile.ZipFile(src)
    infos = zin.infolist()
    if len(infos) > 5000 or sum(i.file_size for i in infos) > 400 << 20:
        raise SystemExit(4)
    # Word finds its parts through relationship files, so a part can sit anywhere in the
    # zip (word/sub/document.xml, other/x.xml). Check every XML part, wherever it is.
    def is_xml(n):
        low = n.lower()
        return low.endswith(".xml") and not low.endswith(".rels") and low != "[content_types].xml"
    names = [i.filename for i in infos if not i.is_dir()]
    styles = {}
    for n in names:
        if not is_xml(n):
            continue
        head = zin.read(n)[:4096]
        if re.search(rb"<[A-Za-z_][\w.\-]*:styles[\s>]", head):
            data = zin.read(n)
            if b"<!DOCTYPE" in data[:4096] or b"<!ENTITY" in data[:65536]:
                raise SystemExit(5)
            styles.update(style_table(data))
    total = 0
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in infos:
            if info.is_dir() or info.filename.startswith("/") or ".." in info.filename.split("/"):
                continue
            data = zin.read(info.filename)
            if is_xml(info.filename):                 # style parts too: no runs there, so nothing is cut
                if b"<!DOCTYPE" in data[:4096] or b"<!ENTITY" in data[:65536]:
                    raise SystemExit(5)
                data, n = clean_part(data, styles)
                total += n
            zout.writestr(info.filename, data)
    sys.stdout.write(json.dumps({"hidden": total}))


main()
