"""Deterministic actual-client tool fixture; never submits source/user files."""
import errno
import json
from pathlib import Path
import shlex


class ToolScenario:
    def __init__(self, out, timezone):
        self.out=Path(out)
        self.work=self.out/"work"
        self.timezone=timezone
        self.input=self.work/"native-input.txt"
        self.output=self.work/"native-output.txt"
        self.proof=self.work/"native-proof.json"
        self.script=self.work/"native-tool-probe.py"
        if any(path.exists() or path.is_symlink() for path in (self.input,self.output,self.proof,self.script)):
            raise ValueError("Tool scenario requires a fresh fixture output directory")
        self.input_text="WRAPPER_REAL_READ_MARKER_20261108\n"
        self.write_text="WRAPPER_REAL_WRITE_MARKER_20261108\n"
        self.append_text="BASH_NATIVE_APPEND\n"
        self.input.write_text(self.input_text)
        self.original=self.input.stat()
        self.results={}
        self.stages=[]
        # Run only this fixed script through Claude's real Bash tool. The direct
        # socket probes send no application data to external hosts. They should
        # fail in the inherited kernel policy before any packet is emitted.
        script='''import ctypes, errno, json, os, pwd, socket, subprocess, urllib.parse
from pathlib import Path
work=Path(__file__).resolve().parent
output=work/"native-output.txt"
before=output.stat()
with output.open("a") as handle:
    handle.write("BASH_NATIVE_APPEND\\n")
after=output.stat()
def is_local_relay(value):
    if not value:
        return False
    try:
        url=urllib.parse.urlsplit(value)
        return url.scheme=="http" and url.hostname in ("127.0.0.1","::1") and bool(url.port)
    except ValueError:
        return False
proof={"cwd_matches": Path.cwd()==work,
       "input_matches": (work/"native-input.txt").read_text()=="WRAPPER_REAL_READ_MARKER_20261108\\n",
       "output_native_inode_preserved": (before.st_dev,before.st_ino)==(after.st_dev,after.st_ino),
       "output_owner_matches": after.st_uid==os.getuid(),
       "env": {key:os.environ.get(key) for key in
               ("TZ","LANG","LC_ALL")},
       "home_is_fixture": Path(os.environ["HOME"])==work.parent/"home",
       "private_environment_absent": not any(key.startswith("CLAUDE_WRAPPER_") for key in os.environ),
       "proxy_present": all(is_local_relay(os.environ.get(key))
                            for key in ("HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"))}
native=ctypes.CDLL(None)
native.getenv.argtypes=[ctypes.c_char_p]
native.getenv.restype=ctypes.c_char_p
def native_env(key):
    value=native.getenv(key.encode())
    return value.decode() if value is not None else None
proxy_keys=("HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy","NO_PROXY","no_proxy")
proxy=os.environ.get("HTTPS_PROXY")
proof["native_proxy"]={key:{"present":native_env(key) is not None,
    "matches_child_map":native_env(key)==os.environ.get(key),
    "expected":native_env(key)==("" if key.lower()=="no_proxy" else proxy) and
        (key.lower()=="no_proxy" or is_local_relay(proxy))}
    for key in proxy_keys}
native._NSGetEnviron.argtypes=[]
native._NSGetEnviron.restype=ctypes.POINTER(ctypes.POINTER(ctypes.c_char_p))
environment=native._NSGetEnviron().contents
index=0
private_absent=True
while environment[index] is not None:
    if environment[index].split(b"=",1)[0].startswith(b"CLAUDE_WRAPPER_"):
        private_absent=False
    index+=1
proof["native_private_environment_absent"]=private_absent
try:
    account=pwd.getpwuid(os.getuid())
    proof["account"]={"available": True,"matches_system": account.pw_name==subprocess.check_output(["/usr/bin/id", "-un"], text=True).strip()}
except (OSError,KeyError) as exc:
    proof["account"]={"available": False,"error_kind":type(exc).__name__}
try:
    name=os.uname().nodename
    proof["hostname"]={"available": True,"matches_system": name==subprocess.check_output(["/bin/hostname"], text=True).strip()}
except OSError as exc:
    proof["hostname"]={"available": False,"errno":exc.errno}
proof["network"]={}
for label,kind,address in (("tcp_external",socket.SOCK_STREAM,("1.1.1.1",443)),
                           ("tcp_local_other_port",socket.SOCK_STREAM,("127.0.0.1",9)),
                           ("udp_external",socket.SOCK_DGRAM,("1.1.1.1",53))):
    sock=socket.socket(socket.AF_INET,kind)
    sock.settimeout(2)
    try:
        if kind==socket.SOCK_STREAM:
            sock.connect(address)
        else:
            # connect checks the outbound policy without transmitting a datagram.
            sock.connect(address)
        proof["network"][label]={"blocked":False}
    except OSError as exc:
        proof["network"][label]={"blocked":exc.errno in (errno.EPERM,errno.EACCES),"errno":exc.errno}
    finally:
        sock.close()
(work/"native-proof.json").write_text(json.dumps(proof,sort_keys=True))
print("WRAPPER_REAL_BASH_MARKER_20261108")
'''
        self.script.write_text(script)

    def message(self, data):
        # Background/no-tool requests receive ordinary OK. Only the main run
        # whose schema advertises all three fixture tools enters this scenario.
        names={item.get("name") for item in data.get("tools",[])}
        if not {"Read","Write","Bash"}.issubset(names):
            return self._message([{"type":"text","text":"OK"}],"end_turn")
        for message in data.get("messages",[]):
            content=message.get("content",[])
            if not isinstance(content,list):
                continue
            for block in content:
                if isinstance(block,dict) and block.get("type")=="tool_result":
                    identifier=block.get("tool_use_id","")
                    if identifier.startswith("toolu_wrapper_audit_"):
                        self.results[identifier]=block
        stages=[
            ("read","Read",{"file_path":str(self.input)}),
            ("write","Write",{"file_path":str(self.output),"content":self.write_text}),
            ("bash","Bash",{"command":"/usr/bin/python3 "+shlex.quote(str(self.script)),
                            "description":"Run controlled native file, identity and network checks","timeout":10000}),
        ]
        for stage,name,arguments in stages:
            identifier="toolu_wrapper_audit_"+stage
            if identifier not in self.results:
                self.stages.append(stage)
                return self._message([{"type":"tool_use","id":identifier,"name":name,"input":arguments}],"tool_use")
        self.stages.append("complete")
        return self._message([{"type":"text","text":"OK"}],"end_turn")

    @staticmethod
    def _message(content, stop):
        return {"id":"msg_wrapper_tool_audit","type":"message","role":"assistant",
                "model":"claude-sonnet-4-6","content":content,"stop_reason":stop,
                "stop_sequence":None,"usage":{"input_tokens":10,"output_tokens":1}}

    def verify(self, outcome):
        def result_text(stage):
            return json.dumps(self.results.get("toolu_wrapper_audit_"+stage,{}),ensure_ascii=False)
        proof=json.loads(self.proof.read_text()) if self.proof.exists() else None
        now=self.input.stat()
        checks={
            "client_exit_zero":outcome["exit"]==0,
            "scenario_completed":"complete" in self.stages,
            "actual_read_returned_marker":self.input_text.strip() in result_text("read"),
            "actual_write_succeeded":"toolu_wrapper_audit_write" in self.results and
                not self.results["toolu_wrapper_audit_write"].get("is_error",False),
            "actual_bash_returned_marker":"WRAPPER_REAL_BASH_MARKER_20261108" in result_text("bash"),
            "host_sees_write_and_append":self.output.exists() and self.output.read_text()==self.write_text+self.append_text,
            "input_path_inode_owner_preserved":(now.st_dev,now.st_ino,now.st_uid)==
                (self.original.st_dev,self.original.st_ino,self.original.st_uid),
            "input_unchanged":self.input.read_text()==self.input_text,
            "proof_present":proof is not None,
        }
        if proof:
            for key in ("cwd_matches","input_matches","output_native_inode_preserved",
                        "output_owner_matches","home_is_fixture","private_environment_absent","proxy_present",
                        "native_private_environment_absent"):
                checks[key]=proof.get(key) is True
            for key in ("HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy","NO_PROXY","no_proxy"):
                checks["native_proxy_"+key]=all(proof.get("native_proxy",{}).get(key,{}).get(field) is True
                    for field in ("present","matches_child_map","expected"))
            expected={"TZ":self.timezone,"LANG":"en_US.UTF-8","LC_ALL":"en_US.UTF-8"}
            actual=proof.get("env",{})
            checks["child_environment_matches_profile"]=all(actual.get(key)==value for key,value in expected.items())
            for key in ("account","hostname"):
                value=proof.get(key,{})
                checks["child_"+key+"_native"]=value.get("available") is True and value.get("matches_system") is True
            network=proof.get("network",{})
            for key in ("tcp_external","tcp_local_other_port","udp_external"):
                checks["child_"+key+"_blocked"]=network.get(key,{}).get("blocked") is True
        return {"passed":all(checks.values()),"checks":checks,"stages":self.stages,
                "runtime_assets":getattr(self,"runtime_assets",{}),
                "tool_results":self.results,"child_proof":proof,
                "scope":"Official CLI and tools; local fixture model, dummy credentials; no live Anthropic auth/model."}
