#!/usr/bin/env python3
"""Capture an actual Claude run entirely inside a guarded local test proxy.

Only the explicit dummy key is permitted. The public test CA is trusted by the
child only. Only the optional public GeoIP probe is forwarded through the supplied loopback proxy. Claude requests receive local fixture responses.
"""
import argparse
import gzip
import hashlib
import http.server
import json
import os
import fcntl
import pty
from pathlib import Path
import re
import ssl
import socket
import select
import subprocess
import termios
import threading
import time
import urllib.parse

ROOT=Path(__file__).resolve().parents[2]
CLAUDE=ROOT/"target/compat/claude-code-2.1.319/package/claude"
GUARD=ROOT/"native/egress/build/socket-guard"
CA_CERT=ROOT/"tests/fixtures/geoip-test-ca.pem"
CA_KEY=ROOT/"tests/fixtures/geoip-test-ca-key.pem"
DUMMY="sk-ant-wrapper-audit-dummy-no-external-value"
AUTH_HEADERS={"authorization","proxy-authorization","x-api-key","cookie","x-statsig-api-key"}

def answer_message():
    return {"id":"msg_wrapper_audit","type":"message","role":"assistant","model":"claude-sonnet-4-6",
            "content":[{"type":"text","text":"OK"}],"stop_reason":"end_turn","stop_sequence":None,
            "usage":{"input_tokens":10,"output_tokens":1}}

def stream_message(m=None):
    m=m or answer_message()
    events=[("message_start",{"type":"message_start","message":dict(m,content=[],stop_reason=None)})]
    for index,block in enumerate(m["content"]):
        if block["type"]=="tool_use":
            start=dict(block,input={})
            delta={"type":"input_json_delta","partial_json":json.dumps(block["input"])}
        else:
            start=dict(block,text="")
            delta={"type":"text_delta","text":block["text"]}
        events.extend([
          ("content_block_start",{"type":"content_block_start","index":index,"content_block":start}),
          ("content_block_delta",{"type":"content_block_delta","index":index,"delta":delta}),
          ("content_block_stop",{"type":"content_block_stop","index":index}),
        ])
    events.extend([
      ("message_delta",{"type":"message_delta","delta":{"stop_reason":m["stop_reason"],"stop_sequence":None},"usage":{"output_tokens":1}}),
      ("message_stop",{"type":"message_stop"}),
    ])
    return "".join("event: "+event+"\ndata: "+json.dumps(body)+"\n\n" for event,body in events).encode()

def safe_headers(headers):
    result={}
    errors=[]
    for key,value in headers.items():
        lower=key.lower()
        if lower in AUTH_HEADERS:
            if lower in ("authorization","x-api-key") and value not in (DUMMY,"Bearer "+DUMMY):
                errors.append(lower)
            result[lower]="<dummy>" if DUMMY in value else "<redacted>"
        else:
            result[lower]=value
    return result,errors

def context_for(server,host):
    if not re.fullmatch(r"[A-Za-z0-9.-]+",host):
        raise ValueError("Unexpected authority")
    with server.context_lock:
        if host in server.contexts:
            return server.contexts[host]
        tag=hashlib.sha256(host.encode()).hexdigest()[:16]
        prefix=server.cert_dir/tag
        key=prefix.with_suffix(".key")
        csr=prefix.with_suffix(".csr")
        cert=prefix.with_suffix(".pem")
        ext=prefix.with_suffix(".cnf")
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:"+host+"\n")
        subprocess.run(["/usr/bin/openssl","req","-new","-newkey","rsa:2048","-nodes",
            "-subj","/CN="+host,"-keyout",str(key),"-out",str(csr)],capture_output=True,check=True)
        subprocess.run(["/usr/bin/openssl","x509","-req","-in",str(csr),"-CA",str(CA_CERT),
            "-CAkey",str(CA_KEY),"-set_serial",str(int(tag,16)),"-days","2","-extfile",str(ext),"-out",str(cert)],capture_output=True,check=True)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert,key)
        context.set_alpn_protocols(["http/1.1"])
        server.contexts[host]=context
        return context

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    def log_message(self,*args):
        pass
    def do_CONNECT(self):
        host,port=self.path.rsplit(":",1)
        if self.server.probe_proxy and self.path == "api.country.is:443":
            self.server.records.append({"event":"egress-probe","authority":self.path})
            upstream=socket.create_connection(self.server.probe_proxy,timeout=8)
            try:
                upstream.sendall(b"CONNECT api.country.is:443 HTTP/1.1\r\nHost: api.country.is:443\r\n\r\n")
                head=b""
                while not head.endswith(b"\r\n\r\n") and len(head)<16384:
                    byte=upstream.recv(1)
                    if not byte:
                        raise ValueError("Probe proxy closed CONNECT")
                    head+=byte
                if not head.split(b"\r\n",1)[0].startswith(b"HTTP/1.1 200"):
                    raise ValueError("Probe proxy rejected CONNECT")
                self.send_response(200,"Connection Established")
                self.end_headers()
                sockets=[self.connection,upstream]
                while sockets:
                    ready,_,_=select.select(sockets,[],[],10)
                    if not ready:
                        break
                    for source in ready:
                        data=source.recv(65536)
                        destination=upstream if source is self.connection else self.connection
                        if not data:
                            sockets.remove(source)
                            destination.shutdown(socket.SHUT_WR)
                        else:
                            destination.sendall(data)
            finally:
                upstream.close()
                self.close_connection=True
            return
        self.server.records.append({"event":"connect","authority":self.path})
        try:
            context=context_for(self.server,host)
            self.send_response(200,"Connection Established")
            self.end_headers()
            stream=context.wrap_socket(self.connection,server_side=True)
            Handler(stream,self.client_address,self.server)
        except Exception as exc:
            self.server.records.append({"event":"tls-error","authority":self.path,"kind":type(exc).__name__,"message":str(exc)})
        self.close_connection=True
    def body(self):
        if self.headers.get("transfer-encoding","").lower()=="chunked":
            body=b""
            while True:
                size=int(self.rfile.readline().strip().split(b";")[0],16)
                if not size:
                    self.rfile.readline()
                    return body
                body+=self.rfile.read(size)
                self.rfile.read(2)
        return self.rfile.read(int(self.headers.get("content-length",0)))
    def record(self):
        body=self.body() if self.command=="POST" else b""
        if self.headers.get("content-encoding")=="gzip":
            body=gzip.decompress(body)
        try:
            data=json.loads(body) if body else None
        except Exception:
            data=body.decode(errors="replace")
        headers,unexpected=safe_headers(self.headers)
        self.server.records.append({"event":"request","method":self.command,"path":self.path,"headers":headers,"unexpected_auth":unexpected,"body":data})
        if unexpected:
            raise ValueError("Unexpected authentication header")
        return data
    def answer(self,data,status=200,kind="application/json"):
        body=data if isinstance(data,bytes) else json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type",kind)
        self.send_header("Content-Length",str(len(body)))
        self.send_header("Connection","close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection=True
    def do_GET(self):
        self.record()
        if "/models" in self.path:
            self.answer({"data":[{"id":"claude-sonnet-4-6","type":"model","display_name":"Audit model","created_at":"2026-01-01T00:00:00Z"}],"has_more":False})
        else:
            self.answer({})
    def do_POST(self):
        data=self.record()
        if "/messages/count_tokens" in self.path:
            self.answer({"input_tokens":10})
        elif "/messages" in self.path:
            message=self.server.tool_scenario.message(data) if self.server.tool_scenario else answer_message()
            self.answer(stream_message(message) if data.get("stream") else message,
                        kind="text/event-stream" if data.get("stream") else "application/json")
        elif "/initialize" in self.path:
            self.answer({"has_updates":False,"feature_gates":{},"dynamic_configs":{},"layer_configs":{},"time":int(time.time()*1000)})
        else:
            self.answer({})

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--out",required=True)
    p.add_argument("--timezone",required=True)
    p.add_argument("--locale",default="en_US.UTF-8")
    p.add_argument("--base-host")
    p.add_argument("--inherited-base-host",help="set shell routing without explicitly selecting it in a Profile")
    p.add_argument("--bare",action="store_true")
    p.add_argument("--preload")
    p.add_argument("--disable-nonessential",action="store_true")
    p.add_argument("--device-seed",default="c"*64)
    p.add_argument("--profile-device",default="a"*64)
    p.add_argument("--claude",default=str(CLAUDE))
    p.add_argument("--wrapper")
    p.add_argument("--native-dir",default=str(ROOT/"native/macos/build"))
    p.add_argument("--socket-guard",default=str(GUARD),help="test this exact guard artifact")
    p.add_argument("--probe-proxy",help="existing loopback HTTP proxy used only for the real US probe")
    p.add_argument("--profile-timezone",default="America/Los_Angeles")
    p.add_argument("--profile-root")
    p.add_argument("--interactive",action="store_true",help="exercise the terminal CLI rather than --print")
    p.add_argument("--tool-scenario",action="store_true",help="run controlled Read/Write/Bash tools inside the fixture workspace")
    p.add_argument("--project-env",action="append",default=[],help="KEY=VALUE set through the fixture project's Claude settings")
    args=p.parse_args()
    guard=Path(args.socket_guard).resolve(strict=True)
    if args.tool_scenario and (args.interactive or not args.wrapper):
        raise ValueError("Tool scenario requires the wrapper and print mode")
    out=Path(args.out).resolve()
    if args.tool_scenario and not out.is_relative_to(ROOT/"target"):
        raise ValueError("Tool scenario output must remain inside the project test output directory")
    out.mkdir(parents=True,exist_ok=True)
    for name in ("work","config","home","certs"):
        (out/name).mkdir(exist_ok=True)
    if not re.fullmatch(r"[0-9a-f]{64}", args.device_seed) or not re.fullmatch(r"[0-9a-f]{64}", args.profile_device):
        raise ValueError("Test device IDs must contain 64 lowercase hex characters")
    initial_config={"userID":args.device_seed,"hasCompletedOnboarding":True,"theme":"dark",
        "customApiKeyResponses":{"approved":[DUMMY[-20:]],"rejected":[]},
        "projects":{str(out/"work"):{"hasTrustDialogAccepted":True}}}
    (out/"config"/".claude.json").write_text(json.dumps(initial_config))
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
    server.probe_proxy=None
    if args.probe_proxy:
        parsed=urllib.parse.urlparse(args.probe_proxy)
        if parsed.scheme!="http" or parsed.hostname not in ("127.0.0.1","::1") or not parsed.port or parsed.username:
            raise ValueError("Probe forwarding requires an unauthenticated loopback HTTP proxy")
        server.probe_proxy=(parsed.hostname,parsed.port)
    server.records=[]
    server.tool_scenario=None
    if args.tool_scenario:
        from tool_scenario import ToolScenario
        server.tool_scenario=ToolScenario(out,args.profile_timezone)
    server.contexts={}
    server.context_lock=threading.Lock()
    server.cert_dir=out/"certs"
    threading.Thread(target=server.serve_forever,daemon=True).start()
    port=server.server_port
    proxy=f"http://127.0.0.1:{port}"
    env={k:os.environ[k] for k in ("PATH","TMPDIR","TERM") if k in os.environ}
    env.update({"HOME":str(out/"home"),"CLAUDE_CONFIG_DIR":str(out/"config"),
        "ANTHROPIC_API_KEY":DUMMY,"TZ":args.timezone,"LANG":args.locale,"LC_ALL":args.locale,
        "NODE_EXTRA_CA_CERTS":str(CA_CERT),"HTTP_PROXY":proxy,"HTTPS_PROXY":proxy,"ALL_PROXY":proxy,
        "http_proxy":proxy,"https_proxy":proxy,"all_proxy":proxy,"NO_PROXY":"","no_proxy":"",
        "CLAUDE_CODE_GZIP_REQUEST_BODIES":"0"})
    if args.base_host or args.inherited_base_host:
        env["ANTHROPIC_BASE_URL"]="https://"+(args.base_host or args.inherited_base_host)
    if args.disable_nonessential:
        env.update({"DISABLE_TELEMETRY":"1","DISABLE_ERROR_REPORTING":"1",
            "DISABLE_NON_ESSENTIAL_MODEL_CALLS":"1","CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC":"1","DISABLE_AUTOUPDATER":"1"})
    if args.preload:
        env.update({"BUN_OPTIONS":"--preload "+str(Path(args.preload).resolve()),
            "CLAUDE_WRAPPER_DEVICE_ID":args.profile_device})
    command=[str(guard),"--ipv4",str(port),str(Path(args.claude).resolve()),"-p","Reply exactly OK. Do not use any tools.",
        "--model","claude-sonnet-4-6","--tools","","--no-session-persistence","--setting-sources",""]
    if args.tool_scenario:
        command[command.index("-p")+1]="Run the controlled fixture tool checks requested by the local test model, then reply OK."
        command[command.index("--tools")+1]="Read,Write,Bash"
        command.append("--dangerously-skip-permissions")
    if args.project_env:
        project_env={}
        for entry in args.project_env:
            key,value=entry.split("=",1)
            if not re.fullmatch(r"[A-Z_][A-Z_0-9]*",key):
                raise ValueError("Invalid project environment key")
            project_env[key]=value
        settings=out/"work"/".claude"/"settings.json"
        settings.parent.mkdir(exist_ok=True)
        settings.write_text(json.dumps({"env":project_env}))
        command[command.index("--setting-sources")+1]="project"
    if args.bare:
        command.append("--bare")
    if args.interactive:
        command.remove("-p")
        command.remove("--no-session-persistence")
    if args.wrapper:
        if args.preload or not args.probe_proxy:
            raise ValueError("Wrapper capture requires --probe-proxy and does not accept --preload")
        wrapper=str(Path(args.wrapper).resolve())
        profiles=Path(args.profile_root).resolve() if args.profile_root else out/"profiles"
        if not profiles.is_relative_to(ROOT/"target"):
            raise ValueError("Audit profiles must remain inside the project test output directory")
        if not (profiles/"audit.toml").exists():
            subprocess.run([wrapper,"--profiles-dir",str(profiles),"profile","create","audit",
                "--timezone",args.profile_timezone,
                "--proxy",proxy,"--identity","bun","--device-id",args.profile_device],
                capture_output=True,check=True)
        client_config=profiles/"clients"/"audit"/".claude.json"
        if args.interactive and not client_config.exists():
            client_config.parent.mkdir(parents=True,exist_ok=True)
            client_config.write_text(json.dumps(dict(initial_config,userID=args.profile_device)))
        client_args=command[4:]
        command=[wrapper,"--profiles-dir",str(profiles),"run","audit",
            "--target",str(Path(args.claude).resolve()),"--native-dir",str(Path(args.native_dir).resolve()),
            "--socket-guard",str(guard),"--proxy",proxy,
            "--timezone",args.profile_timezone,"--telemetry="+str(not args.disable_nonessential).lower(),
            "--",*client_args]
        if args.base_host:
            command[command.index("--"):command.index("--")]=["--api-base-url","https://"+args.base_host]
    if server.tool_scenario:
        assets={"official_claude":Path(args.claude).resolve(),"wrapper":Path(args.wrapper).resolve(),
                "socket_guard":guard,"identity_library":Path(args.native_dir).resolve()/"libclaude-wrapper.dylib",
                "identity_preload":Path(args.native_dir).resolve()/"identity.cjs"}
        server.tool_scenario.runtime_assets={name:{"path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
            for name,path in assets.items()}
    started=time.monotonic()
    try:
        if args.interactive:
            master,slave=pty.openpty()
            fcntl.ioctl(slave,termios.TIOCSWINSZ, __import__("struct").pack("HHHH",35,120,0,0))
            def terminal_session():
                os.setsid()
                fcntl.ioctl(0,termios.TIOCSCTTY,0)
            result=subprocess.Popen(command,cwd=out/"work",env=env,stdin=slave,stdout=slave,stderr=slave,
                preexec_fn=terminal_session)
            os.close(slave)
            chunks=[]
            completed_at=None
            requested_exit=False
            fixture_terminated=False
            trusted=False
            trust_confirmation=None
            try:
                while time.monotonic()-started<40 and result.poll() is None:
                    ready,_,_=select.select([master],[],[],0.2)
                    if ready:
                        try:
                            chunk=os.read(master,65536)
                        except OSError:
                            break
                        if not chunk:
                            break
                        chunks.append(chunk)
                        with (out/"terminal.log").open("ab") as log:
                            log.write(chunk)
                    # Supply a harmless workspace-trust response only inside this empty fixture.
                    screen=b"".join(chunks[-20:])
                    plain=re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]",b"",screen)
                    compact=re.sub(rb"\s+",b"",plain)
                    if not trusted and b"Yes,Itrustthisfolder" in compact:
                        os.write(master,b"\x1b[B")
                        trust_confirmation=time.monotonic()+0.4
                        trusted=True
                        chunks.append(b"\n[fixture accepted empty workspace]\n")
                    if trust_confirmation and time.monotonic()>=trust_confirmation:
                        os.write(master,b"\r")
                        trust_confirmation=None
                    if any(x.get("event")=="request" and "/v1/messages" in x.get("path","") for x in server.records):
                        completed_at=completed_at or time.monotonic()
                        if not requested_exit and time.monotonic()-completed_at>3:
                            os.write(master,b"/exit\r")
                            requested_exit=True
                try:
                    result.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    fixture_terminated=True
                    result.terminate()
                    try:
                        result.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        result.kill()
                        result.wait(timeout=5)
            finally:
                os.close(master)
            outcome={"exit":result.returncode,"stdout":b"".join(chunks).decode(errors="replace"),
                "stderr":"","seconds":time.monotonic()-started,"fixture_terminated":fixture_terminated}
        else:
            result=subprocess.run(command,cwd=out/"work",env=env,capture_output=True,text=True,timeout=50)
            outcome={"exit":result.returncode,"stdout":result.stdout,"stderr":result.stderr,"seconds":time.monotonic()-started}
    except subprocess.TimeoutExpired as exc:
        outcome={"exit":"timeout","stdout":str(exc.stdout),"stderr":str(exc.stderr),"seconds":time.monotonic()-started}
    finally:
        server.shutdown()
    (out/"requests.json").write_text(json.dumps(server.records,ensure_ascii=False,indent=2))
    (out/"result.json").write_text(json.dumps(outcome,ensure_ascii=False,indent=2))
    summary={"out":str(out),"exit":outcome["exit"],"seconds":outcome["seconds"],"events":len(server.records)}
    if server.tool_scenario:
        report=server.tool_scenario.verify(outcome)
        (out/"tool-scenario.json").write_text(json.dumps(report,ensure_ascii=False,indent=2))
        summary["tool_scenario_passed"]=report["passed"]
    print(json.dumps(summary,ensure_ascii=False))
    if summary.get("tool_scenario_passed") is False:
        raise SystemExit(1)
if __name__=="__main__":
    main()
