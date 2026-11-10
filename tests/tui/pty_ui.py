#!/usr/bin/env python3
"""Drive the actual TUI through a controlling PTY, without launching Claude."""
import argparse
import codecs
from collections import Counter
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import traceback
import unicodedata


ROOT=Path(__file__).resolve().parents[2]


class Screen:
    """Small VT screen reader for Crossterm cursor moves; raw bytes are retained."""
    def __init__(self, rows=42, columns=132):
        self.rows,self.columns=rows,columns
        self.cells=[[" "]*columns for _ in range(rows)]
        self.row=self.column=0
        self.saved=(0,0)
        self.pending=""
        self.decoder=codecs.getincrementaldecoder("utf-8")("replace")

    def feed(self, data):
        text=self.pending+self.decoder.decode(data)
        self.pending=""
        i=0
        while i<len(text):
            c=text[i]
            if c=="\x1b":
                if i+1>=len(text):
                    self.pending=text[i:]
                    break
                if text[i+1]=="[":
                    match=re.match(r"\x1b\[([0-?]*)([ -/]*)([@-~])",text[i:])
                    if not match:
                        self.pending=text[i:]
                        break
                    self.csi(match.group(1),match.group(3))
                    i+=len(match.group())
                    continue
                if text[i+1]=="]":
                    match=re.search(r"\x07|\x1b\\",text[i+2:])
                    if not match:
                        self.pending=text[i:]
                        break
                    i+=2+match.end()
                    continue
                if text[i+1] in "()":
                    if i+2>=len(text):
                        self.pending=text[i:]
                        break
                    i+=3
                    continue
                if text[i+1]=="7":self.saved=(self.row,self.column)
                elif text[i+1]=="8":self.row,self.column=self.saved
                i+=2
                continue
            if c=="\r":self.column=0
            elif c=="\n":self.row=min(self.rows-1,self.row+1)
            elif c=="\b":self.column=max(0,self.column-1)
            elif c=="\t":self.column=min(self.columns-1,(self.column//8+1)*8)
            elif ord(c)>=32 and c!="\x7f":
                width=0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in "WF" else 1
                if width==0:
                    if self.column:self.cells[self.row][self.column-1]+=c
                else:
                    if self.column>=self.columns:self.row=min(self.rows-1,self.row+1);self.column=0
                    self.cells[self.row][self.column]=c
                    if width==2 and self.column+1<self.columns:self.cells[self.row][self.column+1]=""
                    self.column+=width
            i+=1

    def csi(self, parameters, final):
        if parameters.startswith("?"):
            if final=="h" and "1049" in parameters.lstrip("?").split(";"):
                self.cells=[[" "]*self.columns for _ in range(self.rows)]
                self.row=self.column=0
            return
        try: values=[int(value) if value else 0 for value in parameters.split(";")]
        except ValueError:return
        n=values[0] if values else 0
        if final in "Hf":
            self.row=max(0,min(self.rows-1,(values[0] or 1)-1))
            self.column=max(0,min(self.columns-1,((values[1] if len(values)>1 else 1) or 1)-1))
        elif final=="A":self.row=max(0,self.row-(n or 1))
        elif final=="B":self.row=min(self.rows-1,self.row+(n or 1))
        elif final=="C":self.column=min(self.columns-1,self.column+(n or 1))
        elif final=="D":self.column=max(0,self.column-(n or 1))
        elif final=="G":self.column=max(0,min(self.columns-1,(n or 1)-1))
        elif final=="d":self.row=max(0,min(self.rows-1,(n or 1)-1))
        elif final=="J":
            if n in (2,3):self.cells=[[" "]*self.columns for _ in range(self.rows)]
            elif n==0:
                self.cells[self.row][self.column:]=[" "]*(self.columns-self.column)
                for row in range(self.row+1,self.rows):self.cells[row]=[" "]*self.columns
        elif final=="K":
            if n==2:self.cells[self.row]=[" "]*self.columns
            elif n==0:self.cells[self.row][self.column:]=[" "]*(self.columns-self.column)
            elif n==1:self.cells[self.row][:self.column+1]=[" "]*(self.column+1)
        elif final=="X":self.cells[self.row][self.column:min(self.columns,self.column+(n or 1))]=[" "]*min(n or 1,self.columns-self.column)
        elif final=="s":self.saved=(self.row,self.column)
        elif final=="u":self.row,self.column=self.saved

    def text(self):
        return "\n".join("".join(row).rstrip() for row in self.cells).rstrip()+"\n"


def attribute_json(attrs):
    return [item if not isinstance(item,list) else [value.hex() if isinstance(value,bytes) else value for value in item] for item in attrs]


class KeptSession:
    """Popen-like view of the UI grandchild, with a persistent session leader."""
    def __init__(self, command, cwd, env, slave, error_slave):
        self.status_fd,status_write=os.pipe()
        ack_read,self.ack_fd=os.pipe()
        self.pending=b""
        self.pid=None
        self.returncode=None
        def controlling_terminal():
            os.setsid()
            fcntl.ioctl(0,termios.TIOCSCTTY,0)
        self.keeper=subprocess.Popen([sys.executable,str(Path(__file__).with_name("pty_keeper.py")),
            str(status_write),str(ack_read),*command],cwd=cwd,env=env,
            stdin=slave,stdout=slave,stderr=error_slave,preexec_fn=controlling_terminal,
            pass_fds=(status_write,ack_read))
        os.close(status_write)
        os.close(ack_read)
        deadline=time.monotonic()+5
        while self.pid is None and time.monotonic()<deadline:
            self.read_status(.05)
            if self.keeper.poll() is not None:break
        require(self.pid is not None,"Terminal keeper did not start the UI")

    def read_status(self, timeout=0):
        if not select.select([self.status_fd],[],[],timeout)[0]:return
        self.pending+=os.read(self.status_fd,65536)
        while b"\n" in self.pending:
            line,self.pending=self.pending.split(b"\n",1)
            event=json.loads(line)
            if event["event"]=="started":self.pid=event["pid"]
            elif event["event"]=="exit":self.returncode=event["code"]

    def poll(self):
        self.read_status()
        return self.returncode

    def wait(self, timeout):
        deadline=time.monotonic()+timeout
        while self.poll() is None and time.monotonic()<deadline:self.read_status(.02)
        if self.returncode is None:raise subprocess.TimeoutExpired("TUI",timeout)
        return self.returncode

    def kill(self):
        if self.poll() is None:os.kill(self.pid,signal.SIGKILL)

    def release(self):
        try:os.write(self.ack_fd,b"1")
        except BrokenPipeError:pass
        os.close(self.ack_fd)
        try:self.keeper.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.keeper.kill()
            self.keeper.wait(timeout=2)
        os.close(self.status_fd)


class TerminalRun:
    def __init__(self, binary, fixture, output, arguments=(), rows=42, columns=132, profiles_dir=None):
        self.output=output
        output.mkdir(parents=True)
        self.master,self.slave=pty.openpty()
        self.error_master,self.error_slave=pty.openpty()
        for fd in (self.slave,self.error_slave):
            fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack("HHHH",rows,columns,0,0))
        self.before=termios.tcgetattr(self.slave)
        self.error_before=termios.tcgetattr(self.error_slave)
        self.screens={self.master:Screen(rows,columns),self.error_master:Screen(rows,columns)}
        self.raw={self.master:bytearray(),self.error_master:bytearray()}
        self.closed=False
        self.events=[]
        self.snapshots=[]
        self.started=time.monotonic()
        self.fixture=fixture
        env={"HOME":str(fixture/"home"),"PATH":str(fixture/"bin")+":/usr/bin:/bin:/usr/sbin:/sbin",
             "TERM":"xterm-256color","LANG":"en_US.UTF-8","LC_ALL":"en_US.UTF-8",
             "TMPDIR":str(fixture/"tmp")+"/","TUI_QA_CLIENT_LOG":str(fixture/"unexpected-client.log")}
        command=[str(binary),"--profiles-dir",str(profiles_dir if profiles_dir is not None else fixture/"profiles"),*arguments]
        self.process=KeptSession(command,fixture/"work",env,self.slave,self.error_slave)
        (output/"command.json").write_text(json.dumps({"command":command,"stdio_tty":True,
            "rows":rows,"columns":columns,
            "controlling_session_keeper":self.process.keeper.pid,"ui_pid":self.process.pid,
            "binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest()},indent=2))

    def pump(self, seconds=.15):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            ready,_,_=select.select(list(self.screens),[],[],min(.05,max(0,end-time.monotonic())))
            for fd in ready:
                try: data=os.read(fd,65536)
                except OSError as exc:
                    if exc.errno==errno.EIO:continue
                    raise
                self.raw[fd].extend(data)
                self.screens[fd].feed(data)

    def wait_text(self, expected, timeout=5):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            self.pump(.08)
            text=self.screens[self.master].text()
            if all(part in text for part in expected):return text
            if self.process.poll() is not None:break
        self.snapshot("failure-screen")
        raise AssertionError("Screen did not contain: "+repr(expected)+"; exit="+str(self.process.poll()))

    def key(self, value):
        data=value.encode() if isinstance(value,str) else value
        self.events.append({"seconds":time.monotonic()-self.started,"input_hex":data.hex()})
        os.write(self.master,data)
        self.pump()

    def snapshot(self, name):
        self.pump(.08)
        (self.output/(name+".txt")).write_text(self.screens[self.master].text())
        (self.output/(name+".stderr.txt")).write_text(self.screens[self.error_master].text())
        self.snapshots.append({"name":name,"stdout_bytes":len(self.raw[self.master]),
            "stderr_bytes":len(self.raw[self.error_master]),"rows":self.screens[self.master].rows,
            "columns":self.screens[self.master].columns})
        (self.output/"snapshot-index.json").write_text(json.dumps(self.snapshots,indent=2))

    def exit(self, keys=None, signum=None):
        if keys is not None:self.key(keys)
        if signum is not None:
            self.events.append({"seconds":time.monotonic()-self.started,"signal":signal.Signals(signum).name})
            os.kill(self.process.pid,signum)
        end=time.monotonic()+5
        while self.process.poll() is None and time.monotonic()<end:self.pump(.1)
        if self.process.poll() is None:raise AssertionError("TUI did not exit")
        self.pump(.2)
        return self.finish()

    def finish(self):
        if self.closed:return self.result
        forced=False
        if self.process.poll() is None:
            self.key(b"\x1b")
            self.key("q")
            try:self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                forced=True
                self.process.kill()
                self.process.wait(timeout=2)
        self.pump(.1)
        stdout=bytes(self.raw[self.master])
        stderr=bytes(self.raw[self.error_master])
        (self.output/"stdout.ansi.bin").write_bytes(stdout)
        (self.output/"stderr.ansi.bin").write_bytes(stderr)
        (self.output/"input-events.json").write_text(json.dumps(self.events,indent=2))
        after=termios.tcgetattr(self.slave)
        error_after=termios.tcgetattr(self.error_slave)
        sequence=re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]|\x1b[^\[]")
        escapes=lambda data:{repr(item):count for item,count in Counter(sequence.findall(data)).items()}
        self.result={"exit":self.process.returncode,"forced_cleanup":forced,
            "termios_restored":self.before==after,"stderr_termios_restored":self.error_before==error_after,
            "termios_before":attribute_json(self.before),"termios_after":attribute_json(after),
            "stderr_before":attribute_json(self.error_before),"stderr_after":attribute_json(error_after),
            "stdout_bytes":len(stdout),"stderr_bytes":len(stderr),
            "stdout_escape_sequences":escapes(stdout),"stderr_escape_sequences":escapes(stderr),
            "alternate_screen_entered":b"\x1b[?1049h" in stdout,
            "alternate_screen_left":b"\x1b[?1049l" in stdout,
            "stderr_raw_hex":stderr.hex(),
            "literal_escape_notation_absent":b"\\x1b[" not in stdout and b"\\033[" not in stdout}
        (self.output/"terminal-result.json").write_text(json.dumps(self.result,indent=2))
        self.process.release()
        for fd in (self.master,self.slave,self.error_master,self.error_slave):os.close(fd)
        self.closed=True
        return self.result


def read_profile(path):
    # Generated fields used by this test are simple JSON-compatible TOML values.
    values={}
    for line in path.read_text().splitlines():
        match=re.fullmatch(r"([A-Za-z_][A-Za-z_0-9]*)\s*=\s*(.+)",line)
        if match:
            try:values[match[1]]=json.loads(match[2])
            except ValueError:pass
    return values


def require(condition, message):
    if not condition:raise AssertionError(message)


def form_value(ui, value):
    ui.key(b"\x15")
    ui.key(value)


def select_profile(ui, name):
    names=sorted(path.stem for path in (ui.fixture/"profiles").glob("*.toml"))
    ui.key(b"\x1b[A"*max(3,len(names)+1))
    ui.key(b"\x1b[B"*names.index(name))


def exercise_management(binary, fixture, out, rows=42, columns=132):
    ui=TerminalRun(binary,fixture,out,rows=rows,columns=columns)
    checks={}
    try:
        ui.wait_text(["Claude 环境工作台"])
        ui.snapshot("01-initial-empty")
        checks["initial_real_tty_screen"]=True
        ui.key("?")
        ui.wait_text(["帮助"])
        ui.snapshot("02-keyboard-help")
        ui.key(b"\x1b")
        ui.key("p")
        ui.wait_text(["美国预设"])
        ui.snapshot("02a-empty-presets")
        ui.key(b"\r")
        ui.wait_text(["新建配置"])
        ui.key(b"\x1b")
        require(not list((fixture/"profiles").glob("*.toml")),"Cancelling preset creation saved a Profile")
        checks["empty_preset_creation_can_cancel"]=True
        ui.key("n")
        screen = ui.wait_text(["新建配置", "配置名", "时区", "自动固定", "2–30 秒"])
        require("主机名" not in screen and "用户名" not in screen,"Retired alias fields are still visible")
        ui.snapshot("03-new-form")
        for index,value in enumerate(("qa-west","America/Los_Angeles")):
            if index:ui.key(b"\x1b[B")
            form_value(ui,value)
        ui.key(b"\x1b[B"*5)
        ui.key(b"\r")
        ui.wait_text(["选择固定出口方式", "仅校验地区", "自动固定", "手动输入"])
        ui.key(b"\x1b[B\r")
        ui.wait_text(["手动输入出口"])
        form_value(ui,"8.8.8")
        ui.key(b"\r")
        ui.wait_text(["地址格式无效"])
        form_value(ui,"8.8.8.8")
        ui.key(b"\r")
        ui.wait_text(["新建配置", "8.8.8.8"])
        ui.key(b"\x1b[B\r")
        ui.wait_text(["选择出口地区", "搜索代码或名称"])
        form_value(ui,"zz")
        ui.key(b"\r")
        ui.wait_text(["没有匹配地区"])
        form_value(ui,"Japan")
        ui.wait_text(["JP", "日本", "Japan"])
        ui.key(b"\r")
        ui.wait_text(["新建配置", "JP", "日本"])
        ui.key(b"\r")
        form_value(ui,"ca")
        ui.wait_text(["CA", "加拿大", "Canada"])
        ui.key(b"\x1b")
        ui.key(b"\x1b[B\r")
        ui.wait_text(["选择出口复查间隔", "30 秒", "自定义秒数"])
        ui.key(b"\x1b[B\r")
        ui.wait_text(["自定义检查间隔"])
        form_value(ui,"0")
        ui.key(b"\r")
        ui.wait_text(["自定义检查间隔", "秒之间的整数"])
        form_value(ui,"45")
        ui.key(b"\r")
        ui.wait_text(["新建配置", "45 秒"])
        ui.key(b"\x13")
        end=time.monotonic()+3
        profile=fixture/"profiles"/"qa-west.toml"
        while not profile.exists() and time.monotonic()<end:ui.pump(.1)
        require(profile.exists(),"N form did not save the Profile")
        original=read_profile(profile)
        require(re.fullmatch(r"[0-9a-f]{64}",original.get("device_id","")),"New device ID is invalid")
        require(original.get("expected_exit_ip")=="8.8.8.8","Fixed exit IP did not round-trip through the form")
        require(original.get("expected_exit_country")=="JP","Exit country did not round-trip through the form")
        require(original.get("exit_check_interval_seconds")==45,"Custom interval did not round-trip through the form")
        require("hostname" not in original and "username" not in original,"Retired aliases were saved")
        ui.wait_text(["★ qa-west"])
        ui.snapshot("04-profile-saved")
        checks["create_form_saved_native_toml"]=True
        checks["exit_pickers_reject_typos_and_preserve_selection_on_cancel"]=True
        checks["exit_interval_validated_before_form_save"]=True
        checks["single_profile_marked_as_default"]=True
        ui.key("e")
        ui.wait_text(["编辑配置","时区"])
        ui.key(b"\x1b[B\x1b[A\x1b[B")
        form_value(ui,"America/Chicago")
        ui.key(b"\x13")
        ui.wait_text(["已保存"])
        edited=read_profile(profile)
        require(edited.get("timezone")=="America/Chicago","Edit did not save timezone")
        require(edited.get("device_id")==original["device_id"],"Edit changed the device ID")
        ui.snapshot("05-edited-timezone")
        checks["edit_kept_device_id"]=True
        ui.key("p")
        ui.wait_text(["美国预设"])
        ui.snapshot("06-us-presets")
        # Protocol: a selected Profile receives the preset atomically.
        ui.key(b"\x1b[A"*3+b"\x1b[B"*2)
        ui.key(b"\r")
        end=time.monotonic()+3
        while read_profile(profile).get("timezone")!="America/New_York" and time.monotonic()<end:ui.pump(.1)
        preset=read_profile(profile)
        require(preset.get("timezone")=="America/New_York","US east preset was not applied")
        require(preset.get("device_id")==original["device_id"],"Preset changed existing device ID")
        ui.snapshot("07-preset-applied")
        checks["us_preset_selected"]=True
        ui.key("e")
        ui.wait_text(["编辑配置"])
        ui.key(b"\x1b[B"*6+b"\r")
        ui.wait_text(["选择固定出口方式"])
        ui.key(b"\x1b[A\r")
        ui.key(b"\x1b[B"*2+b"\r")
        ui.wait_text(["选择出口复查间隔", "流量高时更频繁"])
        ui.key(b"\x1b[A\r")
        ui.key(b"\x13")
        ui.wait_text(["待学习"])
        require(read_profile(profile).get("expected_exit_ip")=="auto","Picker did not select automatic pinning")
        require(read_profile(profile).get("exit_check_interval_seconds")=="auto","Picker did not select adaptive checks")
        pin=fixture/"profiles"/".exit-pin-qa-west"
        pin.write_text("8.8.8.8\n")
        ui.key("r")
        ui.wait_text(["重置自动出口"])
        ui.key(b"\x1b")
        require(pin.exists(),"Cancelling reset cleared the pin")
        ui.key("r")
        ui.key(b"\r")
        ui.wait_text(["已重置自动出口"])
        require(not pin.exists(),"Reset left the automatic pin behind")
        checks["automatic_exit_reset_can_be_cancelled_and_confirmed"]=True
        ui.key("l")
        ui.wait_text(["Wrapper Logs", "[Exit]", "Auto-pin cleared. Waiting for a new probe."])
        ui.key(b"\x1b[D")
        ui.wait_text(["[Exit]", "Auto-pin cleared. Waiting for a new probe."])
        ui.key(b"\x1b")
        ui.key("c")
        ui.wait_text(["复制配置"])
        form_value(ui,"qa-copy")
        ui.key(b"\r")
        screen = ui.wait_text(["已复制"])
        require("★ qa-west" not in screen and "★ qa-copy" not in screen,
                "No Profile should be marked by default when multiple Profiles are unpinned")
        copied_path=fixture/"profiles"/"qa-copy.toml"
        require(copied_path.exists(),"Copy did not create Profile")
        copied=read_profile(copied_path)
        require(re.fullmatch(r"[0-9a-f]{64}",copied.get("device_id","")),"Copied device ID is invalid")
        require(copied["device_id"]!=original["device_id"],"Copy reused source device ID")
        client=fixture/"profiles"/"clients"/"qa-copy"/".claude.json"
        client.parent.mkdir(parents=True)
        client_content=json.dumps({"userID":copied["device_id"],"fixture":"preserve-client-state"})
        client.write_text(client_content)
        ui.snapshot("08-profile-copied")
        checks["copy_has_new_device_id"]=True
        select_profile(ui,"qa-copy")
        ui.key("d")
        ui.wait_text(["删除配置","qa-copy"])
        ui.snapshot("09-delete-confirmation")
        ui.key(b"\x1b")
        require(copied_path.exists(),"Cancel deleted the Profile")
        ui.key("d")
        ui.wait_text(["删除配置","qa-copy"])
        ui.key("y")
        ui.wait_text(["已删除"])
        require(not copied_path.exists(),"Delete confirmation did not remove Profile")
        require(client.read_text()==client_content,"Delete removed or changed retained client state")
        require(profile.exists() and read_profile(profile)["device_id"]==original["device_id"],"Delete affected another Profile")
        ui.snapshot("10-delete-kept-client-state")
        checks["delete_cancel_and_confirm"]=True
        checks["delete_retained_client_state"]=True
        terminal=ui.exit(keys="q")
        checks["q_exit_zero"]=terminal["exit"]==0
        checks["all_termios_fields_restored"]=terminal["termios_restored"] and terminal["stderr_termios_restored"]
        checks["actual_ansi_screen_entered_and_left"]=terminal["alternate_screen_entered"] and terminal["alternate_screen_left"]
        checks["literal_escape_notation_absent"]=terminal["literal_escape_notation_absent"]
        checks["no_client_was_executed"]=not (fixture/"unexpected-client.log").exists()
        require(all(checks.values()),"Terminal cleanup or safety check failed")
        return {"passed":True,"checks":checks,"terminal":terminal}
    finally:
        ui.finish()


def exercise_exit(binary, fixture, out, signum=None, control_c=False):
    ui=TerminalRun(binary,fixture,out,("ui",))
    try:
        ui.wait_text(["Claude 环境工作台"])
        ui.snapshot("initial")
        result=ui.exit(keys=b"\x03" if control_c else None,signum=signum)
        expected=130 if control_c else 128+int(signum)
        require(result["exit"]==expected,"Signal exit code was not "+str(expected))
        require(result["termios_restored"] and result["stderr_termios_restored"],"Signal exit left terminal attributes changed")
        require(result["alternate_screen_entered"] and result["alternate_screen_left"],"Signal exit left alternate screen")
        require(not result["forced_cleanup"],"Signal exit required forced cleanup")
        require(not (fixture/"unexpected-client.log").exists(),"TUI unexpectedly executed a client")
        return {"passed":True,"terminal":result}
    finally:
        ui.finish()


def exercise_narrow(binary, fixture, out):
    ui=TerminalRun(binary,fixture,out,("ui",),rows=24,columns=80)
    try:
        ui.wait_text(["Claude 环境工作台"])
        ui.snapshot("80x24-initial")
        before=sorted(path.name for path in (fixture/"profiles").glob("*.toml"))
        ui.key("n")
        ui.wait_text(["新建配置"])
        ui.snapshot("80x24-new-form")
        ui.key(b"\x1b")
        require(sorted(path.name for path in (fixture/"profiles").glob("*.toml"))==before,"Narrow form cancel persisted a Profile")
        result=ui.exit(keys="q")
        require(result["exit"]==0 and result["termios_restored"] and result["stderr_termios_restored"],"Narrow terminal exit was not clean")
        require(result["alternate_screen_entered"] and result["alternate_screen_left"],"Narrow terminal screen mode was not restored")
        return {"passed":True,"terminal":result}
    finally:
        ui.finish()


def exercise_handoff(binary, fixture, out):
    """Reach the same exit preflight from H, Enter, and the saved default."""
    name = "qa-handoff"
    device_id = "f" * 64
    profiles = fixture / "profiles"
    with socket.socket() as proxy:
        proxy.bind(("127.0.0.1", 0))
        proxy.listen(1)
        proxy.settimeout(6)
        port = proxy.getsockname()[1]
        profile = (
            'timezone = "America/Los_Angeles"\nlocale = "en_US.UTF-8"\n'
            'identity = "env"\nnetwork = "proxy-env"\n'
            f'proxy_url = "http://127.0.0.1:{port}"\ndevice_id = "{device_id}"\n'
        )
        (profiles / f"{name}.toml").write_text(profile)
        (profiles / "aaa-other.toml").write_text(profile.replace(device_id, "e" * 64))
        requests = []
        proxy_errors = []

        def reject_probes():
            try:
                for _ in range(3):
                    connection, _ = proxy.accept()
                    with connection:
                        connection.settimeout(2)
                        received = bytearray()
                        while b"\r\n\r\n" not in received and len(received) < 4096:
                            part = connection.recv(1024)
                            if not part:
                                break
                            received.extend(part)
                        requests.append(bytes(received).split(b"\r\n", 1)[0])
                        connection.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError as error:
                proxy_errors.append(str(error))

        ui = TerminalRun(binary, fixture, out / "interactive", ("ui",), profiles_dir="../profiles")
        try:
            screen = ui.wait_text(["Claude 环境工作台", name])
            require("J 项目" not in screen, "Removed project shortcut is still shown")
            select_profile(ui, name)
            ui.key("j")
            ui.wait_text(["Claude 环境工作台", name])
            require("项目目录" not in ui.screens[ui.master].text(), "J still opens a project prompt")
            ui.key("s")
            ui.wait_text(["已设为默认", f"★ {name}"])
            require((profiles / ".default-profile").read_text() == name + "\n",
                    "S did not persist the selected Profile as the default")
            select_profile(ui, "aaa-other")
            ui.wait_text(["›   aaa-other", f"★ {name}"])
            ui.snapshot("saved-default")
            select_profile(ui, name)
            worker = threading.Thread(target=reject_probes, daemon=True)
            worker.start()
            state = profiles / "clients" / name / ".claude.json"
            ui.key("h")
            ui.wait_text(["出口探测服务连接失败", "API 未执行"])
            ui.snapshot("health-probe-failed")
            require(not state.exists(), "H created Claude configuration state")
            require(not (fixture / "unexpected-client.log").exists(), "H launched Claude")
            terminal = ui.exit(keys=b"\r")
            require(state.is_file() and json.loads(state.read_text())["userID"] == device_id,
                    "TUI handoff did not resolve the relative Profile directory")
            require(terminal["exit"] == 1 and terminal["termios_restored"] and terminal["stderr_termios_restored"],
                    "Rejected launch did not restore terminal attributes and return the expected error")
            require(terminal["alternate_screen_left"] and not terminal["forced_cleanup"],
                    "Launch handoff did not leave the alternate screen")
        finally:
            ui.finish()

        # A fresh process must resolve the saved Profile even with another Profile first in the list.
        state.unlink()
        direct = TerminalRun(binary, fixture, out / "direct", ("start", "--", "--version"),
                             profiles_dir="../profiles")
        try:
            direct_terminal = direct.exit()
            worker.join(timeout=7)
            require(direct_terminal["exit"] == 1 and not direct_terminal["forced_cleanup"],
                    "Direct start did not return the rejected probe error")
            require(not direct_terminal["alternate_screen_entered"] and not direct_terminal["alternate_screen_left"],
                    "Direct start opened the TUI")
            require(direct_terminal["termios_restored"] and direct_terminal["stderr_termios_restored"],
                    "Direct start changed terminal attributes")
            require(state.is_file() and json.loads(state.read_text())["userID"] == device_id,
                    "Direct start did not use the saved default Profile")
            require(requests == [b"CONNECT api.country.is:443 HTTP/1.1"] * 3 and not proxy_errors,
                    "H, Enter, and direct start must each contact the owned proxy")
            require(not (fixture / "unexpected-client.log").exists(), "Client started after the probe was rejected")
            logs = TerminalRun(binary, fixture, out / "logs", ("ui",), rows=24, columns=80)
            try:
                logs.wait_text(["Claude 环境工作台"])
                logs.key("l")
                logs.wait_text(["Wrapper Logs", "[Error]", "Network - exit probe failed"])
                logs.key(b"\x1b[C")
                logs.wait_text(["No entries in this category."])
                logs.key(b"\x1b[C")
                logs.wait_text(["[Error]", "Network - exit probe failed"])
                logs.snapshot("classified-errors")
                logs.key(b"\x1b")
                require(logs.exit(keys="q")["exit"] == 0, "Log view did not close cleanly")
            finally:
                logs.finish()
            return {"passed": True, "terminal": terminal, "direct_terminal": direct_terminal,
                    "local_probes": [request.decode() for request in requests],
                    "relative_profile_directory_preserved": True, "default_profile_persisted": True,
                    "default_marker_follows_profile_not_selection": True,
                    "health_result_visible_without_launch": True,
                    "outside_tui_errors_visible_and_filterable": True,
                    "client_started": False, "public_network": False}
        finally:
            direct.finish()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--binary",default=str(ROOT/"target/debug/claude-wrapper"))
    parser.add_argument("--node",help="optional Node executable for testing an npm bin entry under the same clean PATH")
    parser.add_argument("--out",required=True)
    parser.add_argument("--case",action="append",choices=("management","ctrl-c-key","narrow-80x24","handoff","SIGINT","SIGTERM","SIGHUP"))
    parser.add_argument("--rows",type=int,default=42,help="management-case terminal rows")
    parser.add_argument("--columns",type=int,default=132,help="management-case terminal columns")
    args=parser.parse_args()
    # Keep an installed npm bin symlink in the actual exec path so the package's
    # own path resolution is exercised; read_bytes/stat still follow its target.
    binary=Path(os.path.abspath(args.binary))
    require(binary.is_file() and os.access(binary,os.X_OK),"TUI entry must be an executable file")
    require(args.rows>=18 and args.columns>=60,"Management terminal must be at least 60x18")
    out=Path(args.out).resolve()
    require(out.is_relative_to(ROOT/"target"),"Use an output directory inside target/")
    out.mkdir(parents=True,exist_ok=True)
    fixture=Path(tempfile.mkdtemp(prefix="owned-fixture-",dir=out))
    for name in ("home","profiles","bin","tmp","work"):(fixture/name).mkdir()
    stub=fixture/"bin"/"claude"
    stub.write_text('#!/bin/sh\nprintf "unexpected client execution\\n" >> "$TUI_QA_CLIENT_LOG"\nexit 97\n')
    stub.chmod(0o755)
    if args.node:
        node=Path(args.node).resolve()
        require(node.is_file() and os.access(node,os.X_OK),"Node must be an executable file")
        (fixture/"bin"/"node").symlink_to(node)
    report={"fixture":str(fixture),"binary":str(binary),"cases":{},
        "scope":"Real controlling PTY, owned temporary HOME/profiles, no client session/model/account/public network requested. H, Enter, and direct start use a rejecting local proxy."}
    cases=[("management",lambda:exercise_management(binary,fixture,out/"management",args.rows,args.columns)),
           ("ctrl-c-key",lambda:exercise_exit(binary,fixture,out/"ctrl-c-key",control_c=True)),
           ("narrow-80x24",lambda:exercise_narrow(binary,fixture,out/"narrow-80x24")),
           ("handoff",lambda:exercise_handoff(binary,fixture,out/"handoff"))]
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
        cases.append((sig.name,lambda sig=sig:exercise_exit(binary,fixture,out/sig.name,signum=sig)))
    if args.case:cases=[case for case in cases if case[0] in args.case]
    for name,run in cases:
        try:report["cases"][name]=run()
        except Exception as exc:
            report["cases"][name]={"passed":False,"error":str(exc),"traceback":traceback.format_exc()}
        (out/"summary.json").write_text(json.dumps(report,ensure_ascii=False,indent=2))
    report["passed"]=all(case["passed"] for case in report["cases"].values())
    (out/"summary.json").write_text(json.dumps(report,ensure_ascii=False,indent=2))
    print(json.dumps({"out":str(out),"passed":report["passed"],"cases":{name:case["passed"] for name,case in report["cases"].items()}},ensure_ascii=False))
    raise SystemExit(0 if report["passed"] else 1)


if __name__=="__main__":main()
