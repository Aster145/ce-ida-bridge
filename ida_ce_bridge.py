# -*- coding: utf-8 -*-
"""Run once in IDA (File -> Script file). Export live samples on breakpoints."""
import builtins
import os
import tempfile
import time
import uuid

import ida_dbg
import ida_idd
import ida_kernwin

BRIDGE_DIR = os.path.join(os.environ.get("TEMP") or tempfile.gettempdir(), "CE_IDA_Bridge")
ANCHOR_FILE = os.path.join(BRIDGE_DIR, "anchor.txt")


class CEIDABridge(ida_dbg.DBG_Hooks):
    def __init__(self):
        super().__init__()
        self.timer = None
        self.active = True

    def cancel_timer(self):
        if self.timer is not None:
            ida_kernwin.unregister_timer(self.timer)
            self.timer = None

    def stop(self):
        self.active = False
        self.cancel_timer()
        self.unhook()
        print("[CE-IDA] 自动导出已停止。")

    def export(self, breakpoint_ea=None):
        if not self.active:
            return False
        try:
            if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
                raise RuntimeError("请让游戏在 IDA 中保持暂停。")
            # Use live ARM64 PC, never an IDB cursor address, for manual export.
            pc = int(ida_dbg.get_reg_val("PC")) if breakpoint_ea is None else int(breakpoint_ea)
            address = pc + 4  # Skip the ARM64 breakpoint instruction itself.
            data = None
            for size in (64, 32, 16):
                block = ida_idd.dbg_read_memory(address, size)
                if block is not None and len(block) == size:
                    data = bytes(block)
                    break
            if data is None:
                raise RuntimeError("无法读取断点后方的内存，请换一个 ARM64 代码断点。")
            if len(set(data)) < 4:
                raise RuntimeError("附近字节过于重复，请换一个代码断点。")
            lines = ["CEIDA1", uuid.uuid4().hex, str(int(time.time())),
                     "0x%X" % pc, "0x%X" % address,
                     " ".join("%02X" % value for value in data)]
            os.makedirs(BRIDGE_DIR, exist_ok=True)
            temporary = ANCHOR_FILE + ".tmp"
            with open(temporary, "w", encoding="ascii", newline="\n") as stream:
                stream.write("\n".join(lines) + "\n")
            os.replace(temporary, ANCHOR_FILE)
            print("[CE-IDA] 已导出：断点 0x%X，取样起点 0x%X，%d 字节。" % (pc, address, len(data)))
            print("[CE-IDA] CE 将自动 AOB 搜索；请保持游戏暂停直到搜索结束。")
            return True
        except Exception as error:
            print("[CE-IDA] 导出失败：%s" % error)
            return False

    def dbg_bpt(self, tid, ea):
        self.cancel_timer()
        attempts = [0]

        def deferred_export():
            attempts[0] += 1
            if not self.active:
                self.timer = None
                return -1
            if ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP:
                self.timer = None
                self.export(ea)
                return -1
            if attempts[0] >= 20:
                self.timer = None
                print("[CE-IDA] 未保持暂停，跳过本次样本。")
                return -1
            return 100

        # Read after the breakpoint event has settled into a suspended state.
        self.timer = ida_kernwin.register_timer(100, deferred_export)
        return 0

    def dbg_process_exit(self, pid, tid, ea, code):
        self.cancel_timer()

    def dbg_process_detach(self, pid, tid, ea):
        self.cancel_timer()


previous = getattr(builtins, "_ce_ida_bridge", None)
if previous is not None:
    previous.stop()
builtins._ce_ida_bridge = CEIDABridge()
if not builtins._ce_ida_bridge.hook():
    raise RuntimeError("无法安装 IDA 调试事件钩子。")


def ce_ida_export_now():
    return builtins._ce_ida_bridge.export()


def ce_ida_stop():
    builtins._ce_ida_bridge.stop()


builtins.ce_ida_export_now = ce_ida_export_now
builtins.ce_ida_stop = ce_ida_stop
print("[CE-IDA] 已就绪。断点命中后将自动导出内存样本。")
print("[CE-IDA] 当前暂停处重发：ce_ida_export_now()；停止：ce_ida_stop()")
print("[CE-IDA] 共享文件：" + ANCHOR_FILE)
if ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP:
    ce_ida_export_now()
