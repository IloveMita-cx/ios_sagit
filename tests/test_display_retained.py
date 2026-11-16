"""Retained display publication, endian encoding and nonfatal commit boundaries."""
import copy
import importlib.util
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bridge_retained', ROOT/'scripts/build-bridge.py')
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)

def node(name, compatible=b'', children=None, **props):
    return dict(name=name, props=dict(compatible=compatible, **props), children=children or [])

def fixture():
    panel = node('panel@0', b'qcom,dsi-panel\0', reg=bytes(4))
    dsi = node('dsi@c994000', b'qcom,msm8998-dsi-ctrl\0', [panel],
               reg=struct.pack('>4I', 0, 0xc994000, 0, 0x400))
    dsi['props'].update({'#address-cells':struct.pack('>I',1), '#size-cells':bytes(4)})
    dpu = node('display-controller@c901000', b'qcom,msm8998-dpu\0')
    other = node('existing', phandle=struct.pack('>I',17))
    soc = node('soc', children=[dpu, dsi, other])
    soc['props'].update({'#address-cells':struct.pack('>I',2), '#size-cells':struct.pack('>I',2)})
    tree = node('', b'qcom,msm8998\0', [node('chosen'),soc])
    return tree, dpu, dsi, panel

def decode(blob):
    out=[]
    def walk(pos):
        np,nc=struct.unpack_from('<II',blob,pos); pos+=8; props={}
        for _ in range(np):
            key=blob[pos:pos+32].split(b'\0',1)[0].decode(); size=struct.unpack_from('<I',blob,pos+32)[0]
            pos+=36; props[key]=blob[pos:pos+size]; pos+=(size+3)&~3
        out.append(props)
        for _ in range(nc): pos=walk(pos)
        return pos
    assert walk(0)==len(blob)
    return out

class RetainedDisplay(unittest.TestCase):
    def test_slots_phandle_and_encoding(self):
        tree,dpu,dsi,panel=fixture()
        bridge.configure_display_handoff(tree,ROOT/'tools/display-handoff.json',disable_backlight=True)
        handle=struct.unpack('>I',panel['props']['phandle'])[0]
        self.assertEqual(handle,18)
        self.assertEqual(dsi['props']['qcom,dsi-panel'],panel['props']['phandle'])
        self.assertEqual(dpu['props']['display-panel'],bytes(4))
        for key in ('qcom,dsi-handoff-version','qcom,dsi-handoff-flags','dsi-lanes',
                    'qcom,dsi-byte-clock-hz','qcom,dsi-escape-clock-hz','qcom,dsi-bridge-status'):
            self.assertEqual(dsi['props'][key],bytes(4))
        encoded=decode(bridge.apple_dt(tree))
        encoded_dsi=next(p for p in encoded if p['name']==b'dsi@c994000\0')
        encoded_panel=next(p for p in encoded if p['name']==b'panel@0\0')
        self.assertEqual(encoded_dsi['qcom,dsi-panel'],struct.pack('<I',handle))
        self.assertEqual(encoded_panel['AAPL,phandle'],struct.pack('<I',handle))
        self.assertEqual(encoded_panel['panel-handoff-version'],bytes(4))
        # Reconfiguring an existing tree must preserve the same identifier.
        bridge.configure_display_handoff(tree,ROOT/'tools/display-handoff.json',disable_backlight=True)
        self.assertEqual(panel['props']['phandle'],struct.pack('>I',handle))

    def test_reject_ambiguous_panel(self):
        tree,_,dsi,panel=fixture(); dsi['children'].append(copy.deepcopy(panel))
        with self.assertRaises(ValueError):
            bridge.configure_display_handoff(tree,ROOT/'tools/display-handoff.json',disable_backlight=True)

    def test_nonfatal_runtime_publication(self):
        compiler=shutil.which('c++') or shutil.which('clang++')
        if not compiler: self.skipTest('C++ host compiler unavailable; required in CI')
        source=(ROOT/'boot/bridge/display_handoff.c').read_text()
        # Execute the actual publication function against a mock DT and MMIO.
        start=source.index('static void write32(')
        end=source.index('int bridge_display_takeover(void)',start)
        program=r'''
#include <cassert>
#include <cstdint>
#include <map>
#include <string>
#include <vector>
static std::map<std::string,std::vector<unsigned char>> props;
static uint32_t intf=1,dsi_byte_hz=100000000,dsi_escape_hz=19200000,dsi_clock_valid=3;
static uint32_t control=0x1f5, status=0;
static void *display_tree=(void*)1;
static std::string key(const char *n,const char *p) { return std::string(n)+"/"+p; }
static void *dt_property(void *,const char *n,const char *p,uint32_t *size) {
    auto it=props.find(key(n,p)); *size=it==props.end()?0:it->second.size();
    return *size?it->second.data():nullptr;
}
static void *dt_find_phandle(void *,uint32_t id) { return id==18?(void*)2:nullptr; }
static unsigned char *dt_node_property(void *,const char *p,uint32_t *size) {
    return (unsigned char*)dt_property(nullptr,"panel@0",p,size);
}
static uint32_t rd(uint64_t address) {
    switch(address-0xc994000) {
        case 0: return 0x20000000; case 4: return control; case 8: return status;
        case 0x1f0: return 0; case 0x1f4: return 0x03000104;
        default: assert(false); return 0;
    }
}
static void bridge_puts(const char *) {}
static void bridge_hex(uint64_t) {}
''' + source[start:end] + r'''
static uint32_t get(const char *n,const char *p) { return read32(props.at(key(n,p)).data()); }
static void setup() {
    props.clear(); intf=1; control=0x1f5; status=0;
    for(auto k:{"qcom,dsi-handoff-version","qcom,dsi-handoff-flags","dsi-lanes",
        "qcom,dsi-byte-clock-hz","qcom,dsi-escape-clock-hz","qcom,dsi-clock-valid-mask",
        "qcom,dsi-retained-control","qcom,dsi-panel","qcom,dsi-bridge-status"})
        props[key("dsi@c994000",k)] = std::vector<unsigned char>(4);
    props[key("dsi@c994000","qcom,dsi-panel")][0]=18;
    for(auto k:{"panel-handoff-version","panel-handoff-flags"})
        props[key("panel@0",k)] = std::vector<unsigned char>(4);
    props[key("display-controller@c901000","display-panel")]=std::vector<unsigned char>(4);
}
int main() {
    setup(); retain_dsi();
    assert(get("dsi@c994000","qcom,dsi-bridge-status")==1);
    assert(get("dsi@c994000","qcom,dsi-handoff-version")==2);
    assert(get("dsi@c994000","qcom,dsi-handoff-flags")==64);
    assert(get("dsi@c994000","dsi-lanes")==4);
    assert(get("dsi@c994000","qcom,dsi-byte-clock-hz")==100000000);
    assert(get("panel@0","panel-handoff-flags")==3);
    assert(get("display-controller@c901000","display-panel")==18);
    setup(); auto original=props;
    for(auto &item:original) {
        setup(); props.erase(item.first); retain_dsi();
        if(props.count(key("dsi@c994000","qcom,dsi-handoff-version")))
            assert(get("dsi@c994000","qcom,dsi-handoff-version")==0);
        if(props.count(key("panel@0","panel-handoff-version")))
            assert(get("panel@0","panel-handoff-version")==0);
        setup(); props[item.first].resize(8); retain_dsi();
        assert(get("dsi@c994000","qcom,dsi-handoff-version")==0);
    }
    setup(); control=0x151; retain_dsi(); // Sparse lanes are not guessed.
    assert(get("dsi@c994000","qcom,dsi-bridge-status")==3);
    setup(); status=2; retain_dsi(); // Existing command DMA cannot be adopted.
    assert(get("dsi@c994000","qcom,dsi-handoff-version")==0);
    setup(); dsi_byte_hz=dsi_escape_hz=dsi_clock_valid=0; retain_dsi();
    assert(get("dsi@c994000","qcom,dsi-bridge-status")==1);
    assert(get("dsi@c994000","qcom,dsi-byte-clock-hz")==0);
    setup(); intf=2; retain_dsi(); // No active-interface slots: nonfatal, no commit.
    assert(get("dsi@c994000","qcom,dsi-handoff-version")==0);
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory); (p/'test.cpp').write_text(program)
            subprocess.run([compiler,'-std=c++17','-Wall','-Wextra','-Werror',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
            subprocess.run([str(p/'test')],check=True)

if __name__=='__main__': unittest.main()
