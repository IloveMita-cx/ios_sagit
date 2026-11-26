"""Place this directory in tools/TouchHook in the prepared ios_sagit checkout."""
from pathlib import Path
import sys

here = Path(__file__).resolve().parent
root = here.parent.parent
if not (root / "scripts/toolchain.py").is_file() or here.parent != root / "tools":
    raise SystemExit("Place the TouchHook directory under ios_sagit/tools first.")
sys.path.insert(0, str(root / "scripts"))
import toolchain

toolchain.build_iokit_client("TouchHook", [str(here / "TouchHook.mm")],
                             frameworks=["Foundation", "UIKit"], adhoc_sign=True, loadable=True)
print(toolchain.BUILD / "output/TouchHook.dylib")
