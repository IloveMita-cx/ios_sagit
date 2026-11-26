"""Place this directory in tools/TouchProbe in the prepared ios_sagit checkout."""
from pathlib import Path
import plistlib
import shutil
import sys

here = Path(__file__).resolve().parent
root = here.parent.parent
if not (root / "scripts/toolchain.py").is_file() or here.parent != root / "tools":
    raise SystemExit("Place the TouchProbe directory under ios_sagit/tools first.")
sys.path.insert(0, str(root / "scripts"))
import toolchain

if not list((toolchain.TOOLS / "sdk/iPhoneOS18.6.sdk/System/Library/Frameworks/UIKit.framework").rglob("UIKit.tbd")):
    raise SystemExit("Missing UIKit.tbd in tools/sdk/iPhoneOS18.6.sdk. Check the user SDK.")
ENTITLEMENTS = {
    "com.apple.QuartzCore.displayable-context": True,
    "com.apple.QuartzCore.secure-mode": True,
    "com.apple.QuartzCore.display-state": True,
    "platform-application": True,
}
toolchain.build_iokit_client("TouchProbe", [str(here / "TouchProbe.mm")],
                             frameworks=["Foundation", "UIKit"],
                             entitlements=ENTITLEMENTS,
                             signing_identifier="org.darwin.development.touchprobe")
bundle = toolchain.BUILD / "output/TouchProbe.app"
bundle.mkdir(exist_ok=True)
shutil.copy2(toolchain.BUILD / "output/TouchProbe", bundle / "TouchProbe")
with (here / "Info.plist").open("rb") as src:
    info = plistlib.load(src)
shutil.copy2(here / "Info.plist", bundle / "Info.plist")
assert (bundle / info["CFBundleExecutable"]).is_file()
print(bundle)
