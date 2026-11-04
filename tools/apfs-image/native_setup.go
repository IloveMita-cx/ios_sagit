package main

import (
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// Build just the two preference payloads. The native editor retains every
// unrelated inode and extent, including Data streams it cannot reconstruct.
func nativeSetupInputs(data *apfs.Volume) []nativeSystemInput {
	root := &apfswrite.Entry{Mode: os.ModeDir | 0755}
	prefs := dir(dir(dir(root, "mobile"), "Library"), "Preferences")
	const prefix = "mobile/Library/Preferences/"
	for _, name := range []string{"com.apple.purplebuddy.plist", "com.apple.purplebuddy.notbackedup.plist"} {
		entry, err := data.FileEntryByPath(prefix + name)
		if err != nil {
			// applyVolume checks the directory record before allowing creation.
			continue
		}
		repairCheck(must(entry.FileMode())&0170000 == 0100000, "Setup preference is not a regular file")
		repairCheck(must(entry.RawDataStream()).Size() <= 1<<20, "Setup preference exceeds 1 MiB")
		prefs.Children = append(prefs.Children, &apfswrite.Entry{
			Name: name, Mode: 0600, Data: must(data.ReadFile(prefix + name)),
		})
	}
	seedSetupCompletion(root, &stats{})
	inputs := []nativeSystemInput{}
	for _, entry := range prefs.Children {
		inputs = append(inputs, nativeSystemInput{
			path: prefix + entry.Name, payload: entry.Data, mode: 0600, uid: 501, gid: 501,
		})
	}
	// Disable the Preboard services so they stop crash-looping during development boot.
	inputs = append(inputs, nativeSystemInput{
		path:    "db/com.apple.xpc.launchd/disabled.plist",
		payload: []byte(launchdDisabledXML),
		mode:    0644, uid: 0, gid: 0,
	})
	return inputs
}

const launchdDisabledXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.preboardservice</key>
	<true/>
	<key>com.apple.preboardservice_v2</key>
	<true/>
</dict>
</plist>
`
