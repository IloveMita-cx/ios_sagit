# Run P: retained DSI display handoff

Base: O (`270a6577dceb9df466cad7183c58043b1d7e0239`). O device evidence shows
the active `dsi@c994000` provider with `status=okay` and the driver-written
`handoff-property-unreadable` stage, mask zero. The input properties were absent.

The bridge now reserves and commits the DSI/panel properties after the existing
post-EFI raster checks. It binds the DPU to the active panel using a unique
phandle. A missing/wrong-sized slot or invalid controller leaves the optional
contract uncommitted; it does not introduce a new fatal bridge return.
All pre-existing mandatory DPU failure returns remain unchanged.

## Explicitly limited contract

DSI version 2, flags 64 means retained read-only operation. It does **not** assert
the five version-1 resource ownership guarantees or DMA bypass. The driver checks
the committed bridge status, current controller identity, no active command DMA,
lane count and retained CTRL mode before publishing the native panel nub. It
does not create a command mapping/buffer. Its operation handler permits only
idempotent interface/video enable requests; all commands, readbacks and mode
changes return unsupported before MMIO writes. Version-1 behavior is unchanged.

Lane count comes from CTRL bits 4..7, requiring a contiguous low-lane mask.
Sources: [Linux v6.12 register definitions](https://github.com/torvalds/linux/blob/v6.12/drivers/gpu/drm/msm/registers/display/dsi.xml)
and [DSI6G register shift handling](https://github.com/torvalds/linux/blob/v6.12/drivers/gpu/drm/msm/dsi/dsi_host.c).
The byte/escape rates are firmware-reported configuration, not measured rates.
Failed/zero reports remain zero; `qcom,dsi-clock-valid-mask` records successful
nonzero reports (bit 0 byte, bit 1 escape). They are diagnostic in retained mode,
and cannot be used to program hardware. Version 1 still requires its old ranges.

Panel version 1, flags 3 retains the initialized panel seen displaying the live
boot console, rather than replaying an undocumented initialization sequence.
It does not newly verify panel sleep state or establish runtime power control.
Brightness commands are unavailable without a separately supported transport.

## Evidence for the next boot

`qcom,dsi-bridge-status`: 0 unattempted, 1 committed, 2 missing/invalid property
slots or panel reference, 3 controller/lane/active-DMA check failed.
The inactive second controller remains disabled and uncommitted.
The client now also prints panel and DPU DT properties plus their start stages.
The P rc samples registry before and after the user-space display probes.

Tests cover Apple DT endian encoding and phandle uniqueness, every absent or
wrong-sized runtime slot, invalid lanes, busy command DMA, missing frequency
reports, unselected controller, v1 contract rejection and retained operation
policy. CI builds the actual kexts and bridge. GUI boot success requires device
validation; this change does not establish that later framebuffer initialization
or the PreBoard assertion has been fixed.
