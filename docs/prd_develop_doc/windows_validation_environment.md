# Windows Validation Environment

## Scope

This document defines the real-host Windows kernel validation environment and execution protocol for PRD-05, PRD-15, and PRD-24. Simulation is forbidden. The validation host must run the real NT kernel on dedicated bare metal and must remain air-gapped for the full preparation, execution, and evidence-sealing lifecycle.

## Validation Topology

- One offline Windows build workstation for compiling `ransomeye_service.exe`, the minifilter driver, and the Ed25519 signing utility.
- One dedicated Windows validation host for the 24-hour run. No hypervisor, no nested guest, no internet access, no cloud-managed tooling.
- One removable transfer medium used only for signed artifacts and validation output export.

## Hardware Requirements

- Bare-metal x64 host only. VM, WSL2, or emulation is not acceptable for the validation run.
- CPU: 4 physical cores minimum, Intel VT-x or AMD-V capable, SLAT capable.
- Memory: 16 GB minimum, 32 GB recommended.
- Storage: 256 GB SSD minimum with at least 80 GB free before the run.
- TPM 2.0 enabled.
- One additional offline removable drive or encrypted USB device for artifact import/export.
- Stable power. Use a UPS for the 24-hour run.

## OS Version

- Validation host OS: Windows 11 Enterprise 23H2 x64, build family `22631`.
- Tooling installed offline on the validation host:
  - Windows Debugging Tools (`cdb.exe` or `kd.exe`)
  - PowerShell 5.1 or PowerShell 7
  - The built `sign-integrity-manifest.exe` utility for Ed25519 result sealing
- Build workstation tooling:
  - Visual Studio 2022 Build Tools
  - WDK 10.0.22621.x
  - Rust toolchain already vendored or preinstalled offline for `scripts/sign-integrity-manifest`

## BIOS / Firmware Settings

- `Secure Boot`
  - `ON` for production-signed driver validation.
  - `OFF` for test-signed pre-release driver validation. Windows test-signing mode will not work with Secure Boot enabled.
- `Virtualization`
  - `ON` for Intel VT-x / AMD-V and SLAT.
  - `IOMMU / VT-d / AMD-Vi` recommended `ON`.
- `TPM 2.0`: `ON`.
- `Fast Boot`: `OFF` so boot-policy changes are observable and reproducible.
- `Memory Integrity / HVCI / VBS`
  - `OFF` on the validation host when the driver is test-signed.
  - May remain `ON` only for production-signed validation if the driver load path is already proven compatible.

## Air-Gap Rules

- Disconnect Ethernet before staging artifacts.
- Remove or disable Wi-Fi, Bluetooth, and cellular adapters.
- No package downloads, symbol downloads, or remote log sinks during the run.
- Move artifacts only by signed offline media.
- Preserve the imported artifact manifest alongside the runtime output directory.

## Artifact Set To Transfer

Copy these files from the offline build workstation to the validation host:

- `agents/windows/build/service/Release/ransomeye_service.exe`
- built minifilter driver (`ransomeye_minifilter.sys` or equivalent build output)
- `agents/windows/build/build_manifest.json`
- `agents/windows/build/build_manifest.sig`
- `scripts/windows/deploy_driver.ps1`
- `tests/windows_agent/runtime_stress/*.ps1`
- built `sign-integrity-manifest.exe`
- `C:\ProgramData\RansomEye\worm_signing.key` provisioning material for the validation host

## Test-Signing Mode

Use this path only for pre-production validation of a test-signed driver.

1. Disable Secure Boot in firmware.
2. Boot Windows as Administrator and enable test-signing:

```powershell
bcdedit /set testsigning on
bcdedit /set nointegritychecks off
```

3. Reboot.
4. Confirm the policy:

```powershell
bcdedit /enum {current}
```

Required result:

- `testsigning Yes`
- Secure Boot disabled in firmware

If production-signed validation is available, keep Secure Boot enabled and do not use test-signing mode.

## Driver Installation Steps

1. Install the user-mode service prerequisites with the existing Windows installer flow if required:

```powershell
.\scripts\install-windows.ps1
```

2. Deploy the minifilter driver from an elevated PowerShell session:

```powershell
.\scripts\windows\deploy_driver.ps1 `
  -DriverBinaryPath D:\staging\ransomeye_minifilter.sys `
  -StagedDriverName ransomeye.sys `
  -ServiceName RansomEyeMinifilter
```

3. Verify the deployed filter:

```powershell
sc.exe query RansomEyeMinifilter
fltmc filters
fltmc instances RansomEyeMinifilter
```

Required result:

- Service `RansomEyeMinifilter` exists
- Driver image placed in `C:\Windows\System32\drivers\ransomeye.sys`
- `fltmc filters` shows the filter loaded

## Driver Verifier Protocol

1. Enable the required verifier profile:

```powershell
.\tests\windows_agent\runtime_stress\enable_driver_verifier.ps1 -DriverName ransomeye.sys
```

2. Reboot the validation host.
3. Confirm verifier stayed active:

```powershell
verifier /querysettings
```

Required checks:

- Special pool
- Force IRQL checking
- Pool tracking
- I/O verification
- Deadlock detection
- DMA checking
- Security checks
- DDI compliance checking
- Force pending I/O requests
- Boot mode `Persistent`

## 24-Hour Runtime Validation Execution

Run only from an elevated PowerShell session on the air-gapped validation host:

```powershell
.\tests\windows_agent\runtime_stress\run_runtime_stress.ps1 `
  -DurationHours 24 `
  -DriverName ransomeye.sys `
  -DriverServiceName RansomEyeMinifilter `
  -DriverBinaryPath C:\Windows\System32\drivers\ransomeye.sys `
  -SignerPath D:\tools\sign-integrity-manifest.exe `
  -WormSigningKeyPath C:\ProgramData\RansomEye\worm_signing.key
```

Protocol invariants:

- Duration is fixed at 24 hours.
- The harness records a sealed observation every 5 minutes.
- Each observation includes memory usage, handle count, and enforcement-event totals.
- The output directory must remain on local disk until the run completes or fails.

## Result Sealing

The runtime harness must emit:

- `runtime_observations.jsonl` as the append-only observation log
- `hash_chain.json` with the final chain head and entry count
- `runtime_result.json` as the final report
- `runtime_result.sig` as the Ed25519 detached signature over `runtime_result.json`
- `runtime_result.pub` as the matching public key bytes when exported by the signer

The `hash` field inside `runtime_result.json` is the final SHA-256 chain head derived from the append-only observation log.

## Fail Conditions

Abort and mark the run failed if any of the following occurs:

- Any crash or unexpected reboot
- Any Driver Verifier stop
- Any IRQL violation
- Any deadlock
- Any memory leak or NonPagedPool growth beyond the configured threshold
- Any enforcement inconsistency:
  - blocked write succeeds
  - blocked network connect succeeds
  - kill target survives
  - verifier configuration disappears
  - signed result cannot be produced

## Commit Gate

Do not commit validation changes until:

- the real 24-hour run completes on the bare-metal validation host
- `runtime_result.json` shows a PASS verdict
- the append-only log, hash chain, and Ed25519 signature are present

Only after that gate is satisfied may the validation commit be created:

```bash
git commit -m "test(PRD-05): real kernel validation passed (24h stress, verifier clean)"
```
