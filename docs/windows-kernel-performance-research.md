# Windows kernel performance research notes

## Scope

Static analysis target:

`/home/pedro/Downloads/AD46014AC59E010001D62E597DB6FBCE709681EF5B4EE79ECF01D07E6EDA08B000.blob`

The image identifies itself as Microsoft `ntkrnlmp.exe`, version
`10.0.28000.2525`. It is the multiprocessor Windows kernel, not a tuning
utility or a configuration database. The names below were recovered from the
binary using Ghidra headless and string analysis. Their presence proves that
the kernel implements or consumes the concept; it does not prove a registry
value, supported public API, type, unit, or valid range.

Treat unknown settings as research leads. Record the machine, Windows build,
active power plan, AC/DC state, firmware version, and baseline benchmark before
changing one variable. Keep an export or restore point before each experiment.

## Symbol-backed reverse engineering results

The matching Microsoft public PDB was resolved from the image's CodeView
record:

```text
PDB: ntkrnlmp.pdb
GUID: BC7235DA-3728-A7BA-5DC0-2351A9061615
Age: 1
```

The PDB and decompiled consumers provide substantially stronger evidence than
the string names alone. Searches performed on 2026-07-16 found lists and tweak
scripts containing some names, but no Microsoft Learn documentation explaining
the behavior below. The descriptions here come from this exact kernel build.

### Normal-priority anti-starvation controls

All four values are read as `REG_DWORD` from:

```text
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel
```

They are loaded by `KiInitializeNormalPriorityAntiStarvationPolicies` and used
by `KiNormalPriorityReadyScan`, `KiScanSharedReadyThreads`,
`KiPrepareReadyThreadForRescheduling`, and `KiUpdateRunTime`.

| Registry value | Build default | Enforced range | Observed impact |
| --- | ---: | ---: | --- |
| `ScanLatencyTicks` | 7 | 7-70 | Sets the delay until the scheduler's next normal-priority ready-queue scan. Lower values scan more frequently. |
| `ReadyTimeTicks` | 6 | 6-70 | Sets the age threshold used to decide that a ready thread has waited long enough for anti-starvation handling. Lower values make threads eligible sooner. |
| `ThreadReadyCount` | 1 | 1-10 | Limits how many eligible ready threads are considered during a scan. It is not the total system ready-thread count. |
| `BoostingPeriodMultiplier` | 3 | 1-20 | Multiplies the scheduler's base boosting period/quantum used by the anti-starvation path. |

The kernel clamps out-of-range values at boot. These controls target fairness
and starvation prevention, not timer resolution. Aggressive values can add
ready-queue scanning and migration overhead or distort scheduling fairness.

### Power control-vector inputs

The following values are entries in `CmControlVector`. Their key component is
`Power`, which resolves under:

```text
HKLM\SYSTEM\CurrentControlSet\Control\Power
```

Their destinations are 32-bit kernel globals. No explicit range validation was
seen in the consuming routines, so only the compiled defaults and boolean
tests are stated with confidence.

| Registry value | Build default | Destination | Decompiled behavior |
| --- | ---: | --- | --- |
| `PerfBoostAtGuaranteed` | 0 | `PpmPerfBoostAtGuaranteed` | Changes performance selection in `PpmPerfSelectProcessorState`, `PpmPerfApplyDomainState`, and `PpmPerfApplyLatencyHint`. When enabled, several non-CPPC policy paths use the domain's performance boundary instead of an unconditional 100-percent boundary; another path permits 100-percent selection at the guaranteed-performance point. This changes when boost is considered, not the boost clock itself. |
| `IpiLastClockOwnerDisable` | 0 | `PpmIpiLastClockOwnerDisable` | In `PpmWakeClockOwnerIfNeeded`, a nonzero value bypasses the path that sends an IPI to the previous clock-owner processor and marks the wake with flag `0x800`. It can reduce an IPI but may delay clock/timer ownership work. |
| `LatencyToleranceFSVP` | 20,000 | private 32-bit target | `PopFxGetLatencyLimitWithoutResiliency` selects this value when the FSVP state flag is active. It feeds `PoFxSendSystemLatencyUpdate`, so it is a device power-framework latency tolerance, not a DPC/ISR timeout. The value is consistent with microseconds: 20,000 equals 20 ms. |
| `LatencyToleranceIdleResiliency` | 1,500,000 | private 32-bit target | Selected during the idle-resiliency state and sent as the system PoFx latency tolerance. The default corresponds to 1.5 seconds if expressed in microseconds. |
| `HighPerfSoftParkLatency` | 1,000 | `PpmHighPerfSoftParkLatencyUs` | In `PpmParkApplyPolicy`, a nonzero value caps the soft-park latency when high-performance mode is active. The PDB confirms microseconds. It does not disable core parking; lower values demand a faster response from soft-parked processors. |

`LatencyToleranceFSVP=1` is commonly repeated online as a latency tweak. The
decompiled path does not mean "stop tolerating DPC/ISR latency." It changes a
PoFx device latency-tolerance request from the compiled 20 ms to 1 microsecond,
which can prevent deeper device power states and increase power/thermal load.

### Reserved CPU sets

`KiInitializeReservedCpuSets` reads:

```text
Key:   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel
Value: ReservedCpuSets
Type:  REG_BINARY
```

The byte length must be divisible by eight. The loader accepts at most 32
64-bit masks (256 bytes) and copies them into `KiReservedCpuSets`. Each mask is
therefore consistent with a processor-group CPU bitmap. This participates in
kernel CPU-set/partition initialization; it is not ordinary process affinity.
An invalid type or size is ignored. Reserving the wrong processors can remove
capacity from general scheduling, so this is unsuitable for blind tuning.

### False-positive names

Several strings initially looked configurable but are not registry settings:

| String | Actual role |
| --- | --- |
| `SchedulerSharedData` | Name of an Object Manager type created by `PspInitPhase0`; it supports scheduler shared-data regions for CPU partitions. |
| `ClockOwnerDynamicTick` | ETW/event field describing clock-owner dynamic-tick state. |
| `TimerTscSync` | Timer telemetry/category text, not proof of a registry value. |
| `SoftParkLatency` | ETW policy field name. The actual boot input found in `CmControlVector` is `HighPerfSoftParkLatency`. |
| `ResponsivenessPerfFloor` / `ResponsivenessEppCeiling` | Processor-policy/ETW field names in this image; no registry-loading path was established in this pass. |

## Ghidra symbol work

The original blob was not patched. The Ghidra project at
`/tmp/ghidra_projects/KernelPerfBlob` now contains verified names for the
control-vector entries, destination globals, and these consumer routines:

```text
PpmPerfSelectProcessorState
PpmPerfApplyDomainState
PpmPerfApplyLatencyHint
PpmWakeClockOwnerIfNeeded
PopFxGetLatencyLimitWithoutResiliency
PoFxSendSystemLatencyUpdate
PpmParkApplyPolicy
KiInitializeNormalPriorityAntiStarvationPolicies
KiNormalPriorityReadyScan
KiScanSharedReadyThreads
KiPrepareReadyThreadForRescheduling
KiUpdateRunTime
KiInitializeReservedCpuSets
PspInitPhase0
```

## Likely configuration locations

The kernel contains these paths:

```text
HKLM\SYSTEM\CurrentControlSet\Control\Power
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\CPU Partitions
```

The actual processor-performance settings exposed to users are normally
stored as power-plan values and should be inspected through `powercfg`, not by
adding guessed values under those kernel keys:

```bat
powercfg /list
powercfg /query SCHEME_CURRENT SUB_PROCESSOR
powercfg /query SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN
powercfg /query SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX
powercfg /query SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE
```

`powercfg /query` prints the concrete setting GUIDs, current AC/DC values, and
the build-specific set of supported settings. This is the preferred way to map
a friendly name to an editable policy.

## Processor power and core parking

These names are associated with processor performance policy, core parking, or
frequency selection:

| Recovered name | Likely area | Research question |
| --- | --- | --- |
| `PerfBoostMode` | Boost behavior | Which `powercfg` processor boost setting maps to this build? |
| `PerfBoostPolicy` | Boost policy selection | Is it OEM/firmware-controlled or exposed by the active plan? |
| `PerfBoostAtGuaranteed` | Guaranteed-performance boost behavior | Does it affect boost while the CPU is at its guaranteed frequency? |
| `PerfMaxPolicy` | Performance cap | Does it correspond to maximum processor state or a platform cap? |
| `PerfTimeCheck` | Performance control cadence | Does ETW show a periodic policy-evaluation interval? |
| `CPMinCores` / `CPMaxCores` | Core parking bounds | Does the plan expose minimum/maximum unparked cores? |
| `CPDistributeThreshold` | Work distribution | Does it change how work is spread before unparking cores? |
| `ParkingPerfState` | Parking decision state | Is it telemetry only, or a value derived from plan policy? |
| `ComplexUnparkPolicy` | Multi-core-complex unparking | Does behavior vary on CCD/chiplet processors? |
| `ModuleUnparkPolicy` | Module-level unparking | Is it relevant only to a specific processor topology? |
| `SoftParkLatency` | Soft-parking telemetry | This is an ETW/policy field; the confirmed boot input is `HighPerfSoftParkLatency`. |
| `ThrottlingPolicy` | Thermal/power throttling | Is it a platform constraint rather than user policy? |

## Latency, responsiveness, and EPP

These names suggest latency-sensitive policy and energy-performance preference
(EPP) handling:

| Recovered name | Likely area | Research question |
| --- | --- | --- |
| `LatencyHintUnpark` | Latency-triggered unparking | Which workloads submit a latency hint? |
| `LatencyHintEpp` | EPP adjustment | Does a latency hint temporarily reduce EPP? |
| `LatencyHintFreq` | Frequency request | Does it ask for a higher performance level? |
| `LatencyHintPerf` | Relative performance target | Is this a requested floor or measured state? |
| `ResponsivenessPerfFloor` | Minimum performance during responsiveness windows | Is it enabled only for interactive workloads? |
| `ResponsivenessEppCeiling` | EPP upper bound | Is it a ceiling applied during responsiveness windows? |
| `ResponsivenessDisableTime` | Responsiveness timeout | What event starts and stops the window? |
| ` ` | Workload/resource priority | Is it derived from thread QoS rather than globally configured? |

## Hybrid CPU and scheduling policy

These names concern P-core/E-core or other heterogeneous CPU scheduling. They
are particularly build-, processor-, and scheduler-dependent.

| Recovered name | Likely area | Research question |
| --- | --- | --- |
| `SchedulingPolicy` | General scheduling policy | Is it per power plan, workload class, or scheduler state? |
| `ShortSchedulingPolicy` | Short-running work policy | What counts as a short-running thread on this build? |
| `HeteroPolicy` | Heterogeneous CPU policy | Does the active plan expose a matching policy? |
| `HeteroIncreaseThreshold` / `HeteroDecreaseThreshold` | Migration threshold | Is the threshold based on utilization, performance feedback, or QoS? |
| `HeteroIncreaseTime` / `HeteroDecreaseTime` | Hysteresis interval | Are values milliseconds, scheduler ticks, or sampling periods? |
| `HeteroContainmentIncreaseTime` | Containment hysteresis | Which CPU class is being contained? |
| `LongThreadArchClassLowerThreshold` | Long-thread CPU-class selection | How is a long thread identified? |
| `LongThreadArchClassUpperThreshold` | Long-thread CPU-class selection | Does it prevent oscillation across CPU classes? |
| `ShortThreadArchClassLowerThreshold` | Short-thread CPU-class selection | Which thread types are affected? |
| `ShortThreadArchClassUpperThreshold` | Short-thread CPU-class selection | Does it reflect foreground/background QoS? |
| `ShortThreadRuntimeThreshold` | Thread-duration classification | What unit and sampling clock are used? |
| `DefaultHeteroCpuPolicy` | Default scheduler policy | Is it an OEM or Windows default? |

## Kernel scheduling and partitioning summary

The image references the following scheduler names and areas:

```text
ThreadReadyCount
ReadyTimeTicks
ScanLatencyTicks
BoostingPeriodMultiplier
ReservedCpuSets
CPU Partitions
```

The first four and `ReservedCpuSets` are confirmed boot inputs and are described
above. CPU partitions are a broader kernel feature, not a single tuning value.
They can restrict scheduling and reduce throughput if configured incorrectly.
`SchedulerSharedData` is deliberately omitted because decompilation established
that it is an Object Manager type name, not a registry value.

## Timer and clock-related names

The image implements timer infrastructure and contains these terms:

```text
TimerHardware
ClockTimer
PerformanceCounter
AlwaysOnTimer
VpptPhysicalTimer
AlwaysOnCounter
TimerTscSync
TscAdjustAvailable
ClockOwnerDynamicTick
USEPLATFORMCLOCK
USEPLATFORMTICK
DISABLEDYNAMICTICK
FORCETIMESYNC
```

The last four are boot-option tokens, not normal performance controls. On a
modern system Windows selects an appropriate clock source, typically using an
invariant TSC where supported. Forcing platform clock/tick sources can increase
overhead, harm latency, or cause timekeeping issues. Do not enable them merely
because they exist in the kernel.
