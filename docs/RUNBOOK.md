# verifierloop — Operator Manual (RUNBOOK)

> **Purpose:** "what do I run, from where, in what order" — copy-and-run.
> No clutter. If you don't remember something, start with **§2 (health + demo)**.
>
> - Repo root: `<repo-root>` — **all commands run from here.**
> - Last updated: 2026-08-28 (verified by probing on this machine).

---

## 1. What this machine has / doesn't have

| Tool | Required? | Status (2026-08-26) |
| --- | --- | --- |
| `cargo` (Rust) | yes | ✅ 1.93 |
| `python3` | yes (score stage) | ✅ 3.10 |
| `qemu-system-x86_64` | yes (VM/fuzzer) | ✅ 6.2 |
| `go` | to build syzkaller | ✅ 1.26 (syzkaller already built) |
| `just` | optional shortcut | ❌ **not installed** |
| KVM (`-enable-kvm`) | speed (optional) | ❌ **not working** → TCG (see §6) |

> [!important] Don't forget two things
> 1. **No `just`.** If you see `just build-kernel` in the README/justfile, its
>    equivalent is directly `./scripts/build-kernel.sh`. This manual always gives the direct path.
> 2. **KVM doesn't work** (probed: the `/dev/kvm` node exists but `-enable-kvm`
>    → `No such device`). Everything runs on **TCG** (software, slow but works).

---

## 2. What you'll do most often (copy-and-run)

### A) Health check — "did I break anything?" (~30 s)
```bash
cargo build            # does the Rust workspace build
cargo test             # 43 tests should pass (0 failed)
python3 -c "import sys; sys.path.insert(0,'python/src'); import verifierloop_analysis; print('python OK')"
```

### B) See the pipeline end to end — with synthetic data (~5 s)
All five stages (ingest→normalize→score→diff→report) in a single command:
```bash
cargo run -q -p pipeline --example report_demo -- /tmp/vl-demo
```
What you should see: `PERIOD REPORT ... top_score=0.95 divergences=3` + a triage list.
Artifacts: `/tmp/vl-demo/data/periods/1/*.json`.

> ⚠️ This is **synthetic** data (a hand-written sample record) — it demonstrates the stage logic.
> For **real** verifier data: `harness_demo` (committed in-VM sample),
> `real_period` (live VM), or `syz_period` (syzkaller-driven, §4b).

### C) Run the stages one by one
Each takes a `<base_dir>`; stages sharing the same directory chain together.
```bash
cargo run -q -p pipeline --example ingest_demo    -- /tmp/vl
cargo run -q -p pipeline --example normalize_demo -- /tmp/vl   # on top of ingest
cargo run -q -p pipeline --example score_demo     -- /tmp/vl   # on top of normalize (requires python3)
cargo run -q -p pipeline --example diff_demo      -- /tmp/vl
cargo run -q -p pipeline --example report_demo    -- /tmp/vl   # also runs all of them standalone
```

### D) Regenerate the golden fixture — ONLY if you deliberately changed the CORE schema
```bash
cargo run -q -p pipeline --example report_demo -- /tmp/vl-golden
python3 -c "import json; json.dump(json.load(open('/tmp/vl-golden/data/periods/1/normalized_metrics.json'))['payload'], open('crates/pipeline/tests/fixtures/golden/normalized.expected.json','w'), indent=2, sort_keys=True)"
cargo test -p pipeline --test golden_normalize   # should be green
```
> If the golden test is red and you did **not** change the schema: this is a regression, fix it —
> don't overwrite the golden. (Parser-layer guardrail; see devlog 0010.)

### E) If you changed `harness/diffharness.c` — refresh the authoritative sample
The committed sample (`harness/samples/bpf-next-sample.txt`) is a capture **taken from a
real bpf-next VM**; output produced on the host does not substitute for it (the host kernel
is different, the message texts come out different).
```bash
./scripts/build-harness.sh                                   # build first
./harness/diffharness | head -40                             # quick sanity check (root, host kernel)
TIMEOUT=300 ./scripts/run-harness-vm.sh /tmp/vm-capture.log   # ~3-5 dk, TCG
# keep the header block, change the body, then:
cargo test -p pipeline --lib parses_bpf_next_richer_format    # block count + rejection reasons pinned
```
> The block count and rejection reasons in the sample are **anchored** to the test — if you added
> a new program the test goes red and must be deliberately updated. This is intentional: if a new
> error-message shape silently breaks the parser, the detector says "clean" (devlog 0018/0024).

---

## 3. Lab: kernel + VM setup (heavy, sequential — **already done**)

These build `.lab/` from scratch. `.lab/` is currently populated, so **you normally
don't touch these**; but on a clean machine, or if you want to refresh the kernel, run in order:

```bash
./scripts/fetch-kernel.sh      # bpf-next'i .lab/bpf-next'e klonla (blobless)
./scripts/build-kernel.sh      # produce bzImage (.lab/build/bzImage, with BTF)
./scripts/create-rootfs.sh     # disposable Debian rootfs (.lab/images/rootfs.img)
./scripts/verify-vm.sh         # boot, verify BTF+bpffs+kcov, shut down
```

**Currently ready (check):**
```bash
ls -la .lab/build/bzImage .lab/images/rootfs.img   # varsa kurulum tamam
```

---

## 4. Run the fuzzer (syzkaller — NO LONGER PRIMARY)

> **Since 0077 the primary hunting tool is not syzkaller but our own coverage-driven loop.**
> The reason is OI-1: WSL2 nested KVM cannot carry a syzkaller campaign, even a single VM
> keeps dropping. Our own loop is genome-based, reproducible, and carries four oracles.
> For hunting see **§4c**; this section stays around for collecting samples from the
> syzkaller corpus.

```bash
./scripts/setup-syzkaller.sh              # one-time (already done; builds syzkaller)

# Limited campaign (benchmark / sample collection):
DURATION=600 ./scripts/run-syzkaller.sh   # stops on its own after ~10 min

# Indefinite (until stopped with Ctrl-C):
./scripts/run-syzkaller.sh
```

- **Dashboard:** while running → http://127.0.0.1:56741
- **Output:** `.lab/syzkaller/workdir/` → `corpus.db`, `crashes/` (if a crash occurs)
- **TCG reality:** warm-up ~90–100 s (VM boot + machine check + candidate triage).
  **Give it at least 5 min to see coverage grow** — a short run (200 s) gets stuck
  in triage (see devlog 0010).

---

## 4b. Syzkaller-driven period (the volume path)

Turns syzkaller's corpus into a **real verifier log** and feeds it into the pipeline:
corpus → `syz-prog2c` → replay shim (injects `log_level=2`) → bpf-next VM.

```bash
# 1) grow the corpus (run the fuzzer for a while)
DURATION=900 ./scripts/run-syzkaller.sh

# 2) replay binary'lerini derle (corpus -> C -> shim ile static binary)
./scripts/syz-replay-build.sh

# 3) replay in the VM + capture native output
TIMEOUT=900 ./scripts/run-syzreplay-vm.sh /tmp/syz-capture.log

# 4a) triage only (no VM, from a captured file)
cargo run -q -p pipeline --example parse_report -- /tmp/syz-capture.log

# 4b) ya da TAM period (2+3+4 hepsi; VM boot eder, dakikalar)
TIMEOUT=900 cargo run -q -p orchestrator --example syz_period -- /tmp/syz-period
```

In the output, **two channels are read separately**:
- `SIGNAL divergences=...` → a real verifier signal (triage it),
- `PARSE HEALTH ... with_notes / unparsed_blocks` → **parser blind spots**
  (NOT an anomaly; the place where you need to fix the parser).

> When volume first runs it will most likely produce `parse notes` / `unparsed` — this is
> the expected and correct behavior: log shapes the parser hasn't seen are reported
> separately, without contaminating the signal (devlog 0017/0018).

---

## 4c. HUNTING: coverage-driven continuous loop (PRIMARY)

```bash
SECONDS_BUDGET=1800 ./scripts/run-fuzz.sh /tmp/hunt.log     # 30 dk, ~560 program/sn
```

`run-fuzz.sh` **first calibrates the reference interpreter and refuses to run if it can't pass**;
the loop also refuses to run without KCOV (without feedback it would be a plain random walk
under the guise of "fuzzing").

The result line is `FUZZ done ...`, and the fields to read:

| field | what it means |
|---|---|
| `findings` / `FINDING` lines | oracle findings — each printed **with its genome** |
| `livecells` / `livemiss` | liveness gate: denominator and mismatch (see §4d) |
| `liveunsup` | number of programs the model REJECTED — honest coverage; if nonzero, read the denominator accordingly |
| `prunepairs` / `pruneflip` / `pruneartifact` | pruning difference; **`pruneartifact` is an artificial rejection** |
| `invchecked` / `invfault` | `BPF_F_TEST_REG_INVARIANTS` channel |
| `trunc` | did the KCOV buffer overflow — **if nonzero, `seen_pcs` is undercounting** |
| `maxstates` / `avgstates` | exploration depth; if low, the pruning pairs are insignificant |

**Reproduce a finding** (give the genome from the finding line verbatim):

```bash
G='genes=18 hi=1:15.1.1.7.4,10.0.1.9.27,...'
HARNESS_ARGS="--fuzz-replay '$G'" TIMEOUT=240 ./scripts/run-harness-vm.sh /tmp/replay.log
```

Replay uses the loop's **own** prologue/body/epilogue — a second implementation
could produce a difference. The output is a full pipeline record, so the same oracles
judge it as in every family.

---

## 4d. Liveness gate (`bpflive.h`) — cross-state oracle

`func_states_equal` only compares registers it counts as LIVE, so liveness is the **gate**
for every prune decision. `bpflive.h` recomputes that analysis independently of the emitted
bytes and compares it against the table the kernel prints.

```bash
./scripts/run-liveness.sh                    # prune + spill aileleri, ~2 dk
FAMILIES=comp TIMEOUT=1500 ./scripts/run-liveness.sh   # 896-program corpus, ~25 min
```

**The direction is one-sided:** kernel DEAD / model LIVE = a finding. Kernel LIVE / model DEAD =
conservatism, not reported and **not counted**. If the model sees something it doesn't cover
(a subprog call, an unregistered kfunc, an unknown opcode) it does not guess, it **rejects** —
because the finding direction is also the direction a coarse analysis would produce.

The model's own calibration, against the kernel's own selftests:

```bash
HARNESS_ARGS=--probe-livetraps TIMEOUT=240 ./scripts/run-harness-vm.sh /tmp/traps.log
```

---

## 4e. Calibration pairs (against real kernel bugs)

Each pair certifies one channel, **and only that one**. The ones that have a runner:

```bash
./scripts/run-calibration.sh    # 92424801261d — VERDICT channel (REG_INVARIANTS)
./scripts/probe-idlink.sh       # af9e89d8dd39 — LIMIT: over-rejection, outside instrumentation
./scripts/probe-spill.sh        # 811c363645b3 — measured limit of the runtime channel
./scripts/probe-deltalink.sh    # 3878ae04e9fc — STORE-LOCATION channel
./scripts/probe-jsetlive.sh     # 3157f7e29996 — LIVENESS GATE channel
```

The ones without a runner, run directly with `HARNESS_ARGS`: `--probe-maygotolive`
(871ef8d50e7c, the gate's LIMIT), `--probe-idbase` (2f2ec8e7730e, the **structural** limit
of the pruning difference), `--probe-mixwidth` (bc308be380c1, the verifier accepts and
**the kernel crashes**), `--probe-sx`, `--probe-fakereg`, `--probe-ref`.

Buggy kernels are `.lab/build/bzImage-buggy*` and `-fix*`; select with `KERNEL=`. A pair
is meaningful only if both kernels were built with the **same `.config`** — `build-kernel.sh`
takes `SRC`/`OUT`, and its verification is to `diff` the two `.config`s.

---

## 5. Enter the VM by hand (manual PoC / debug)

```bash
./scripts/boot-vm.sh              # disposable VM, serial console (KVM auto-selected)
# ACCEL=tcg ./scripts/boot-vm.sh  # if you want to force TCG (~20x slower)
```
Exit: inside the VM run `poweroff` or kill QEMU (see §7 gotcha).

---

## 6. KVM or TCG? (the speed question)

Currently: **KVM** (Win11/WSL2 nested virtualization works). `boot-vm.sh` picks KVM if
`/dev/kvm` is writable, otherwise TCG — you don't need to do anything by hand. Measured: KVM
is ~20x the median `load_ns` of TCG, and the output is **byte-for-byte identical** on both
accelerators (242/242 programs), so the accelerator choice is a throughput decision, never a
semantic one.

> Historical note: on 2026-08-26 `-enable-kvm` gave `No such device`; that obstacle is gone.
KVM would be ~10–20x faster; but because the loop logic is **period = exec-count**, only
wall-clock is affected, not the results.

**IMPORTANT (reviewer correction, 2026-09-01):** for WSL2, **nested virtualization is
specific to Windows 11** — it does not work on Windows 10. The earlier "it might also work on
Win10" expectation was **wrong and has been retracted**. So the steps below will never succeed
on Win10; **switching to Win11 is a real precondition for KVM**, not an optional setting. Backup
plan for the switch: `wsl --export`, push to the git remote, and choose "Keep personal files
and apps" during setup.

**Trying to enable KVM (host-side, what you need to do — requires Win11):**
1. On Windows run `wsl --shutdown`, then reopen WSL.
2. Test inside WSL:
   ```bash
   egrep -c '(vmx|svm)' /proc/cpuinfo          # should be > 0
   qemu-system-x86_64 -enable-kvm -machine q35 -m 128 -display none \
     -serial stdio -kernel .lab/build/bzImage -append "console=ttyS0 panic=-1" 2>&1 | head
   ```
   If kernel boot messages stream, KVM **works**. If you see `No such device`, it's still off.
3. If still off: `nestedVirtualization=true` in `.wslconfig` (if present), and if the host
   Windows is itself a VM, **expose VT-x/EPT** on the hypervisor.
   Note: even if VT-x is on in the BIOS, WSL2/Hyper-V nested-virt is a separate layer.

If KVM works: the syzkaller config is already pinned to TCG; you need to switch the
`QEMU_ARGS` in `scripts/gen-syz-config.sh` to KVM and regenerate the config.

---

## 7. Where things are (map)

| Path | What |
| --- | --- |
| `crates/` | Rust code (pipeline, orchestrator, metrics, contract, vmctl) |
| `python/` | Python analysis package (score stage) |
| `scripts/` | Lab bring-up + fuzzer scripts (the ones you actually run) |
| `config/` | kernel `.config` fragment, qemu launch templates |
| `.lab/` | **Heavy artifacts** (outside git): kernel, rootfs, syzkaller, bpf-next |
| `.lab/syzkaller/workdir/` | fuzzer output (corpus, crashes) |
| `data/` | period harvest output (runtime; outside git) |
| `docs/devlog/devlog.md` | what was done/why — persistent memory |
| `docs/REVIEW-HANDOFF.md` | the report handed to someone else to "verify" |

---

## 8. Things that trip you up often (gotchas)

- **`just <thing>` "command not found"** → `just` is not installed. Use `./scripts/<thing>.sh`
  or the `cargo run` equivalent above.
- **Don't kill yourself while killing QEMU:** `pkill -f qemu` also kills **your own shell**
  if it has "qemu" on its command line. The correct one is: `pkill -x qemu-system-x86_64`.
- **syzkaller waits silently / no exec at all** → it probably can't ssh into the VM. The network
  was already made name-independent (devlog 0009); if it still happens, run the config with `-debug`.
- **`score`/`report_demo` python error** → `python3` must be on PATH and `python/src` must be
  importable (test with §2-A).

---

## 9. NOT WORKING YET (placeholder — don't be fooled!)

These deliberately **print intent and `exit 1`**; they're not wired up yet:

| Command (in justfile) | Status |
| --- | --- |
| `collect-metrics` | placeholder — once the real parser + VM are wired |
| `run-period` | placeholder — once the real `FuzzDriver` is wired |
| `period-report` | placeholder |

> Note: these are the **old `just` shortcuts**. Their equivalents are now real and working:
> a single period → `cargo run -p orchestrator --example real_period` (harness) or
> `--example syz_period` (syzkaller-driven, §4b); triage → `parse_report`.
> So real data is flowing; the remaining work is volume + external ground-truth loaders.

---

## 10. "I just started a new session, where do I look?" (30 s)

```bash
git --no-pager log --oneline -8                  # son bacaklar
git log --oneline -20                             # recent commits
cargo test --workspace                           # is everything green (371 passed)
```

And to read the instrument's **own health** — which numbers are denominators and which are coverage:

```bash
MEASURE_LOG=<yakalama> cargo test -p pipeline --test measure_log -- --ignored --nocapture
```

This prints EVERY recorded denominator (the list is derived from `INVARIANT_DENOMINATORS`,
not hand-written — in 0091 six of them went unprinted for years). This is the place to look
before deciding a family is "clean": **zero findings, without a denominator, is not information.**

Detailed status: `docs/REVIEW-HANDOFF.md`. The story: `docs/devlog/devlog.md`.
Open items and measured limits: `docs/OPEN-ITEMS.md`.
