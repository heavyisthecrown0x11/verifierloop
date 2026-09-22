# RATER PACKET — 57 kernel fixes, one question each

You are an independent second rater. Answer ONE question per commit, from the DIFF
ALONE (not from the commit title or message):

    Does this defect corrupt an artifact in oracle B's CONSUMPTION SET?

Three answers are permitted: **Yes** / **No** / **Undecided**.
- Yes  = the fix changes code that WRITES a field B consumes; B would read the
         corrupted value and reproduce it (structurally blind).
- No   = the fix changes something B does not consume: the comparison predicate
         itself, a guard around it, an unmodelled part, or code off the path.
- Undecided = the diff does not settle it from source. Use this freely; it is a
         legitimate answer and a count of it is part of the result.

## Oracle B's consumption set (facts about the oracle, not about any commit)

B is `scripts/subsume-check.py` (reference) and `harness/bpfsubs.h` (in-VM twin).
It reads PRUNEPAIR rows the kernel prints when it PRUNES a state pair, one row per
register per side: type, var_off (value/mask), u64/s64/u32/s32 bounds (or cnum
base+size in the newest era), id, frameno, precise, live. It re-implements
regsafe()'s SCALAR arm on those consumed values (range_within, tnum_in,
check_ids / check_scalar_ids, the precision short-circuit) and the pointer arms as a
prefix memcmp. It does NOT model refsafe(), stack slots / stacksafe(), or the code in
is_state_visited() that decides WHETHER to call states_equal. You MAY read the two
source files above to check any of this. You MUST NOT read anything under
docs/heldout/ — it contains a prior rater's labels, and your value is your
independence from them.

## Output format (exactly this, one line per commit)

    <12-char sha>  <Yes|No|Undecided>  <file:function the decision rests on>  <one clause of reasoning>



---
## fd4cfa8c8f9a — bpf: Reject negative const offsets for buffer pointers

```diff
 kernel/bpf/verifier.c | 31 +++++++++++++++++++------------
 1 file changed, 19 insertions(+), 12 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 6515d4d3c003..9f1333676365 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -5326,14 +5326,11 @@ static int check_max_stack_depth(struct bpf_verifier_env *env)
 static int __check_buffer_access(struct bpf_verifier_env *env,
 				 const char *buf_info,
 				 const struct bpf_reg_state *reg,
-				 argno_t argno, int off, int size)
+				 argno_t argno, int off, int size,
+				 u32 *access_end)
 {
-	if (off < 0) {
-		verbose(env,
-			"%s invalid %s buffer access: off=%d, size=%d\n",
-			reg_arg_name(env, argno), buf_info, off, size);
-		return -EACCES;
-	}
+	s64 start;
+
 	if (!tnum_is_const(reg->var_off)) {
 		char tn_buf[48];
 
@@ -5344,6 +5341,15 @@ static int __check_buffer_access(struct bpf_verifier_env *env,
 		return -EACCES;
 	}
 
+	start = (s64)reg->var_off.value + off;
+	if (start < 0) {
+		verbose(env,
+			"%s invalid negative %s buffer offset: off=%d, var_off=%lld\n",
+			reg_arg_name(env, argno), buf_info, off, (s64)reg->var_off.value);
+		return -EACCES;
+	}
+
+	*access_end = start + size;
 	return 0;
 }
 
@@ -5351,14 +5357,14 @@ static int check_tp_buffer_access(struct bpf_verifier_env *env,
 				  const struct bpf_reg_state *reg,
 				  argno_t argno, int off, int size)
 {
+	u32 access_end;
 	int err;
 
-	err = __check_buffer_access(env, "tracepoint", reg, argno, off, size);
+	err = __check_buffer_access(env, "tracepoint", reg, argno, off, size, &access_end);
 	if (err)
 		return err;
 
-	env->prog->aux->max_tp_access = max(reg->var_off.value + off + size,
-					    env->prog->aux->max_tp_access);
+	env->prog->aux->max_tp_access = max(access_end, env->prog->aux->max_tp_access);
 
 	return 0;
 }
@@ -5370,13 +5376,14 @@ static int check_buffer_access(struct bpf_verifier_env *env,
 			       u32 *max_access)
 {
 	const char *buf_info = type_is_rdonly_mem(reg->type) ? "rdonly" : "rdwr";
+	u32 access_end;
 	int err;
 
-	err = __check_buffer_access(env, buf_info, reg, argno, off, size);
+	err = __check_buffer_access(env, buf_info, reg, argno, off, size, &access_end);
 	if (err)
 		return err;
 
-	*max_access = max(reg->var_off.value + off + size, *max_access);
+	*max_access = max(access_end, *max_access);
 
 	return 0;
 }

```


---
## 2aaf67f0516f — bpf: Reject rdonly/rdwr_buf_size kfunc arguments that exceed u32 max

```diff
 kernel/bpf/verifier.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index a0830ad6bebb..03e2202cca13 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -12109,6 +12109,11 @@ static int check_kfunc_args(struct bpf_verifier_env *env, struct bpf_kfunc_call_
 				}
 
 				meta->r0_size = reg->var_off.value;
+				if (meta->r0_size > U32_MAX) {
+					verbose(env, "%s rdonly/rdwr_buf_size exceeds u32 max\n",
+						reg_arg_name(env, argno));
+					return -EINVAL;
+				}
 				if (regno >= 0)
 					ret = mark_chain_precision(env, regno);
 				else

```


---
## 37363191cbe8 — bpf: Fold reg->var_off into PTR_TO_FLOW_KEYS bounds check

```diff
 kernel/bpf/verifier.c | 18 +++++++++++++++---
 1 file changed, 15 insertions(+), 3 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 935595138aa0..68ddd465584c 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -4728,9 +4728,21 @@ static int check_ctx_access(struct bpf_verifier_env *env, int insn_idx, struct b
 	return err;
 }
 
-static int check_flow_keys_access(struct bpf_verifier_env *env, int off,
-				  int size)
+static int check_flow_keys_access(struct bpf_verifier_env *env,
+				  struct bpf_reg_state *reg, argno_t argno,
+				  int off, int size)
 {
+	/* Only a constant offset is allowed here; fold it into off. */
+	if (!tnum_is_const(reg->var_off)) {
+		char tn_buf[48];
+
+		tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
+		verbose(env, "%s invalid variable offset to flow keys: off=%d, var_off=%s\n",
+			reg_arg_name(env, argno), off, tn_buf);
+		return -EACCES;
+	}
+	off += reg->var_off.value;
+
 	if (size < 0 || off < 0 ||
 	    (u64)off + size > sizeof(struct bpf_flow_keys)) {
 		verbose(env, "invalid access to flow keys off=%d size=%d\n",
@@ -6239,7 +6251,7 @@ static int check_mem_access(struct bpf_verifier_env *env, int insn_idx, struct b
 			return -EACCES;
 		}
 
-		err = check_flow_keys_access(env, off, size);
+		err = check_flow_keys_access(env, reg, argno, off, size);
 		if (!err && t == BPF_READ && value_regno >= 0)
 			mark_reg_unknown(env, regs, value_regno);
 	} else if (type_is_sk_pointer(reg->type)) {

```


---
## 179ee84a8911 — bpf: Fix incorrect pruning due to atomic fetch precision tracking

```diff
 kernel/bpf/verifier.c | 27 ++++++++++++++++++++++++---
 1 file changed, 24 insertions(+), 3 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index df04dccfc540..e3814152b52f 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -617,6 +617,13 @@ static bool is_atomic_load_insn(const struct bpf_insn *insn)
 	       insn->imm == BPF_LOAD_ACQ;
 }
 
+static bool is_atomic_fetch_insn(const struct bpf_insn *insn)
+{
+	return BPF_CLASS(insn->code) == BPF_STX &&
+	       BPF_MODE(insn->code) == BPF_ATOMIC &&
+	       (insn->imm & BPF_FETCH);
+}
+
 static int __get_spi(s32 off)
 {
 	return (-off - 1) / BPF_REG_SIZE;
@@ -4447,10 +4454,24 @@ static int backtrack_insn(struct bpf_verifier_env *env, int idx, int subseq_idx,
 			   * dreg still needs precision before this insn
 			   */
 		}
-	} else if (class == BPF_LDX || is_atomic_load_insn(insn)) {
-		if (!bt_is_reg_set(bt, dreg))
+	} else if (class == BPF_LDX ||
+		   is_atomic_load_insn(insn) ||
+		   is_atomic_fetch_insn(insn)) {
+		u32 load_reg = dreg;
+
+		/*
+		 * Atomic fetch operation writes the old value into
+		 * a register (sreg or r0) and if it was tracked for
+		 * precision, propagate to the stack slot like we do
+		 * in regular ldx.
+		 */
+		if (is_atomic_fetch_insn(insn))
+			load_reg = insn->imm == BPF_CMPXCHG ?
+				   BPF_REG_0 : sreg;
+
+		if (!bt_is_reg_set(bt, load_reg))
 			return 0;
-		bt_clear_reg(bt, dreg);
+		bt_clear_reg(bt, load_reg);
 
 		/* scalars can only be spilled into stack w/o losing precision.
 		 * Load from any other memory can be zero extended.

```


---
## efc11a667878 — bpf: Improve bounds when tnum has a single possible value

```diff
 kernel/bpf/verifier.c | 30 ++++++++++++++++++++++++++++++
 1 file changed, 30 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index bb12ba020649..401d6c4960ec 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -2379,6 +2379,9 @@ static void __update_reg32_bounds(struct bpf_reg_state *reg)
 
 static void __update_reg64_bounds(struct bpf_reg_state *reg)
 {
+	u64 tnum_next, tmax;
+	bool umin_in_tnum;
+
 	/* min signed is max(sign bit) | min(other bits) */
 	reg->smin_value = max_t(s64, reg->smin_value,
 				reg->var_off.value | (reg->var_off.mask & S64_MIN));
@@ -2388,6 +2391,33 @@ static void __update_reg64_bounds(struct bpf_reg_state *reg)
 	reg->umin_value = max(reg->umin_value, reg->var_off.value);
 	reg->umax_value = min(reg->umax_value,
 			      reg->var_off.value | reg->var_off.mask);
+
+	/* Check if u64 and tnum overlap in a single value */
+	tnum_next = tnum_step(reg->var_off, reg->umin_value);
+	umin_in_tnum = (reg->umin_value & ~reg->var_off.mask) == reg->var_off.value;
+	tmax = reg->var_off.value | reg->var_off.mask;
+	if (umin_in_tnum && tnum_next > reg->umax_value) {
+		/* The u64 range and the tnum only overlap in umin.
+		 * u64:  ---[xxxxxx]-----
+		 * tnum: --xx----------x-
+		 */
+		___mark_reg_known(reg, reg->umin_value);
+	} else if (!umin_in_tnum && tnum_next == tmax) {
+		/* The u64 range and the tnum only overlap in the maximum value
+		 * represented by the tnum, called tmax.
+		 * u64:  ---[xxxxxx]-----
+		 * tnum: xx-----x--------
+		 */
+		___mark_reg_known(reg, tmax);
+	} else if (!umin_in_tnum && tnum_next <= reg->umax_value &&
+		   tnum_step(reg->var_off, tnum_next) > reg->umax_value) {
+		/* The u64 range and the tnum only overlap in between umin
+		 * (excluded) and umax.
+		 * u64:  ---[xxxxxx]-----
+		 * tnum: xx----x-------x-
+		 */
+		___mark_reg_known(reg, tnum_next);
+	}
 }
 
 static void __update_reg_bounds(struct bpf_reg_state *reg)

```


---
## e2d2115e56c4 — bpf: Do not include stack ptr register in precision backtracking bookkeeping

```diff
 include/linux/bpf_verifier.h | 12 ++++++++----
 kernel/bpf/verifier.c        | 18 ++++++++++++++++--
 2 files changed, 24 insertions(+), 6 deletions(-)

diff --git a/include/linux/bpf_verifier.h b/include/linux/bpf_verifier.h
index 78c97e12ea4e..256274acb1d8 100644
--- a/include/linux/bpf_verifier.h
+++ b/include/linux/bpf_verifier.h
@@ -356,7 +356,11 @@ enum {
 	INSN_F_SPI_MASK = 0x3f, /* 6 bits */
 	INSN_F_SPI_SHIFT = 3, /* shifted 3 bits to the left */
 
-	INSN_F_STACK_ACCESS = BIT(9), /* we need 10 bits total */
+	INSN_F_STACK_ACCESS = BIT(9),
+
+	INSN_F_DST_REG_STACK = BIT(10), /* dst_reg is PTR_TO_STACK */
+	INSN_F_SRC_REG_STACK = BIT(11), /* src_reg is PTR_TO_STACK */
+	/* total 12 bits are used now. */
 };
 
 static_assert(INSN_F_FRAMENO_MASK + 1 >= MAX_CALL_FRAMES);
@@ -365,9 +369,9 @@ static_assert(INSN_F_SPI_MASK + 1 >= MAX_BPF_STACK / 8);
 struct bpf_insn_hist_entry {
 	u32 idx;
 	/* insn idx can't be bigger than 1 million */
-	u32 prev_idx : 22;
-	/* special flags, e.g., whether insn is doing register stack spill/load */
-	u32 flags : 10;
+	u32 prev_idx : 20;
+	/* special INSN_F_xxx flags */
+	u32 flags : 12;
 	/* additional registers that need precision tracking when this
 	 * jump is backtracked, vector of six 10-bit records
 	 */
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 99582e5a8c69..98c52829936e 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -4410,8 +4410,10 @@ static int backtrack_insn(struct bpf_verifier_env *env, int idx, int subseq_idx,
 			 * before it would be equally necessary to
 			 * propagate it to dreg.
 			 */
-			bt_set_reg(bt, dreg);
-			bt_set_reg(bt, sreg);
+			if (!hist || !(hist->flags & INSN_F_SRC_REG_STACK))
+				bt_set_reg(bt, sreg);
+			if (!hist || !(hist->flags & INSN_F_DST_REG_STACK))
+				bt_set_reg(bt, dreg);
 		} else if (BPF_SRC(insn->code) == BPF_K) {
 			 /* dreg <cond> K
 			  * Only dreg still needs precision before
@@ -16392,6 +16394,7 @@ static int check_cond_jmp_op(struct bpf_verifier_env *env,
 	struct bpf_reg_state *eq_branch_regs;
 	struct linked_regs linked_regs = {};
 	u8 opcode = BPF_OP(insn->code);
+	int insn_flags = 0;
 	bool is_jmp32;
 	int pred = -1;
 	int err;
@@ -16450,6 +16453,9 @@ static int check_cond_jmp_op(struct bpf_verifier_env *env,
 				insn->src_reg);
 			return -EACCES;
 		}
+
+		if (src_reg->type == PTR_TO_STACK)
+			insn_flags |= INSN_F_SRC_REG_STACK;
 	} else {
 		if (insn->src_reg != BPF_REG_0) {
 			verbose(env, "BPF_JMP/JMP32 uses reserved fields\n");
@@ -16461,6 +16467,14 @@ static int check_cond_jmp_op(struct bpf_verifier_env *env,
 		__mark_reg_known(src_reg, insn->imm);
 	}
 
+	if (dst_reg->type == PTR_TO_STACK)
+		insn_flags |= INSN_F_DST_REG_STACK;
+	if (insn_flags) {
+		err = push_insn_history(env, this_branch, insn_flags, 0);
+		if (err)
+			return err;
+	}
+
 	is_jmp32 = BPF_CLASS(insn->code) == BPF_JMP32;
 	pred = is_branch_taken(dst_reg, src_reg, opcode, is_jmp32);
 	if (pred >= 0) {

```


---
## c03bb2fa327e — bpf: Fix out-of-bounds read in check_atomic_load/store()

```diff
 kernel/bpf/verifier.c | 16 ++++++++++++++--
 1 file changed, 14 insertions(+), 2 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 41fd93db8258..8ad7338e726b 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -7788,6 +7788,12 @@ static int check_atomic_rmw(struct bpf_verifier_env *env,
 static int check_atomic_load(struct bpf_verifier_env *env,
 			     struct bpf_insn *insn)
 {
+	int err;
+
+	err = check_load_mem(env, insn, true, false, false, "atomic_load");
+	if (err)
+		return err;
+
 	if (!atomic_ptr_type_ok(env, insn->src_reg, insn)) {
 		verbose(env, "BPF_ATOMIC loads from R%d %s is not allowed\n",
 			insn->src_reg,
@@ -7795,12 +7801,18 @@ static int check_atomic_load(struct bpf_verifier_env *env,
 		return -EACCES;
 	}
 
-	return check_load_mem(env, insn, true, false, false, "atomic_load");
+	return 0;
 }
 
 static int check_atomic_store(struct bpf_verifier_env *env,
 			      struct bpf_insn *insn)
 {
+	int err;
+
+	err = check_store_reg(env, insn, true);
+	if (err)
+		return err;
+
 	if (!atomic_ptr_type_ok(env, insn->dst_reg, insn)) {
 		verbose(env, "BPF_ATOMIC stores into R%d %s is not allowed\n",
 			insn->dst_reg,
@@ -7808,7 +7820,7 @@ static int check_atomic_store(struct bpf_verifier_env *env,
 		return -EACCES;
 	}
 
-	return check_store_reg(env, insn, true);
+	return 0;
 }
 
 static int check_atomic(struct bpf_verifier_env *env, struct bpf_insn *insn)

```


---
## b0e66977dc07 — bpf: Fix narrow scalar spill onto 64-bit spilled scalar slots

```diff
 kernel/bpf/verifier.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index f18aad339de8..01fbef9576e0 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -4703,6 +4703,7 @@ static int check_stack_write_fixed_off(struct bpf_verifier_env *env,
 	 */
 	if (!env->allow_ptr_leaks &&
 	    is_spilled_reg(&state->stack[spi]) &&
+	    !is_spilled_scalar_reg(&state->stack[spi]) &&
 	    size != BPF_REG_SIZE) {
 		verbose(env, "attempt to corrupt spilled pointer on stack\n");
 		return -EACCES;

```


---
## d0b98f6a17a5 — bpf: disallow 40-bytes extra stack for bpf_fastcall patterns

```diff
 kernel/bpf/verifier.c | 14 ++------------
 1 file changed, 2 insertions(+), 12 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 3254c27085b8..bb99bada7e2e 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -6804,20 +6804,10 @@ static int check_stack_slot_within_bounds(struct bpf_verifier_env *env,
                                           struct bpf_func_state *state,
                                           enum bpf_access_type t)
 {
-	struct bpf_insn_aux_data *aux = &env->insn_aux_data[env->insn_idx];
-	int min_valid_off, max_bpf_stack;
-
-	/* If accessing instruction is a spill/fill from bpf_fastcall pattern,
-	 * add room for all caller saved registers below MAX_BPF_STACK.
-	 * In case if bpf_fastcall rewrite won't happen maximal stack depth
-	 * would be checked by check_max_stack_depth_subprog().
-	 */
-	max_bpf_stack = MAX_BPF_STACK;
-	if (aux->fastcall_pattern)
-		max_bpf_stack += CALLER_SAVED_REGS * BPF_REG_SIZE;
+	int min_valid_off;
 
 	if (t == BPF_WRITE || env->allow_uninit_stack)
-		min_valid_off = -max_bpf_stack;
+		min_valid_off = -MAX_BPF_STACK;
 	else
 		min_valid_off = -state->allocated_stack;
 

```


---
## aa30eb3260b2 — bpf: Force checkpoint when jmp history is too long

```diff
 kernel/bpf/verifier.c | 9 ++++++---
 1 file changed, 6 insertions(+), 3 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 587a6c76e564..3254c27085b8 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -17886,9 +17886,11 @@ static int is_state_visited(struct bpf_verifier_env *env, int insn_idx)
 	struct bpf_verifier_state_list *sl, **pprev;
 	struct bpf_verifier_state *cur = env->cur_state, *new, *loop_entry;
 	int i, j, n, err, states_cnt = 0;
-	bool force_new_state = env->test_state_freq || is_force_checkpoint(env, insn_idx);
-	bool add_new_state = force_new_state;
-	bool force_exact;
+	bool force_new_state, add_new_state, force_exact;
+
+	force_new_state = env->test_state_freq || is_force_checkpoint(env, insn_idx) ||
+			  /* Avoid accumulating infinitely long jmp history */
+			  cur->jmp_history_cnt > 40;
 
 	/* bpf progs typically have pruning point every 4 instructions
 	 * http://vger.kernel.org/bpfconf2019.html#session-1
@@ -17898,6 +17900,7 @@ static int is_state_visited(struct bpf_verifier_env *env, int insn_idx)
 	 * In tests that amounts to up to 50% reduction into total verifier
 	 * memory consumption and 20% verifier time speedup.
 	 */
+	add_new_state = force_new_state;
 	if (env->jmps_processed - env->prev_jmps_processed >= 2 &&
 	    env->insn_processed - env->prev_insn_processed >= 8)
 		add_new_state = true;

```


---
## 8ea607330a39 — bpf: Fix overloading of MEM_UNINIT's meaning

```diff
 kernel/bpf/verifier.c | 73 ++++++++++++++++++++++++---------------------------
 1 file changed, 35 insertions(+), 38 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 411ab1b57af4..f9e2f1cd4975 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -7438,7 +7438,8 @@ static int check_stack_range_initialized(
 }
 
 static int check_helper_mem_access(struct bpf_verifier_env *env, int regno,
-				   int access_size, bool zero_size_allowed,
+				   int access_size, enum bpf_access_type access_type,
+				   bool zero_size_allowed,
 				   struct bpf_call_arg_meta *meta)
 {
 	struct bpf_reg_state *regs = cur_regs(env), *reg = &regs[regno];
@@ -7450,7 +7451,7 @@ static int check_helper_mem_access(struct bpf_verifier_env *env, int regno,
 		return check_packet_access(env, regno, reg->off, access_size,
 					   zero_size_allowed);
 	case PTR_TO_MAP_KEY:
-		if (meta && meta->raw_mode) {
+		if (access_type == BPF_WRITE) {
 			verbose(env, "R%d cannot write into %s\n", regno,
 				reg_type_str(env, reg->type));
 			return -EACCES;
@@ -7458,15 +7459,13 @@ static int check_helper_mem_access(struct bpf_verifier_env *env, int regno,
 		return check_mem_region_access(env, regno, reg->off, access_size,
 					       reg->map_ptr->key_size, false);
 	case PTR_TO_MAP_VALUE:
-		if (check_map_access_type(env, regno, reg->off, access_size,
-					  meta && meta->raw_mode ? BPF_WRITE :
-					  BPF_READ))
+		if (check_map_access_type(env, regno, reg->off, access_size, access_type))
 			return -EACCES;
 		return check_map_access(env, regno, reg->off, access_size,
 					zero_size_allowed, ACCESS_HELPER);
 	case PTR_TO_MEM:
 		if (type_is_rdonly_mem(reg->type)) {
-			if (meta && meta->raw_mode) {
+			if (access_type == BPF_WRITE) {
 				verbose(env, "R%d cannot write into %s\n", regno,
 					reg_type_str(env, reg->type));
 				return -EACCES;
@@ -7477,7 +7476,7 @@ static int check_helper_mem_access(struct bpf_verifier_env *env, int regno,
 					       zero_size_allowed);
 	case PTR_TO_BUF:
 		if (type_is_rdonly_mem(reg->type)) {
-			if (meta && meta->raw_mode) {
+			if (access_type == BPF_WRITE) {
 				verbose(env, "R%d cannot write into %s\n", regno,
 					reg_type_str(env, reg->type));
 				return -EACCES;
@@ -7505,7 +7504,6 @@ static int check_helper_mem_access(struct bpf_verifier_env *env, int regno,
 		 * Dynamically check it now.
 		 */
 		if (!env->ops->convert_ctx_access) {
-			enum bpf_access_type atype = meta && meta->raw_mode ? BPF_WRITE : BPF_READ;
 			int offset = access_size - 1;
 
 			/* Allow zero-byte read from PTR_TO_CTX */
@@ -7513,7 +7511,7 @@ static int check_helper_mem_access(struct bpf_verifier_env *env, int regno,
 				return zero_size_allowed ? 0 : -EACCES;
 
 			return check_mem_access(env, env->insn_idx, regno, offset, BPF_B,
-						atype, -1, false, false);
+						access_type, -1, false, false);
 		}
 
 		fallthrough;
@@ -7538,6 +7536,7 @@ static int check_helper_mem_access(struct bpf_verifier_env *env, int regno,
  */
 static int check_mem_size_reg(struct bpf_verifier_env *env,
 			      struct bpf_reg_state *reg, u32 regno,
+			      enum bpf_access_type access_type,
 			      bool zero_size_allowed,
 			      struct bpf_call_arg_meta *meta)
 {
@@ -7553,15 +7552,12 @@ static int check_mem_size_reg(struct bpf_verifier_env *env,
 	 */
 	meta->msize_max_value = reg->umax_value;
 
-	/* The register is SCALAR_VALUE; the access check
-	 * happens using its boundaries.
+	/* The register is SCALAR_VALUE; the access check happens using
+	 * its boundaries. For unprivileged variable accesses, disable
+	 * raw mode so that the program is required to initialize all
+	 * the memory that the helper could just partially fill up.
 	 */
 	if (!tnum_is_const(reg->var_off))
-		/* For unprivileged variable accesses, disable raw
-		 * mode so that the program is required to
-		 * initialize all the memory that the helper could
-		 * just partially fill up.
-		 */
 		meta = NULL;
 
 	if (reg->smin_value < 0) {
@@ -7581,9 +7577,8 @@ static int check_mem_size_reg(struct bpf_verifier_env *env,
 			regno);
 		return -EACCES;
 	}
-	err = check_helper_mem_access(env, regno - 1,
-				      reg->umax_value,
-				      zero_size_allowed, meta);
+	err = check_helper_mem_access(env, regno - 1, reg->umax_value,
+				      access_type, zero_size_allowed, meta);
 	if (!err)
 		err = mark_chain_precision(env, regno);
 	return err;
@@ -7594,13 +7589,11 @@ static int check_mem_reg(struct bpf_verifier_env *env, struct bpf_reg_state *reg
 {
 	bool may_be_null = type_may_be_null(reg->type);
 	struct bpf_reg_state saved_reg;
-	struct bpf_call_arg_meta meta;
 	int err;
 
 	if (register_is_null(reg))
 		return 0;
 
-	memset(&meta, 0, sizeof(meta));
 	/* Assuming that the register contains a value check if the memory
 	 * access is safe. Temporarily save and restore the register's state as
 	 * the conversion shouldn't be visible to a caller.
@@ -7610,10 +7603,8 @@ static int check_mem_reg(struct bpf_verifier_env *env, struct bpf_reg_state *reg
 		mark_ptr_not_null_reg(reg);
 	}
 
-	err = check_helper_mem_access(env, regno, mem_size, true, &meta);
-	/* Check access for BPF_WRITE */
-	meta.raw_mode = true;
-	err = err ?: check_helper_mem_access(env, regno, mem_size, true, &meta);
+	err = check_helper_mem_access(env, regno, mem_size, BPF_READ, true, NULL);
+	err = err ?: check_helper_mem_access(env, regno, mem_size, BPF_WRITE, true, NULL);
 
 	if (may_be_null)
 		*reg = saved_reg;
@@ -7639,13 +7630,12 @@ static int check_kfunc_mem_size_reg(struct bpf_verifier_env *env, struct bpf_reg
 		mark_ptr_not_null_reg(mem_reg);
 	}
 
-	err = check_mem_size_reg(env, reg, regno, true, &meta);
-	/* Check access for BPF_WRITE */
-	meta.raw_mode = true;
-	err = err ?: check_mem_size_reg(env, reg, regno, true, &meta);
+	err = check_mem_size_reg(env, reg, regno, BPF_READ, true, &meta);
+	err = err ?: check_mem_size_reg(env, reg, regno, BPF_WRITE, true, &meta);
 
 	if (may_be_null)
 		*mem_reg = saved_reg;
+
 	return err;
 }
 
@@ -8948,9 +8938,8 @@ static int check_func_arg(struct bpf_verifier_env *env, u32 arg,
 			verbose(env, "invalid map_ptr to access map->key\n");
 			return -EACCES;
 		}
-		err = check_helper_mem_access(env, regno,
-					      meta->map_ptr->key_size, false,
-					      NULL);
+		err = check_helper_mem_access(env, regno, meta->map_ptr->key_size,
+					      BPF_READ, false, NULL);
 		break;
 	case ARG_PTR_TO_MAP_VALUE:
 		if (type_may_be_null(arg_type) && register_is_null(reg))
@@ -8965,9 +8954,9 @@ static int check_func_arg(struct bpf_verifier_env *env, u32 arg,
 			return -EACCES;
 		}
 		meta->raw_mode = arg_type & MEM_UNINIT;
-		err = check_helper_mem_access(env, regno,
-					      meta->map_ptr->value_size, false,
-					      meta);
+		err = check_helper_mem_access(env, regno, meta->map_ptr->value_size,
+					      arg_type & MEM_WRITE ? BPF_WRITE : BPF_READ,
+					      false, meta);
 		break;
 	case ARG_PTR_TO_PERCPU_BTF_ID:
 		if (!reg->btf_id) {
@@ -9009,7 +8998,9 @@ static int check_func_arg(struct bpf_verifier_env *env, u32 arg,
 		 */
 		meta->raw_mode = arg_type & MEM_UNINIT;
 		if (arg_type & MEM_FIXED_SIZE) {
-			err = check_helper_mem_access(env, regno, fn->arg_size[arg], false, meta);
+			err = check_helper_mem_access(env, regno, fn->arg_size[arg],
+						      arg_type & MEM_WRITE ? BPF_WRITE : BPF_READ,
+						      false, meta);
 			if (err)
 				return err;
 			if (arg_type & MEM_ALIGNED)
@@ -9017,10 +9008,16 @@ static int check_func_arg(struct bpf_verifier_env *env, u32 arg,
 		}
 		break;
 	case ARG_CONST_SIZE:
-		err = check_mem_size_reg(env, reg, regno, false, meta);
+		err = check_mem_size_reg(env, reg, regno,
+					 fn->arg_type[arg - 1] & MEM_WRITE ?
+					 BPF_WRITE : BPF_READ,
+					 false, meta);
 		break;
 	case ARG_CONST_SIZE_OR_ZERO:
-		err = check_mem_size_reg(env, reg, regno, true, meta);
+		err = check_mem_size_reg(env, reg, regno,
+					 fn->arg_type[arg - 1] & MEM_WRITE ?
+					 BPF_WRITE : BPF_READ,
+					 true, meta);
 		break;
 	case ARG_PTR_TO_DYNPTR:
 		err = process_dynptr_func(env, regno, insn_idx, arg_type, 0);

```


---
## 763aa759d3b2 — bpf: Fix compare error in function retval_range_within

```diff
 kernel/bpf/verifier.c | 16 +++++++++++-----
 1 file changed, 11 insertions(+), 5 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 8caa7322f031..c419005a29dc 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -9984,9 +9984,13 @@ static bool in_rbtree_lock_required_cb(struct bpf_verifier_env *env)
 	return is_rbtree_lock_required_kfunc(kfunc_btf_id);
 }
 
-static bool retval_range_within(struct bpf_retval_range range, const struct bpf_reg_state *reg)
+static bool retval_range_within(struct bpf_retval_range range, const struct bpf_reg_state *reg,
+				bool return_32bit)
 {
-	return range.minval <= reg->smin_value && reg->smax_value <= range.maxval;
+	if (return_32bit)
+		return range.minval <= reg->s32_min_value && reg->s32_max_value <= range.maxval;
+	else
+		return range.minval <= reg->smin_value && reg->smax_value <= range.maxval;
 }
 
 static int prepare_func_exit(struct bpf_verifier_env *env, int *insn_idx)
@@ -10023,8 +10027,8 @@ static int prepare_func_exit(struct bpf_verifier_env *env, int *insn_idx)
 		if (err)
 			return err;
 
-		/* enforce R0 return value range */
-		if (!retval_range_within(callee->callback_ret_range, r0)) {
+		/* enforce R0 return value range, and bpf_callback_t returns 64bit */
+		if (!retval_range_within(callee->callback_ret_range, r0, false)) {
 			verbose_invalid_scalar(env, r0, callee->callback_ret_range,
 					       "At callback return", "R0");
 			return -EINVAL;
@@ -15698,6 +15702,7 @@ static int check_return_code(struct bpf_verifier_env *env, int regno, const char
 	int err;
 	struct bpf_func_state *frame = env->cur_state->frame[0];
 	const bool is_subprog = frame->subprogno;
+	bool return_32bit = false;
 
 	/* LSM and struct_ops func-ptr's return type could be "void" */
 	if (!is_subprog || frame->in_exception_callback_fn) {
@@ -15809,6 +15814,7 @@ static int check_return_code(struct bpf_verifier_env *env, int regno, const char
 			/* no restricted range, any return value is allowed */
 			if (range.minval == S32_MIN && range.maxval == S32_MAX)
 				return 0;
+			return_32bit = true;
 		} else if (!env->prog->aux->attach_func_proto->type) {
 			/* Make sure programs that attach to void
 			 * hooks don't try to modify return value.
@@ -15839,7 +15845,7 @@ static int check_return_code(struct bpf_verifier_env *env, int regno, const char
 	if (err)
 		return err;
 
-	if (!retval_range_within(range, reg)) {
+	if (!retval_range_within(range, reg, return_32bit)) {
 		verbose_invalid_scalar(env, reg, range, exit_ctx, reg_name);
 		if (!is_subprog &&
 		    prog->expected_attach_type == BPF_LSM_CGROUP &&

```


---
## 4bf79f9be434 — bpf: Track equal scalars history on per-instruction level

```diff
 include/linux/bpf_verifier.h |   4 +
 kernel/bpf/verifier.c        | 245 +++++++++++++++++++++++++++++++++++++++----
 2 files changed, 228 insertions(+), 21 deletions(-)

diff --git a/include/linux/bpf_verifier.h b/include/linux/bpf_verifier.h
index 6503c85b10a3..731a0a4ac13c 100644
--- a/include/linux/bpf_verifier.h
+++ b/include/linux/bpf_verifier.h
@@ -371,6 +371,10 @@ struct bpf_jmp_history_entry {
 	u32 prev_idx : 22;
 	/* special flags, e.g., whether insn is doing register stack spill/load */
 	u32 flags : 10;
+	/* additional registers that need precision tracking when this
+	 * jump is backtracked, vector of six 10-bit records
+	 */
+	u64 linked_regs;
 };
 
 /* Maximum number of register states that can exist at once */
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 4cb5441ad75f..8dade7b51430 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -3335,9 +3335,87 @@ static bool is_jmp_point(struct bpf_verifier_env *env, int insn_idx)
 	return env->insn_aux_data[insn_idx].jmp_point;
 }
 
+#define LR_FRAMENO_BITS	3
+#define LR_SPI_BITS	6
+#define LR_ENTRY_BITS	(LR_SPI_BITS + LR_FRAMENO_BITS + 1)
+#define LR_SIZE_BITS	4
+#define LR_FRAMENO_MASK	((1ull << LR_FRAMENO_BITS) - 1)
+#define LR_SPI_MASK	((1ull << LR_SPI_BITS)     - 1)
+#define LR_SIZE_MASK	((1ull << LR_SIZE_BITS)    - 1)
+#define LR_SPI_OFF	LR_FRAMENO_BITS
+#define LR_IS_REG_OFF	(LR_SPI_BITS + LR_FRAMENO_BITS)
+#define LINKED_REGS_MAX	6
+
+struct linked_reg {
+	u8 frameno;
+	union {
+		u8 spi;
+		u8 regno;
+	};
+	bool is_reg;
+};
+
+struct linked_regs {
+	int cnt;
+	struct linked_reg entries[LINKED_REGS_MAX];
+};
+
+static struct linked_reg *linked_regs_push(struct linked_regs *s)
+{
+	if (s->cnt < LINKED_REGS_MAX)
+		return &s->entries[s->cnt++];
+
+	return NULL;
+}
+
+/* Use u64 as a vector of 6 10-bit values, use first 4-bits to track
+ * number of elements currently in stack.
+ * Pack one history entry for linked registers as 10 bits in the following format:
+ * - 3-bits frameno
+ * - 6-bits spi_or_reg
+ * - 1-bit  is_reg
+ */
+static u64 linked_regs_pack(struct linked_regs *s)
+{
+	u64 val = 0;
+	int i;
+
+	for (i = 0; i < s->cnt; ++i) {
+		struct linked_reg *e = &s->entries[i];
+		u64 tmp = 0;
+
+		tmp |= e->frameno;
+		tmp |= e->spi << LR_SPI_OFF;
+		tmp |= (e->is_reg ? 1 : 0) << LR_IS_REG_OFF;
+
+		val <<= LR_ENTRY_BITS;
+		val |= tmp;
+	}
+	val <<= LR_SIZE_BITS;
+	val |= s->cnt;
+	return val;
+}
+
+static void linked_regs_unpack(u64 val, struct linked_regs *s)
+{
+	int i;
+
+	s->cnt = val & LR_SIZE_MASK;
+	val >>= LR_SIZE_BITS;
+
+	for (i = 0; i < s->cnt; ++i) {
+		struct linked_reg *e = &s->entries[i];
+
+		e->frameno =  val & LR_FRAMENO_MASK;
+		e->spi     = (val >> LR_SPI_OFF) & LR_SPI_MASK;
+		e->is_reg  = (val >> LR_IS_REG_OFF) & 0x1;
+		val >>= LR_ENTRY_BITS;
+	}
+}
+
 /* for any branch, call, exit record the history of jmps in the given state */
 static int push_jmp_history(struct bpf_verifier_env *env, struct bpf_verifier_state *cur,
-			    int insn_flags)
+			    int insn_flags, u64 linked_regs)
 {
 	u32 cnt = cur->jmp_history_cnt;
 	struct bpf_jmp_history_entry *p;
@@ -3353,6 +3431,10 @@ static int push_jmp_history(struct bpf_verifier_env *env, struct bpf_verifier_st
 			  "verifier insn history bug: insn_idx %d cur flags %x new flags %x\n",
 			  env->insn_idx, env->cur_hist_ent->flags, insn_flags);
 		env->cur_hist_ent->flags |= insn_flags;
+		WARN_ONCE(env->cur_hist_ent->linked_regs != 0,
+			  "verifier insn history bug: insn_idx %d linked_regs != 0: %#llx\n",
+			  env->insn_idx, env->cur_hist_ent->linked_regs);
+		env->cur_hist_ent->linked_regs = linked_regs;
 		return 0;
 	}
 
@@ -3367,6 +3449,7 @@ static int push_jmp_history(struct bpf_verifier_env *env, struct bpf_verifier_st
 	p->idx = env->insn_idx;
 	p->prev_idx = env->prev_insn_idx;
 	p->flags = insn_flags;
+	p->linked_regs = linked_regs;
 	cur->jmp_history_cnt = cnt;
 	env->cur_hist_ent = p;
 
@@ -3532,6 +3615,11 @@ static inline bool bt_is_reg_set(struct backtrack_state *bt, u32 reg)
 	return bt->reg_masks[bt->frame] & (1 << reg);
 }
 
+static inline bool bt_is_frame_reg_set(struct backtrack_state *bt, u32 frame, u32 reg)
+{
+	return bt->reg_masks[frame] & (1 << reg);
+}
+
 static inline bool bt_is_frame_slot_set(struct backtrack_state *bt, u32 frame, u32 slot)
 {
 	return bt->stack_masks[frame] & (1ull << slot);
@@ -3576,6 +3664,42 @@ static void fmt_stack_mask(char *buf, ssize_t buf_sz, u64 stack_mask)
 	}
 }
 
+/* If any register R in hist->linked_regs is marked as precise in bt,
+ * do bt_set_frame_{reg,slot}(bt, R) for all registers in hist->linked_regs.
+ */
+static void bt_sync_linked_regs(struct backtrack_state *bt, struct bpf_jmp_history_entry *hist)
+{
+	struct linked_regs linked_regs;
+	bool some_precise = false;
+	int i;
+
+	if (!hist || hist->linked_regs == 0)
+		return;
+
+	linked_regs_unpack(hist->linked_regs, &linked_regs);
+	for (i = 0; i < linked_regs.cnt; ++i) {
+		struct linked_reg *e = &linked_regs.entries[i];
+
+		if ((e->is_reg && bt_is_frame_reg_set(bt, e->frameno, e->regno)) ||
+		    (!e->is_reg && bt_is_frame_slot_set(bt, e->frameno, e->spi))) {
+			some_precise = true;
+			break;
+		}
+	}
+
+	if (!some_precise)
+		return;
+
+	for (i = 0; i < linked_regs.cnt; ++i) {
+		struct linked_reg *e = &linked_regs.entries[i];
+
+		if (e->is_reg)
+			bt_set_frame_reg(bt, e->frameno, e->regno);
+		else
+			bt_set_frame_slot(bt, e->frameno, e->spi);
+	}
+}
+
 static bool calls_callback(struct bpf_verifier_env *env, int insn_idx);
 
 /* For given verifier state backtrack_insn() is called from the last insn to
@@ -3615,6 +3739,12 @@ static int backtrack_insn(struct bpf_verifier_env *env, int idx, int subseq_idx,
 		print_bpf_insn(&cbs, insn, env->allow_ptr_leaks);
 	}
 
+	/* If there is a history record that some registers gained range at this insn,
+	 * propagate precision marks to those registers, so that bt_is_reg_set()
+	 * accounts for these registers.
+	 */
+	bt_sync_linked_regs(bt, hist);
+
 	if (class == BPF_ALU || class == BPF_ALU64) {
 		if (!bt_is_reg_set(bt, dreg))
 			return 0;
@@ -3844,7 +3974,8 @@ static int backtrack_insn(struct bpf_verifier_env *env, int idx, int subseq_idx,
 			 */
 			bt_set_reg(bt, dreg);
 			bt_set_reg(bt, sreg);
-			 /* else dreg <cond> K
+		} else if (BPF_SRC(insn->code) == BPF_K) {
+			 /* dreg <cond> K
 			  * Only dreg still needs precision before
 			  * this insn, so for the K-based conditional
 			  * there is nothing new to be marked.
@@ -3862,6 +3993,10 @@ static int backtrack_insn(struct bpf_verifier_env *env, int idx, int subseq_idx,
 			/* to be analyzed */
 			return -ENOTSUPP;
 	}
+	/* Propagate precision marks to linked registers, to account for
+	 * registers marked as precise in this function.
+	 */
+	bt_sync_linked_regs(bt, hist);
 	return 0;
 }
 
@@ -4456,7 +4591,7 @@ static void assign_scalar_id_before_mov(struct bpf_verifier_env *env,
 
 	if (!src_reg->id && !tnum_is_const(src_reg->var_off))
 		/* Ensure that src_reg has a valid ID that will be copied to
-		 * dst_reg and then will be used by find_equal_scalars() to
+		 * dst_reg and then will be used by sync_linked_regs() to
 		 * propagate min/max range.
 		 */
 		src_reg->id = ++env->id_gen;
@@ -4625,7 +4760,7 @@ static int check_stack_write_fixed_off(struct bpf_verifier_env *env,
 	}
 
 	if (insn_flags)
-		return push_jmp_history(env, env->cur_state, insn_flags);
+		return push_jmp_history(env, env->cur_state, insn_flags, 0);
 	return 0;
 }
 
@@ -4930,7 +5065,7 @@ static int check_stack_read_fixed_off(struct bpf_verifier_env *env,
 		insn_flags = 0; /* we are not restoring spilled register */
 	}
 	if (insn_flags)
-		return push_jmp_history(env, env->cur_state, insn_flags);
+		return push_jmp_history(env, env->cur_state, insn_flags, 0);
 	return 0;
 }
 
@@ -14099,7 +14234,7 @@ static int adjust_reg_min_max_vals(struct bpf_verifier_env *env,
 		u64 val = reg_const_value(src_reg, alu32);
 
 		if ((dst_reg->id & BPF_ADD_CONST) ||
-		    /* prevent overflow in find_equal_scalars() later */
+		    /* prevent overflow in sync_linked_regs() later */
 		    val > (u32)S32_MAX) {
 			/*
 			 * If the register already went through rX += val
@@ -14114,7 +14249,7 @@ static int adjust_reg_min_max_vals(struct bpf_verifier_env *env,
 	} else {
 		/*
 		 * Make sure ID is cleared otherwise dst_reg min/max could be
-		 * incorrectly propagated into other registers by find_equal_scalars()
+		 * incorrectly propagated into other registers by sync_linked_regs()
 		 */
 		dst_reg->id = 0;
 	}
@@ -14264,7 +14399,7 @@ static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
 						copy_register_state(dst_reg, src_reg);
 						/* Make sure ID is cleared if src_reg is not in u32
 						 * range otherwise dst_reg min/max could be incorrectly
-						 * propagated into src_reg by find_equal_scalars()
+						 * propagated into src_reg by sync_linked_regs()
 						 */
 						if (!is_src_reg_u32)
 							dst_reg->id = 0;
@@ -15087,14 +15
... [diff truncated at 9000 chars; the touched functions are all above]

```


---
## 44b7f7151dfc — bpf: Add missed var_off setting in coerce_subreg_to_size_sx()

```diff
 kernel/bpf/verifier.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 904ef5a03cf5..e0a398a97d32 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -6281,6 +6281,7 @@ static void coerce_subreg_to_size_sx(struct bpf_reg_state *reg, int size)
 		reg->s32_max_value = s32_max;
 		reg->u32_min_value = (u32)s32_min;
 		reg->u32_max_value = (u32)s32_max;
+		reg->var_off = tnum_subreg(tnum_range(s32_min, s32_max));
 		return;
 	}
 

```


---
## 380d5f89a481 — bpf: Add missed var_off setting in set_sext32_default_val()

```diff
 kernel/bpf/verifier.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 010cfee7ffe9..904ef5a03cf5 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -6236,6 +6236,7 @@ static void set_sext32_default_val(struct bpf_reg_state *reg, int size)
 	}
 	reg->u32_min_value = 0;
 	reg->u32_max_value = U32_MAX;
+	reg->var_off = tnum_subreg(tnum_unknown);
 }
 
 static void coerce_subreg_to_size_sx(struct bpf_reg_state *reg, int size)

```


---
## 22c7fa171a02 — bpf: Reject variable offset alu on PTR_TO_FLOW_KEYS

```diff
 kernel/bpf/verifier.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index adbf330d364b..65f598694d55 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -12826,6 +12826,10 @@ static int adjust_ptr_min_max_vals(struct bpf_verifier_env *env,
 	}
 
 	switch (base_type(ptr_reg->type)) {
+	case PTR_TO_FLOW_KEYS:
+		if (known)
+			break;
+		fallthrough;
 	case CONST_PTR_TO_MAP:
 		/* smin_val represents the known value */
 		if (known && smin_val == 0 && opcode == BPF_ADD)

```


---
## 6b4a64bafd10 — bpf: Fix accesses to uninit stack slots

```diff
 kernel/bpf/verifier.c | 65 +++++++++++++++++++++------------------------------
 1 file changed, 26 insertions(+), 39 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 0e77bb52542d..de1e29fa467e 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -1259,7 +1259,10 @@ static int resize_reference_state(struct bpf_func_state *state, size_t n)
 	return 0;
 }
 
-static int grow_stack_state(struct bpf_func_state *state, int size)
+/* Possibly update state->allocated_stack to be at least size bytes. Also
+ * possibly update the function's high-water mark in its bpf_subprog_info.
+ */
+static int grow_stack_state(struct bpf_verifier_env *env, struct bpf_func_state *state, int size)
 {
 	size_t old_n = state->allocated_stack / BPF_REG_SIZE, n = size / BPF_REG_SIZE;
 
@@ -1271,6 +1274,11 @@ static int grow_stack_state(struct bpf_func_state *state, int size)
 		return -ENOMEM;
 
 	state->allocated_stack = size;
+
+	/* update known max for given subprogram */
+	if (env->subprog_info[state->subprogno].stack_depth < size)
+		env->subprog_info[state->subprogno].stack_depth = size;
+
 	return 0;
 }
 
@@ -4440,9 +4448,6 @@ static int check_stack_write_fixed_off(struct bpf_verifier_env *env,
 	struct bpf_reg_state *reg = NULL;
 	int insn_flags = insn_stack_access_flags(state->frameno, spi);
 
-	err = grow_stack_state(state, round_up(slot + 1, BPF_REG_SIZE));
-	if (err)
-		return err;
 	/* caller checked that off % size == 0 and -MAX_BPF_STACK <= off < 0,
 	 * so it's aligned access and [off, off + size) are within stack limits
 	 */
@@ -4595,10 +4600,6 @@ static int check_stack_write_var_off(struct bpf_verifier_env *env,
 	    (!value_reg && is_bpf_st_mem(insn) && insn->imm == 0))
 		writing_zero = true;
 
-	err = grow_stack_state(state, round_up(-min_off, BPF_REG_SIZE));
-	if (err)
-		return err;
-
 	for (i = min_off; i < max_off; i++) {
 		int spi;
 
@@ -5774,20 +5775,6 @@ static int check_ptr_alignment(struct bpf_verifier_env *env,
 					   strict);
 }
 
-static int update_stack_depth(struct bpf_verifier_env *env,
-			      const struct bpf_func_state *func,
-			      int off)
-{
-	u16 stack = env->subprog_info[func->subprogno].stack_depth;
-
-	if (stack >= -off)
-		return 0;
-
-	/* update known max for given subprogram */
-	env->subprog_info[func->subprogno].stack_depth = -off;
-	return 0;
-}
-
 /* starting from main bpf function walk all instructions of the function
  * and recursively walk all callees that given function can call.
  * Ignore jump and exit insns.
@@ -6577,13 +6564,14 @@ static int check_ptr_to_map_access(struct bpf_verifier_env *env,
  * The minimum valid offset is -MAX_BPF_STACK for writes, and
  * -state->allocated_stack for reads.
  */
-static int check_stack_slot_within_bounds(s64 off,
-					  struct bpf_func_state *state,
-					  enum bpf_access_type t)
+static int check_stack_slot_within_bounds(struct bpf_verifier_env *env,
+                                          s64 off,
+                                          struct bpf_func_state *state,
+                                          enum bpf_access_type t)
 {
 	int min_valid_off;
 
-	if (t == BPF_WRITE)
+	if (t == BPF_WRITE || env->allow_uninit_stack)
 		min_valid_off = -MAX_BPF_STACK;
 	else
 		min_valid_off = -state->allocated_stack;
@@ -6632,7 +6620,7 @@ static int check_stack_access_within_bounds(
 		max_off = reg->smax_value + off + access_size;
 	}
 
-	err = check_stack_slot_within_bounds(min_off, state, type);
+	err = check_stack_slot_within_bounds(env, min_off, state, type);
 	if (!err && max_off > 0)
 		err = -EINVAL; /* out of stack access into non-negative offsets */
 
@@ -6647,8 +6635,10 @@ static int check_stack_access_within_bounds(
 			verbose(env, "invalid variable-offset%s stack R%d var_off=%s off=%d size=%d\n",
 				err_extra, regno, tn_buf, off, access_size);
 		}
+		return err;
 	}
-	return err;
+
+	return grow_stack_state(env, state, round_up(-min_off, BPF_REG_SIZE));
 }
 
 /* check whether memory at (regno + off) is accessible for t = (read | write)
@@ -6663,7 +6653,6 @@ static int check_mem_access(struct bpf_verifier_env *env, int insn_idx, u32 regn
 {
 	struct bpf_reg_state *regs = cur_regs(env);
 	struct bpf_reg_state *reg = regs + regno;
-	struct bpf_func_state *state;
 	int size, err = 0;
 
 	size = bpf_size_to_bytes(bpf_size);
@@ -6806,11 +6795,6 @@ static int check_mem_access(struct bpf_verifier_env *env, int insn_idx, u32 regn
 		if (err)
 			return err;
 
-		state = func(env, reg);
-		err = update_stack_depth(env, state, off);
-		if (err)
-			return err;
-
 		if (t == BPF_READ)
 			err = check_stack_read(env, regno, off, size,
 					       value_regno);
@@ -7004,7 +6988,8 @@ static int check_atomic(struct bpf_verifier_env *env, int insn_idx, struct bpf_i
 
 /* When register 'regno' is used to read the stack (either directly or through
  * a helper function) make sure that it's within stack boundary and, depending
- * on the access type, that all elements of the stack are initialized.
+ * on the access type and privileges, that all elements of the stack are
+ * initialized.
  *
  * 'off' includes 'regno->off', but not its dynamic part (if any).
  *
@@ -7112,8 +7097,11 @@ static int check_stack_range_initialized(
 
 		slot = -i - 1;
 		spi = slot / BPF_REG_SIZE;
-		if (state->allocated_stack <= slot)
-			goto err;
+		if (state->allocated_stack <= slot) {
+			verbose(env, "verifier bug: allocated_stack too small");
+			return -EFAULT;
+		}
+
 		stype = &state->stack[spi].slot_type[slot % BPF_REG_SIZE];
 		if (*stype == STACK_MISC)
 			goto mark;
@@ -7137,7 +7125,6 @@ static int check_stack_range_initialized(
 			goto mark;
 		}
 
-err:
 		if (tnum_is_const(reg->var_off)) {
 			verbose(env, "invalid%s read from stack R%d off %d+%d size %d\n",
 				err_extra, regno, min_off, i - min_off, access_size);
@@ -7162,7 +7149,7 @@ static int check_stack_range_initialized(
 		 * helper may write to the entire memory range.
 		 */
 	}
-	return update_stack_depth(env, state, min_off);
+	return 0;
 }
 
 static int check_helper_mem_access(struct bpf_verifier_env *env, int regno,

```


---
## 829955981c55 — bpf: Fix verifier log for async callback return values

```diff
 kernel/bpf/verifier.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index c0c7d137066a..873ade146f3d 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -14479,7 +14479,7 @@ static int check_return_code(struct bpf_verifier_env *env)
 	struct tnum enforce_attach_type_range = tnum_unknown;
 	const struct bpf_prog *prog = env->prog;
 	struct bpf_reg_state *reg;
-	struct tnum range = tnum_range(0, 1);
+	struct tnum range = tnum_range(0, 1), const_0 = tnum_const(0);
 	enum bpf_prog_type prog_type = resolve_prog_type(env->prog);
 	int err;
 	struct bpf_func_state *frame = env->cur_state->frame[0];
@@ -14527,8 +14527,8 @@ static int check_return_code(struct bpf_verifier_env *env)
 			return -EINVAL;
 		}
 
-		if (!tnum_in(tnum_const(0), reg->var_off)) {
-			verbose_invalid_scalar(env, reg, &range, "async callback", "R0");
+		if (!tnum_in(const_0, reg->var_off)) {
+			verbose_invalid_scalar(env, reg, &const_0, "async callback", "R0");
 			return -EINVAL;
 		}
 		return 0;

```


---
## d84b1a6708ee — bpf: fix calculation of subseq_idx during precision backtracking

```diff
 kernel/bpf/verifier.c | 14 ++++++++------
 1 file changed, 8 insertions(+), 6 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 5c636276d907..f597491259ab 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -3864,10 +3864,11 @@ static int __mark_chain_precision(struct bpf_verifier_env *env, int regno)
 	struct bpf_verifier_state *st = env->cur_state;
 	int first_idx = st->first_insn_idx;
 	int last_idx = env->insn_idx;
+	int subseq_idx = -1;
 	struct bpf_func_state *func;
 	struct bpf_reg_state *reg;
 	bool skip_first = true;
-	int i, prev_i, fr, err;
+	int i, fr, err;
 
 	if (!env->bpf_capable)
 		return 0;
@@ -3897,8 +3898,8 @@ static int __mark_chain_precision(struct bpf_verifier_env *env, int regno)
 		u32 history = st->jmp_history_cnt;
 
 		if (env->log.level & BPF_LOG_LEVEL2) {
-			verbose(env, "mark_precise: frame%d: last_idx %d first_idx %d\n",
-				bt->frame, last_idx, first_idx);
+			verbose(env, "mark_precise: frame%d: last_idx %d first_idx %d subseq_idx %d \n",
+				bt->frame, last_idx, first_idx, subseq_idx);
 		}
 
 		if (last_idx < 0) {
@@ -3930,12 +3931,12 @@ static int __mark_chain_precision(struct bpf_verifier_env *env, int regno)
 			return -EFAULT;
 		}
 
-		for (i = last_idx, prev_i = -1;;) {
+		for (i = last_idx;;) {
 			if (skip_first) {
 				err = 0;
 				skip_first = false;
 			} else {
-				err = backtrack_insn(env, i, prev_i, bt);
+				err = backtrack_insn(env, i, subseq_idx, bt);
 			}
 			if (err == -ENOTSUPP) {
 				mark_all_scalars_precise(env, env->cur_state);
@@ -3952,7 +3953,7 @@ static int __mark_chain_precision(struct bpf_verifier_env *env, int regno)
 				return 0;
 			if (i == first_idx)
 				break;
-			prev_i = i;
+			subseq_idx = i;
 			i = get_prev_insn_idx(st, i, &history);
 			if (i >= env->prog->len) {
 				/* This can happen if backtracking reached insn 0
@@ -4031,6 +4032,7 @@ static int __mark_chain_precision(struct bpf_verifier_env *env, int regno)
 		if (bt_empty(bt))
 			return 0;
 
+		subseq_idx = first_idx;
 		last_idx = st->last_insn_idx;
 		first_idx = st->first_insn_idx;
 	}

```


---
## 71b547f56124 — bpf: Fix incorrect verifier pruning due to missing register precision taints

```diff
 kernel/bpf/verifier.c | 15 +++++++++++++++
 1 file changed, 15 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index d517d13878cf..767e8930b0bd 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -2967,6 +2967,21 @@ static int backtrack_insn(struct bpf_verifier_env *env, int idx,
 			}
 		} else if (opcode == BPF_EXIT) {
 			return -ENOTSUPP;
+		} else if (BPF_SRC(insn->code) == BPF_X) {
+			if (!(*reg_mask & (dreg | sreg)))
+				return 0;
+			/* dreg <cond> sreg
+			 * Both dreg and sreg need precision before
+			 * this insn. If only sreg was marked precise
+			 * before it would be equally necessary to
+			 * propagate it to dreg.
+			 */
+			*reg_mask |= (sreg | dreg);
+			 /* else dreg <cond> K
+			  * Only dreg still needs precision before
+			  * this insn, so for the K-based conditional
+			  * there is nothing new to be marked.
+			  */
 		}
 	} else if (class == BPF_LD) {
 		if (!(*reg_mask & dreg))

```


---
## 7be14c1c9030 — bpf: Fix __reg_bound_offset 64->32 var_off subreg propagation

```diff
 kernel/bpf/verifier.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 50c995697f0e..fd2f216de920 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -2149,9 +2149,9 @@ static void __reg_bound_offset(struct bpf_reg_state *reg)
 	struct tnum var64_off = tnum_intersect(reg->var_off,
 					       tnum_range(reg->umin_value,
 							  reg->umax_value));
-	struct tnum var32_off = tnum_intersect(tnum_subreg(reg->var_off),
-						tnum_range(reg->u32_min_value,
-							   reg->u32_max_value));
+	struct tnum var32_off = tnum_intersect(tnum_subreg(var64_off),
+					       tnum_range(reg->u32_min_value,
+							  reg->u32_max_value));
 
 	reg->var_off = tnum_or(tnum_clear_subreg(var64_off), var32_off);
 }

```


---
## 79168a669d81 — bpf: Fix missing var_off check for ARG_PTR_TO_DYNPTR

```diff
 kernel/bpf/verifier.c | 84 ++++++++++++++++++++++++++++++++++++++++-----------
 1 file changed, 66 insertions(+), 18 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 39d8ee38c338..76afdbea425a 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -638,11 +638,34 @@ static void print_liveness(struct bpf_verifier_env *env,
 		verbose(env, "D");
 }
 
-static int get_spi(s32 off)
+static int __get_spi(s32 off)
 {
 	return (-off - 1) / BPF_REG_SIZE;
 }
 
+static int dynptr_get_spi(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
+{
+	int off, spi;
+
+	if (!tnum_is_const(reg->var_off)) {
+		verbose(env, "dynptr has to be at a constant offset\n");
+		return -EINVAL;
+	}
+
+	off = reg->off + reg->var_off.value;
+	if (off % BPF_REG_SIZE) {
+		verbose(env, "cannot pass in dynptr at an offset=%d\n", off);
+		return -EINVAL;
+	}
+
+	spi = __get_spi(off);
+	if (spi < 1) {
+		verbose(env, "cannot pass in dynptr at an offset=%d\n", off);
+		return -EINVAL;
+	}
+	return spi;
+}
+
 static bool is_spi_bounds_valid(struct bpf_func_state *state, int spi, int nr_slots)
 {
 	int allocated_slots = state->allocated_stack / BPF_REG_SIZE;
@@ -754,7 +777,9 @@ static int mark_stack_slots_dynptr(struct bpf_verifier_env *env, struct bpf_reg_
 	enum bpf_dynptr_type type;
 	int spi, i, id;
 
-	spi = get_spi(reg->off);
+	spi = dynptr_get_spi(env, reg);
+	if (spi < 0)
+		return spi;
 
 	if (!is_spi_bounds_valid(state, spi, BPF_DYNPTR_NR_SLOTS))
 		return -EINVAL;
@@ -792,7 +817,9 @@ static int unmark_stack_slots_dynptr(struct bpf_verifier_env *env, struct bpf_re
 	struct bpf_func_state *state = func(env, reg);
 	int spi, i;
 
-	spi = get_spi(reg->off);
+	spi = dynptr_get_spi(env, reg);
+	if (spi < 0)
+		return spi;
 
 	if (!is_spi_bounds_valid(state, spi, BPF_DYNPTR_NR_SLOTS))
 		return -EINVAL;
@@ -844,7 +871,11 @@ static bool is_dynptr_reg_valid_uninit(struct bpf_verifier_env *env, struct bpf_
 	if (reg->type == CONST_PTR_TO_DYNPTR)
 		return false;
 
-	spi = get_spi(reg->off);
+	spi = dynptr_get_spi(env, reg);
+	if (spi < 0)
+		return false;
+
+	/* We will do check_mem_access to check and update stack bounds later */
 	if (!is_spi_bounds_valid(state, spi, BPF_DYNPTR_NR_SLOTS))
 		return true;
 
@@ -860,14 +891,15 @@ static bool is_dynptr_reg_valid_uninit(struct bpf_verifier_env *env, struct bpf_
 static bool is_dynptr_reg_valid_init(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
 {
 	struct bpf_func_state *state = func(env, reg);
-	int spi;
-	int i;
+	int spi, i;
 
 	/* This already represents first slot of initialized bpf_dynptr */
 	if (reg->type == CONST_PTR_TO_DYNPTR)
 		return true;
 
-	spi = get_spi(reg->off);
+	spi = dynptr_get_spi(env, reg);
+	if (spi < 0)
+		return false;
 	if (!is_spi_bounds_valid(state, spi, BPF_DYNPTR_NR_SLOTS) ||
 	    !state->stack[spi].spilled_ptr.dynptr.first_slot)
 		return false;
@@ -896,7 +928,9 @@ static bool is_dynptr_type_expected(struct bpf_verifier_env *env, struct bpf_reg
 	if (reg->type == CONST_PTR_TO_DYNPTR) {
 		return reg->dynptr.type == dynptr_type;
 	} else {
-		spi = get_spi(reg->off);
+		spi = dynptr_get_spi(env, reg);
+		if (spi < 0)
+			return false;
 		return state->stack[spi].spilled_ptr.dynptr.type == dynptr_type;
 	}
 }
@@ -2429,7 +2463,9 @@ static int mark_dynptr_read(struct bpf_verifier_env *env, struct bpf_reg_state *
 	 */
 	if (reg->type == CONST_PTR_TO_DYNPTR)
 		return 0;
-	spi = get_spi(reg->off);
+	spi = dynptr_get_spi(env, reg);
+	if (spi < 0)
+		return spi;
 	/* Caller ensures dynptr is valid and initialized, which means spi is in
 	 * bounds and spi is the first dynptr slot. Simply mark stack slot as
 	 * read.
@@ -5992,12 +6028,15 @@ int process_dynptr_func(struct bpf_verifier_env *env, int regno,
 	}
 	/* CONST_PTR_TO_DYNPTR already has fixed and var_off as 0 due to
 	 * check_func_arg_reg_off's logic. We only need to check offset
-	 * alignment for PTR_TO_STACK.
+	 * and its alignment for PTR_TO_STACK.
 	 */
-	if (reg->type == PTR_TO_STACK && (reg->off % BPF_REG_SIZE)) {
-		verbose(env, "cannot pass in dynptr at an offset=%d\n", reg->off);
-		return -EINVAL;
+	if (reg->type == PTR_TO_STACK) {
+		int err = dynptr_get_spi(env, reg);
+
+		if (err < 0)
+			return err;
 	}
+
 	/*  MEM_UNINIT - Points to memory that is an appropriate candidate for
 	 *		 constructing a mutable bpf_dynptr object.
 	 *
@@ -6405,15 +6444,16 @@ int check_func_arg_reg_off(struct bpf_verifier_env *env,
 	}
 }
 
-static u32 dynptr_ref_obj_id(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
+static int dynptr_ref_obj_id(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
 {
 	struct bpf_func_state *state = func(env, reg);
 	int spi;
 
 	if (reg->type == CONST_PTR_TO_DYNPTR)
 		return reg->ref_obj_id;
-
-	spi = get_spi(reg->off);
+	spi = dynptr_get_spi(env, reg);
+	if (spi < 0)
+		return spi;
 	return state->stack[spi].spilled_ptr.ref_obj_id;
 }
 
@@ -6487,7 +6527,9 @@ static int check_func_arg(struct bpf_verifier_env *env, u32 arg,
 			 * PTR_TO_STACK.
 			 */
 			if (reg->type == PTR_TO_STACK) {
-				spi = get_spi(reg->off);
+				spi = dynptr_get_spi(env, reg);
+				if (spi < 0)
+					return spi;
 				if (!is_spi_bounds_valid(state, spi, BPF_DYNPTR_NR_SLOTS) ||
 				    !state->stack[spi].spilled_ptr.ref_obj_id) {
 					verbose(env, "arg %d is an unacquired reference\n", regno);
@@ -7977,13 +8019,19 @@ static int check_helper_call(struct bpf_verifier_env *env, struct bpf_insn *insn
 		for (i = 0; i < MAX_BPF_FUNC_REG_ARGS; i++) {
 			if (arg_type_is_dynptr(fn->arg_type[i])) {
 				struct bpf_reg_state *reg = &regs[BPF_REG_1 + i];
+				int ref_obj_id;
 
 				if (meta.ref_obj_id) {
 					verbose(env, "verifier internal error: meta.ref_obj_id already set\n");
 					return -EFAULT;
 				}
 
-				meta.ref_obj_id = dynptr_ref_obj_id(env, reg);
+				ref_obj_id = dynptr_ref_obj_id(env, reg);
+				if (ref_obj_id < 0) {
+					verbose(env, "verifier internal error: failed to obtain dynptr ref_obj_id\n");
+					return ref_obj_id;
+				}
+				meta.ref_obj_id = ref_obj_id;
 				break;
 			}
 		}

```


---
## 8374bfd5a3c9 — bpf: fix nullness propagation for reg to reg comparisons

```diff
 kernel/bpf/verifier.c | 9 ++++++++-
 1 file changed, 8 insertions(+), 1 deletion(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index a5255a0dcbb6..243d06ce6842 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -11822,10 +11822,17 @@ static int check_cond_jmp_op(struct bpf_verifier_env *env,
 	 *      register B - not null
 	 * for JNE A, B, ... - A is not null in the false branch;
 	 * for JEQ A, B, ... - A is not null in the true branch.
+	 *
+	 * Since PTR_TO_BTF_ID points to a kernel struct that does
+	 * not need to be null checked by the BPF program, i.e.,
+	 * could be null even without PTR_MAYBE_NULL marking, so
+	 * only propagate nullness when neither reg is that type.
 	 */
 	if (!is_jmp32 && BPF_SRC(insn->code) == BPF_X &&
 	    __is_pointer_value(false, src_reg) && __is_pointer_value(false, dst_reg) &&
-	    type_may_be_null(src_reg->type) != type_may_be_null(dst_reg->type)) {
+	    type_may_be_null(src_reg->type) != type_may_be_null(dst_reg->type) &&
+	    base_type(src_reg->type) != PTR_TO_BTF_ID &&
+	    base_type(dst_reg->type) != PTR_TO_BTF_ID) {
 		eq_branch_regs = NULL;
 		switch (opcode) {
 		case BPF_JEQ:

```


---
## f5e477a861e4 — bpf: Fix slot type check in check_stack_write_var_off

```diff
 kernel/bpf/verifier.c | 19 +++++++++++--------
 1 file changed, 11 insertions(+), 8 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 7bf12c492201..eb111a8034e7 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -3181,14 +3181,17 @@ static int check_stack_write_var_off(struct bpf_verifier_env *env,
 		stype = &state->stack[spi].slot_type[slot % BPF_REG_SIZE];
 		mark_stack_slot_scratched(env, spi);
 
-		if (!env->allow_ptr_leaks
-				&& *stype != NOT_INIT
-				&& *stype != SCALAR_VALUE) {
-			/* Reject the write if there's are spilled pointers in
-			 * range. If we didn't reject here, the ptr status
-			 * would be erased below (even though not all slots are
-			 * actually overwritten), possibly opening the door to
-			 * leaks.
+		if (!env->allow_ptr_leaks && *stype != STACK_MISC && *stype != STACK_ZERO) {
+			/* Reject the write if range we may write to has not
+			 * been initialized beforehand. If we didn't reject
+			 * here, the ptr status would be erased below (even
+			 * though not all slots are actually overwritten),
+			 * possibly opening the door to leaks.
+			 *
+			 * We do however catch STACK_INVALID case below, and
+			 * only allow reading possibly uninitialized memory
+			 * later for CAP_PERFMON, as the write may not happen to
+			 * that slot.
 			 */
 			verbose(env, "spilled ptr in range of var-offset stack write; insn %d, ptr off: %d",
 				insn_idx, i);

```


---
## a657182a5c51 — bpf: Don't use tnum_range on array range checking for poke descriptors

```diff
 kernel/bpf/verifier.c | 10 ++++------
 1 file changed, 4 insertions(+), 6 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 30c6eebce146..3eadb14e090b 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -7033,8 +7033,7 @@ record_func_key(struct bpf_verifier_env *env, struct bpf_call_arg_meta *meta,
 	struct bpf_insn_aux_data *aux = &env->insn_aux_data[insn_idx];
 	struct bpf_reg_state *regs = cur_regs(env), *reg;
 	struct bpf_map *map = meta->map_ptr;
-	struct tnum range;
-	u64 val;
+	u64 val, max;
 	int err;
 
 	if (func_id != BPF_FUNC_tail_call)
@@ -7044,10 +7043,11 @@ record_func_key(struct bpf_verifier_env *env, struct bpf_call_arg_meta *meta,
 		return -EINVAL;
 	}
 
-	range = tnum_range(0, map->max_entries - 1);
 	reg = &regs[BPF_REG_3];
+	val = reg->var_off.value;
+	max = map->max_entries;
 
-	if (!register_is_const(reg) || !tnum_in(range, reg->var_off)) {
+	if (!(register_is_const(reg) && val < max)) {
 		bpf_map_key_store(aux, BPF_MAP_KEY_POISON);
 		return 0;
 	}
@@ -7055,8 +7055,6 @@ record_func_key(struct bpf_verifier_env *env, struct bpf_call_arg_meta *meta,
 	err = mark_chain_precision(env, BPF_REG_3);
 	if (err)
 		return err;
-
-	val = reg->var_off.value;
 	if (bpf_map_key_unseen(aux))
 		bpf_map_key_store(aux, val);
 	else if (!bpf_map_key_poisoned(aux) &&

```


---
## a12ca6277eca — bpf: Fix incorrect verifier simulation around jmp32's jeq/jne

```diff
 kernel/bpf/verifier.c | 41 ++++++++++++++++++++++++-----------------
 1 file changed, 24 insertions(+), 17 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index aedac2ac02b9..ec164b3c0fa2 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -9577,26 +9577,33 @@ static void reg_set_min_max(struct bpf_reg_state *true_reg,
 		return;
 
 	switch (opcode) {
+	/* JEQ/JNE comparison doesn't change the register equivalence.
+	 *
+	 * r1 = r2;
+	 * if (r1 == 42) goto label;
+	 * ...
+	 * label: // here both r1 and r2 are known to be 42.
+	 *
+	 * Hence when marking register as known preserve it's ID.
+	 */
 	case BPF_JEQ:
+		if (is_jmp32) {
+			__mark_reg32_known(true_reg, val32);
+			true_32off = tnum_subreg(true_reg->var_off);
+		} else {
+			___mark_reg_known(true_reg, val);
+			true_64off = true_reg->var_off;
+		}
+		break;
 	case BPF_JNE:
-	{
-		struct bpf_reg_state *reg =
-			opcode == BPF_JEQ ? true_reg : false_reg;
-
-		/* JEQ/JNE comparison doesn't change the register equivalence.
-		 * r1 = r2;
-		 * if (r1 == 42) goto label;
-		 * ...
-		 * label: // here both r1 and r2 are known to be 42.
-		 *
-		 * Hence when marking register as known preserve it's ID.
-		 */
-		if (is_jmp32)
-			__mark_reg32_known(reg, val32);
-		else
-			___mark_reg_known(reg, val);
+		if (is_jmp32) {
+			__mark_reg32_known(false_reg, val32);
+			false_32off = tnum_subreg(false_reg->var_off);
+		} else {
+			___mark_reg_known(false_reg, val);
+			false_64off = false_reg->var_off;
+		}
 		break;
-	}
 	case BPF_JSET:
 		if (is_jmp32) {
 			false_32off = tnum_and(false_32off, tnum_const(~val32));

```


---
## bff61f6faedb — bpf: Fix checking PTR_TO_BTF_ID in check_mem_access

```diff
 kernel/bpf/verifier.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index fe9a513e2314..7a6b58fea37d 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -4562,7 +4562,8 @@ static int check_mem_access(struct bpf_verifier_env *env, int insn_idx, u32 regn
 		err = check_tp_buffer_access(env, reg, regno, off, size);
 		if (!err && t == BPF_READ && value_regno >= 0)
 			mark_reg_unknown(env, regs, value_regno);
-	} else if (reg->type == PTR_TO_BTF_ID) {
+	} else if (base_type(reg->type) == PTR_TO_BTF_ID &&
+		   !type_may_be_null(reg->type)) {
 		err = check_ptr_to_btf_access(env, regs, regno, off, size, t,
 					      value_regno);
 	} else if (reg->type == CONST_PTR_TO_MAP) {

```


---
## 345e004d0233 — bpf: Fix incorrect state pruning for <8B spill/fill

```diff
 kernel/bpf/verifier.c | 4 ----
 1 file changed, 4 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index f3001937bbb9..f2f1ed34cfe9 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -2379,8 +2379,6 @@ static int backtrack_insn(struct bpf_verifier_env *env, int idx,
 		 */
 		if (insn->src_reg != BPF_REG_FP)
 			return 0;
-		if (BPF_SIZE(insn->code) != BPF_DW)
-			return 0;
 
 		/* dreg = *(u64 *)[fp - off] was a fill from the stack.
 		 * that [fp - off] slot contains scalar that needs to be
@@ -2403,8 +2401,6 @@ static int backtrack_insn(struct bpf_verifier_env *env, int idx,
 		/* scalars can only be spilled into stack */
 		if (insn->dst_reg != BPF_REG_FP)
 			return 0;
-		if (BPF_SIZE(insn->code) != BPF_DW)
-			return 0;
 		spi = (-insn->off - 1) / BPF_REG_SIZE;
 		if (spi >= 64) {
 			verbose(env, "BUG spi %d\n", spi);

```


---
## b9979db83401 — bpf: Fix propagation of bounds from 64-bit min/max into 32-bit and var_off.

```diff
 kernel/bpf/verifier.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 3c8aa7df1773..29671ed49ee8 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -1425,7 +1425,7 @@ static bool __reg64_bound_s32(s64 a)
 
 static bool __reg64_bound_u32(u64 a)
 {
-	return a > U32_MIN && a < U32_MAX;
+	return a >= U32_MIN && a <= U32_MAX;
 }
 
 static void __reg_combine_64_into_32(struct bpf_reg_state *reg)

```


---
## 10bf4e83167c — bpf: Fix propagation of 32 bit unsigned bounds from 64 bit bounds

```diff
 kernel/bpf/verifier.c | 8 +++-----
 1 file changed, 3 insertions(+), 5 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 637462e9b6ee..9145f88b2a0a 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -1398,9 +1398,7 @@ static bool __reg64_bound_s32(s64 a)
 
 static bool __reg64_bound_u32(u64 a)
 {
-	if (a > U32_MIN && a < U32_MAX)
-		return true;
-	return false;
+	return a > U32_MIN && a < U32_MAX;
 }
 
 static void __reg_combine_64_into_32(struct bpf_reg_state *reg)
@@ -1411,10 +1409,10 @@ static void __reg_combine_64_into_32(struct bpf_reg_state *reg)
 		reg->s32_min_value = (s32)reg->smin_value;
 		reg->s32_max_value = (s32)reg->smax_value;
 	}
-	if (__reg64_bound_u32(reg->umin_value))
+	if (__reg64_bound_u32(reg->umin_value) && __reg64_bound_u32(reg->umax_value)) {
 		reg->u32_min_value = (u32)reg->umin_value;
-	if (__reg64_bound_u32(reg->umax_value))
 		reg->u32_max_value = (u32)reg->umax_value;
+	}
 
 	/* Intersecting with the old var_off might have improved our bounds
 	 * slightly.  e.g. if umax was 0x7f...f and var_off was (0; 0xf...fc),

```


---
## 9b00f1b78809 — bpf: Fix truncation handling for mod32 dst reg wrt zero

```diff
 kernel/bpf/verifier.c | 10 ++++++----
 1 file changed, 6 insertions(+), 4 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 37581919e050..20babdd06278 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -11006,7 +11006,7 @@ static int fixup_bpf_calls(struct bpf_verifier_env *env)
 			bool isdiv = BPF_OP(insn->code) == BPF_DIV;
 			struct bpf_insn *patchlet;
 			struct bpf_insn chk_and_div[] = {
-				/* Rx div 0 -> 0 */
+				/* [R,W]x div 0 -> 0 */
 				BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
 					     BPF_JNE | BPF_K, insn->src_reg,
 					     0, 2, 0),
@@ -11015,16 +11015,18 @@ static int fixup_bpf_calls(struct bpf_verifier_env *env)
 				*insn,
 			};
 			struct bpf_insn chk_and_mod[] = {
-				/* Rx mod 0 -> Rx */
+				/* [R,W]x mod 0 -> [R,W]x */
 				BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
 					     BPF_JEQ | BPF_K, insn->src_reg,
-					     0, 1, 0),
+					     0, 1 + (is64 ? 0 : 1), 0),
 				*insn,
+				BPF_JMP_IMM(BPF_JA, 0, 0, 1),
+				BPF_MOV32_REG(insn->dst_reg, insn->dst_reg),
 			};
 
 			patchlet = isdiv ? chk_and_div : chk_and_mod;
 			cnt = isdiv ? ARRAY_SIZE(chk_and_div) :
-				      ARRAY_SIZE(chk_and_mod);
+				      ARRAY_SIZE(chk_and_mod) - (is64 ? 2 : 0);
 
 			new_prog = bpf_patch_insn_data(env, i + delta, patchlet, cnt);
 			if (!new_prog)

```


---
## e88b2c6e5a4d — bpf: Fix 32 bit src register truncation on div/mod

```diff
 kernel/bpf/verifier.c | 28 +++++++++++++---------------
 1 file changed, 13 insertions(+), 15 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 24c0e9224f3c..37581919e050 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -11003,30 +11003,28 @@ static int fixup_bpf_calls(struct bpf_verifier_env *env)
 		    insn->code == (BPF_ALU | BPF_MOD | BPF_X) ||
 		    insn->code == (BPF_ALU | BPF_DIV | BPF_X)) {
 			bool is64 = BPF_CLASS(insn->code) == BPF_ALU64;
-			struct bpf_insn mask_and_div[] = {
-				BPF_MOV32_REG(insn->src_reg, insn->src_reg),
+			bool isdiv = BPF_OP(insn->code) == BPF_DIV;
+			struct bpf_insn *patchlet;
+			struct bpf_insn chk_and_div[] = {
 				/* Rx div 0 -> 0 */
-				BPF_JMP_IMM(BPF_JNE, insn->src_reg, 0, 2),
+				BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
+					     BPF_JNE | BPF_K, insn->src_reg,
+					     0, 2, 0),
 				BPF_ALU32_REG(BPF_XOR, insn->dst_reg, insn->dst_reg),
 				BPF_JMP_IMM(BPF_JA, 0, 0, 1),
 				*insn,
 			};
-			struct bpf_insn mask_and_mod[] = {
-				BPF_MOV32_REG(insn->src_reg, insn->src_reg),
+			struct bpf_insn chk_and_mod[] = {
 				/* Rx mod 0 -> Rx */
-				BPF_JMP_IMM(BPF_JEQ, insn->src_reg, 0, 1),
+				BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
+					     BPF_JEQ | BPF_K, insn->src_reg,
+					     0, 1, 0),
 				*insn,
 			};
-			struct bpf_insn *patchlet;
 
-			if (insn->code == (BPF_ALU64 | BPF_DIV | BPF_X) ||
-			    insn->code == (BPF_ALU | BPF_DIV | BPF_X)) {
-				patchlet = mask_and_div + (is64 ? 1 : 0);
-				cnt = ARRAY_SIZE(mask_and_div) - (is64 ? 1 : 0);
-			} else {
-				patchlet = mask_and_mod + (is64 ? 1 : 0);
-				cnt = ARRAY_SIZE(mask_and_mod) - (is64 ? 1 : 0);
-			}
+			patchlet = isdiv ? chk_and_div : chk_and_mod;
+			cnt = isdiv ? ARRAY_SIZE(chk_and_div) :
+				      ARRAY_SIZE(chk_and_mod);
 
 			new_prog = bpf_patch_insn_data(env, i + delta, patchlet, cnt);
 			if (!new_prog)

```


---
## b02709587ea3 — bpf: Fix propagation of 32-bit signed bounds from 64-bit bounds.

```diff
 kernel/bpf/verifier.c | 10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 1388bf733071..53fe6ef6d931 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -1298,9 +1298,7 @@ static void __reg_combine_32_into_64(struct bpf_reg_state *reg)
 
 static bool __reg64_bound_s32(s64 a)
 {
-	if (a > S32_MIN && a < S32_MAX)
-		return true;
-	return false;
+	return a > S32_MIN && a < S32_MAX;
 }
 
 static bool __reg64_bound_u32(u64 a)
@@ -1314,10 +1312,10 @@ static void __reg_combine_64_into_32(struct bpf_reg_state *reg)
 {
 	__mark_reg32_unbounded(reg);
 
-	if (__reg64_bound_s32(reg->smin_value))
+	if (__reg64_bound_s32(reg->smin_value) && __reg64_bound_s32(reg->smax_value)) {
 		reg->s32_min_value = (s32)reg->smin_value;
-	if (__reg64_bound_s32(reg->smax_value))
 		reg->s32_max_value = (s32)reg->smax_value;
+	}
 	if (__reg64_bound_u32(reg->umin_value))
 		reg->u32_min_value = (u32)reg->umin_value;
 	if (__reg64_bound_u32(reg->umax_value))
@@ -4895,6 +4893,8 @@ static void do_refine_retval_range(struct bpf_reg_state *regs, int ret_type,
 
 	ret_reg->smax_value = meta->msize_max_value;
 	ret_reg->s32_max_value = meta->msize_max_value;
+	ret_reg->smin_value = -MAX_ERRNO;
+	ret_reg->s32_min_value = -MAX_ERRNO;
 	__reg_deduce_bounds(ret_reg);
 	__reg_bound_offset(ret_reg);
 	__update_reg_bounds(ret_reg);

```


---
## 5b9fbeb75b6a — bpf: Fix scalar32_min_max_or bounds tracking

```diff
 kernel/bpf/verifier.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 47e74f09fa37..fba52d9ec8fc 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -5667,8 +5667,8 @@ static void scalar32_min_max_or(struct bpf_reg_state *dst_reg,
 	bool src_known = tnum_subreg_is_const(src_reg->var_off);
 	bool dst_known = tnum_subreg_is_const(dst_reg->var_off);
 	struct tnum var32_off = tnum_subreg(dst_reg->var_off);
-	s32 smin_val = src_reg->smin_value;
-	u32 umin_val = src_reg->umin_value;
+	s32 smin_val = src_reg->s32_min_value;
+	u32 umin_val = src_reg->u32_min_value;
 
 	/* Assuming scalar64_min_max_or will be called so it is safe
 	 * to skip updating register for known case.
@@ -5691,8 +5691,8 @@ static void scalar32_min_max_or(struct bpf_reg_state *dst_reg,
 		/* ORing two positives gives a positive, so safe to
 		 * cast result into s64.
 		 */
-		dst_reg->s32_min_value = dst_reg->umin_value;
-		dst_reg->s32_max_value = dst_reg->umax_value;
+		dst_reg->s32_min_value = dst_reg->u32_min_value;
+		dst_reg->s32_max_value = dst_reg->u32_max_value;
 	}
 }
 

```


---
## 3a71dc366d4a — bpf: Fix a verifier issue when assigning 32bit reg states to 64bit ones

```diff
 kernel/bpf/verifier.c | 10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index bfea3f9a972f..efe14cf24bc6 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -1168,14 +1168,14 @@ static void __reg_assign_32_into_64(struct bpf_reg_state *reg)
 	 * but must be positive otherwise set to worse case bounds
 	 * and refine later from tnum.
 	 */
-	if (reg->s32_min_value > 0)
-		reg->smin_value = reg->s32_min_value;
-	else
-		reg->smin_value = 0;
-	if (reg->s32_max_value > 0)
+	if (reg->s32_min_value >= 0 && reg->s32_max_value >= 0)
 		reg->smax_value = reg->s32_max_value;
 	else
 		reg->smax_value = U32_MAX;
+	if (reg->s32_min_value >= 0)
+		reg->smin_value = reg->s32_min_value;
+	else
+		reg->smin_value = 0;
 }
 
 static void __reg_combine_32_into_64(struct bpf_reg_state *reg)

```


---
## 100605035e15 — bpf: Verifier, do_refine_retval_range may clamp umin to 0 incorrectly

```diff
 kernel/bpf/verifier.c | 19 +++++++++++--------
 1 file changed, 11 insertions(+), 8 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index b55842033073..dda3b94d9661 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -229,8 +229,7 @@ struct bpf_call_arg_meta {
 	bool pkt_access;
 	int regno;
 	int access_size;
-	s64 msize_smax_value;
-	u64 msize_umax_value;
+	u64 msize_max_value;
 	int ref_obj_id;
 	int func_id;
 	u32 btf_id;
@@ -3571,11 +3570,15 @@ static int check_func_arg(struct bpf_verifier_env *env, u32 regno,
 	} else if (arg_type_is_mem_size(arg_type)) {
 		bool zero_size_allowed = (arg_type == ARG_CONST_SIZE_OR_ZERO);
 
-		/* remember the mem_size which may be used later
-		 * to refine return values.
+		/* This is used to refine r0 return value bounds for helpers
+		 * that enforce this value as an upper bound on return values.
+		 * See do_refine_retval_range() for helpers that can refine
+		 * the return value. C type of helper is u32 so we pull register
+		 * bound from umax_value however, if negative verifier errors
+		 * out. Only upper bounds can be learned because retval is an
+		 * int type and negative retvals are allowed.
 		 */
-		meta->msize_smax_value = reg->smax_value;
-		meta->msize_umax_value = reg->umax_value;
+		meta->msize_max_value = reg->umax_value;
 
 		/* The register is SCALAR_VALUE; the access check
 		 * happens using its boundaries.
@@ -4118,10 +4121,10 @@ static void do_refine_retval_range(struct bpf_reg_state *regs, int ret_type,
 	     func_id != BPF_FUNC_probe_read_str))
 		return;
 
-	ret_reg->smax_value = meta->msize_smax_value;
-	ret_reg->umax_value = meta->msize_umax_value;
+	ret_reg->smax_value = meta->msize_max_value;
 	__reg_deduce_bounds(ret_reg);
 	__reg_bound_offset(ret_reg);
+	__update_reg_bounds(ret_reg);
 }
 
 static int

```


---
## f2d67fec0b43 — bpf: Undo incorrect __reg_bound_offset32 handling

```diff
 kernel/bpf/verifier.c | 19 -------------------
 1 file changed, 19 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 047b2e876399..2a84f73a93a1 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -1036,17 +1036,6 @@ static void __reg_bound_offset(struct bpf_reg_state *reg)
 						 reg->umax_value));
 }
 
-static void __reg_bound_offset32(struct bpf_reg_state *reg)
-{
-	u64 mask = 0xffffFFFF;
-	struct tnum range = tnum_range(reg->umin_value & mask,
-				       reg->umax_value & mask);
-	struct tnum lo32 = tnum_cast(reg->var_off, 4);
-	struct tnum hi32 = tnum_lshift(tnum_rshift(reg->var_off, 32), 32);
-
-	reg->var_off = tnum_or(hi32, tnum_intersect(lo32, range));
-}
-
 /* Reset the min/max bounds of a register */
 static void __mark_reg_unbounded(struct bpf_reg_state *reg)
 {
@@ -5805,10 +5794,6 @@ static void reg_set_min_max(struct bpf_reg_state *true_reg,
 	/* We might have learned some bits from the bounds. */
 	__reg_bound_offset(false_reg);
 	__reg_bound_offset(true_reg);
-	if (is_jmp32) {
-		__reg_bound_offset32(false_reg);
-		__reg_bound_offset32(true_reg);
-	}
 	/* Intersecting with the old var_off might have improved our bounds
 	 * slightly.  e.g. if umax was 0x7f...f and var_off was (0; 0xf...fc),
 	 * then new var_off is (0; 0x7f...fc) which improves our umax.
@@ -5918,10 +5903,6 @@ static void reg_set_min_max_inv(struct bpf_reg_state *true_reg,
 	/* We might have learned some bits from the bounds. */
 	__reg_bound_offset(false_reg);
 	__reg_bound_offset(true_reg);
-	if (is_jmp32) {
-		__reg_bound_offset32(false_reg);
-		__reg_bound_offset32(true_reg);
-	}
 	/* Intersecting with the old var_off might have improved our bounds
 	 * slightly.  e.g. if umax was 0x7f...f and var_off was (0; 0xf...fc),
 	 * then new var_off is (0; 0x7f...fc) which improves our umax.

```


---
## 0af2ffc93a4b — bpf: Fix incorrect verifier simulation of ARSH under ALU32

```diff
 kernel/bpf/tnum.c     |  9 +++++++--
 kernel/bpf/verifier.c | 13 ++++++++++---
 2 files changed, 17 insertions(+), 5 deletions(-)

diff --git a/kernel/bpf/tnum.c b/kernel/bpf/tnum.c
index ca52b9642943..d4f335a9a899 100644
--- a/kernel/bpf/tnum.c
+++ b/kernel/bpf/tnum.c
@@ -44,14 +44,19 @@ struct tnum tnum_rshift(struct tnum a, u8 shift)
 	return TNUM(a.value >> shift, a.mask >> shift);
 }
 
-struct tnum tnum_arshift(struct tnum a, u8 min_shift)
+struct tnum tnum_arshift(struct tnum a, u8 min_shift, u8 insn_bitness)
 {
 	/* if a.value is negative, arithmetic shifting by minimum shift
 	 * will have larger negative offset compared to more shifting.
 	 * If a.value is nonnegative, arithmetic shifting by minimum shift
 	 * will have larger positive offset compare to more shifting.
 	 */
-	return TNUM((s64)a.value >> min_shift, (s64)a.mask >> min_shift);
+	if (insn_bitness == 32)
+		return TNUM((u32)(((s32)a.value) >> min_shift),
+			    (u32)(((s32)a.mask)  >> min_shift));
+	else
+		return TNUM((s64)a.value >> min_shift,
+			    (s64)a.mask  >> min_shift);
 }
 
 struct tnum tnum_add(struct tnum a, struct tnum b)
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index ce85e7041f0c..7d530ce8719d 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -5049,9 +5049,16 @@ static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
 		/* Upon reaching here, src_known is true and
 		 * umax_val is equal to umin_val.
 		 */
-		dst_reg->smin_value >>= umin_val;
-		dst_reg->smax_value >>= umin_val;
-		dst_reg->var_off = tnum_arshift(dst_reg->var_off, umin_val);
+		if (insn_bitness == 32) {
+			dst_reg->smin_value = (u32)(((s32)dst_reg->smin_value) >> umin_val);
+			dst_reg->smax_value = (u32)(((s32)dst_reg->smax_value) >> umin_val);
+		} else {
+			dst_reg->smin_value >>= umin_val;
+			dst_reg->smax_value >>= umin_val;
+		}
+
+		dst_reg->var_off = tnum_arshift(dst_reg->var_off, umin_val,
+						insn_bitness);
 
 		/* blow away the dst_reg umin_value/umax_value and rely on
 		 * dst_reg var_off to refine the result.

```


---
## cc52d9140aa9 — bpf: Fix record_func_key to perform backtracking on r3

```diff
 kernel/bpf/verifier.c | 8 +++++++-
 1 file changed, 7 insertions(+), 1 deletion(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 6ef71429d997..4983940cbdca 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -4134,6 +4134,7 @@ record_func_key(struct bpf_verifier_env *env, struct bpf_call_arg_meta *meta,
 	struct bpf_map *map = meta->map_ptr;
 	struct tnum range;
 	u64 val;
+	int err;
 
 	if (func_id != BPF_FUNC_tail_call)
 		return 0;
@@ -4150,6 +4151,10 @@ record_func_key(struct bpf_verifier_env *env, struct bpf_call_arg_meta *meta,
 		return 0;
 	}
 
+	err = mark_chain_precision(env, BPF_REG_3);
+	if (err)
+		return err;
+
 	val = reg->var_off.value;
 	if (bpf_map_key_unseen(aux))
 		bpf_map_key_store(aux, val);
@@ -9272,7 +9277,8 @@ static int fixup_bpf_calls(struct bpf_verifier_env *env)
 			insn->code = BPF_JMP | BPF_TAIL_CALL;
 
 			aux = &env->insn_aux_data[i + delta];
-			if (prog->jit_requested && !expect_blinding &&
+			if (env->allow_ptr_leaks && !expect_blinding &&
+			    prog->jit_requested &&
 			    !bpf_map_key_poisoned(aux) &&
 			    !bpf_map_ptr_poisoned(aux) &&
 			    !bpf_map_ptr_unpriv(aux)) {

```


---
## 1fbd20f8b77b — bpf: Add missed newline in verifier verbose log

```diff
 kernel/bpf/verifier.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index f2d600199e66..48718e1da16d 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -1426,7 +1426,7 @@ static int check_stack_access(struct bpf_verifier_env *env,
 		char tn_buf[48];
 
 		tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
-		verbose(env, "variable stack access var_off=%s off=%d size=%d",
+		verbose(env, "variable stack access var_off=%s off=%d size=%d\n",
 			tn_buf, off, size);
 		return -EACCES;
 	}

```


---
## 107c26a70ca8 — bpf: Sanity check max value for var_off stack access

```diff
 kernel/bpf/verifier.c | 18 +++++++++++++++---
 1 file changed, 15 insertions(+), 3 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 8400c1f33cd4..f2d600199e66 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -2248,16 +2248,28 @@ static int check_stack_boundary(struct bpf_verifier_env *env, int regno,
 		if (meta && meta->raw_mode)
 			meta = NULL;
 
+		if (reg->smax_value >= BPF_MAX_VAR_OFF ||
+		    reg->smax_value <= -BPF_MAX_VAR_OFF) {
+			verbose(env, "R%d unbounded indirect variable offset stack access\n",
+				regno);
+			return -EACCES;
+		}
 		min_off = reg->smin_value + reg->off;
-		max_off = reg->umax_value + reg->off;
+		max_off = reg->smax_value + reg->off;
 		err = __check_stack_boundary(env, regno, min_off, access_size,
 					     zero_size_allowed);
-		if (err)
+		if (err) {
+			verbose(env, "R%d min value is outside of stack bound\n",
+				regno);
 			return err;
+		}
 		err = __check_stack_boundary(env, regno, max_off, access_size,
 					     zero_size_allowed);
-		if (err)
+		if (err) {
+			verbose(env, "R%d max value is outside of stack bound\n",
+				regno);
 			return err;
+		}
 	}
 
 	if (meta && meta->raw_mode) {

```


---
## 088ec26d9c2d — bpf: Reject indirect var_off stack access in unpriv mode

```diff
 kernel/bpf/verifier.c | 16 ++++++++++++++++
 1 file changed, 16 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 0f12fda35626..8400c1f33cd4 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -2226,6 +2226,19 @@ static int check_stack_boundary(struct bpf_verifier_env *env, int regno,
 		if (err)
 			return err;
 	} else {
+		/* Variable offset is prohibited for unprivileged mode for
+		 * simplicity since it requires corresponding support in
+		 * Spectre masking for stack ALU.
+		 * See also retrieve_ptr_limit().
+		 */
+		if (!env->allow_ptr_leaks) {
+			char tn_buf[48];
+
+			tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
+			verbose(env, "R%d indirect variable offset stack access prohibited for !root, var_off=%s\n",
+				regno, tn_buf);
+			return -EACCES;
+		}
 		/* Only initialized buffer on stack is allowed to be accessed
 		 * with variable offset. With uninitialized buffer it's hard to
 		 * guarantee that whole memory is marked as initialized on
@@ -3339,6 +3352,9 @@ static int retrieve_ptr_limit(const struct bpf_reg_state *ptr_reg,
 
 	switch (ptr_reg->type) {
 	case PTR_TO_STACK:
+		/* Indirect variable offset stack access is prohibited in
+		 * unprivileged mode so it's not handled here.
+		 */
 		off = ptr_reg->off + ptr_reg->var_off.value;
 		if (mask_to_left)
 			*ptr_limit = MAX_BPF_STACK + off;

```


---
## f2bcd05ec7b8 — bpf: Reject indirect var_off stack access in raw mode

```diff
 kernel/bpf/verifier.c | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index bb27b675923c..0f12fda35626 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -2226,6 +2226,15 @@ static int check_stack_boundary(struct bpf_verifier_env *env, int regno,
 		if (err)
 			return err;
 	} else {
+		/* Only initialized buffer on stack is allowed to be accessed
+		 * with variable offset. With uninitialized buffer it's hard to
+		 * guarantee that whole memory is marked as initialized on
+		 * helper return since specific bounds are unknown what may
+		 * cause uninitialized stack leaking.
+		 */
+		if (meta && meta->raw_mode)
+			meta = NULL;
+
 		min_off = reg->smin_value + reg->off;
 		max_off = reg->umax_value + reg->off;
 		err = __check_stack_boundary(env, regno, min_off, access_size,

```


---
## 5f4566498dee — bpf: Fix narrow load on a bpf_sock returned from sk_lookup()

```diff
 kernel/bpf/verifier.c | 11 +++++++----
 1 file changed, 7 insertions(+), 4 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index b63bc77af2d1..516dfc6d78de 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -1640,12 +1640,13 @@ static int check_flow_keys_access(struct bpf_verifier_env *env, int off,
 	return 0;
 }
 
-static int check_sock_access(struct bpf_verifier_env *env, u32 regno, int off,
-			     int size, enum bpf_access_type t)
+static int check_sock_access(struct bpf_verifier_env *env, int insn_idx,
+			     u32 regno, int off, int size,
+			     enum bpf_access_type t)
 {
 	struct bpf_reg_state *regs = cur_regs(env);
 	struct bpf_reg_state *reg = &regs[regno];
-	struct bpf_insn_access_aux info;
+	struct bpf_insn_access_aux info = {};
 
 	if (reg->smin_value < 0) {
 		verbose(env, "R%d min value is negative, either use unsigned index or do a if (index >=0) check.\n",
@@ -1659,6 +1660,8 @@ static int check_sock_access(struct bpf_verifier_env *env, u32 regno, int off,
 		return -EACCES;
 	}
 
+	env->insn_aux_data[insn_idx].ctx_field_size = info.ctx_field_size;
+
 	return 0;
 }
 
@@ -2055,7 +2058,7 @@ static int check_mem_access(struct bpf_verifier_env *env, int insn_idx, u32 regn
 			verbose(env, "cannot write into socket\n");
 			return -EACCES;
 		}
-		err = check_sock_access(env, regno, off, size, t);
+		err = check_sock_access(env, insn_idx, regno, off, size, t);
 		if (!err && value_regno >= 0)
 			mark_reg_unknown(env, regs, value_regno);
 	} else {

```


---
## d623876646be — bpf: Fix narrow load on a bpf_sock returned from sk_lookup()

```diff
 kernel/bpf/verifier.c | 11 +++++++----
 1 file changed, 7 insertions(+), 4 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 56674a7c3778..8f295b790297 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -1617,12 +1617,13 @@ static int check_flow_keys_access(struct bpf_verifier_env *env, int off,
 	return 0;
 }
 
-static int check_sock_access(struct bpf_verifier_env *env, u32 regno, int off,
-			     int size, enum bpf_access_type t)
+static int check_sock_access(struct bpf_verifier_env *env, int insn_idx,
+			     u32 regno, int off, int size,
+			     enum bpf_access_type t)
 {
 	struct bpf_reg_state *regs = cur_regs(env);
 	struct bpf_reg_state *reg = &regs[regno];
-	struct bpf_insn_access_aux info;
+	struct bpf_insn_access_aux info = {};
 
 	if (reg->smin_value < 0) {
 		verbose(env, "R%d min value is negative, either use unsigned index or do a if (index >=0) check.\n",
@@ -1636,6 +1637,8 @@ static int check_sock_access(struct bpf_verifier_env *env, u32 regno, int off,
 		return -EACCES;
 	}
 
+	env->insn_aux_data[insn_idx].ctx_field_size = info.ctx_field_size;
+
 	return 0;
 }
 
@@ -2032,7 +2035,7 @@ static int check_mem_access(struct bpf_verifier_env *env, int insn_idx, u32 regn
 			verbose(env, "cannot write into socket\n");
 			return -EACCES;
 		}
-		err = check_sock_access(env, regno, off, size, t);
+		err = check_sock_access(env, insn_idx, regno, off, size, t);
 		if (!err && value_regno >= 0)
 			mark_reg_unknown(env, regs, value_regno);
 	} else {

```


---
## 979d63d50c0c — bpf: prevent out of bounds speculation on pointer arithmetic

```diff
 include/linux/bpf_verifier.h |  10 +++
 kernel/bpf/verifier.c        | 185 +++++++++++++++++++++++++++++++++++++++++--
 2 files changed, 189 insertions(+), 6 deletions(-)

diff --git a/include/linux/bpf_verifier.h b/include/linux/bpf_verifier.h
index 3f84f3e87704..27b74947cd2b 100644
--- a/include/linux/bpf_verifier.h
+++ b/include/linux/bpf_verifier.h
@@ -148,6 +148,7 @@ struct bpf_verifier_state {
 	/* call stack tracking */
 	struct bpf_func_state *frame[MAX_CALL_FRAMES];
 	u32 curframe;
+	bool speculative;
 };
 
 #define bpf_get_spilled_reg(slot, frame)				\
@@ -167,15 +168,24 @@ struct bpf_verifier_state_list {
 	struct bpf_verifier_state_list *next;
 };
 
+/* Possible states for alu_state member. */
+#define BPF_ALU_SANITIZE_SRC		1U
+#define BPF_ALU_SANITIZE_DST		2U
+#define BPF_ALU_NEG_VALUE		(1U << 2)
+#define BPF_ALU_SANITIZE		(BPF_ALU_SANITIZE_SRC | \
+					 BPF_ALU_SANITIZE_DST)
+
 struct bpf_insn_aux_data {
 	union {
 		enum bpf_reg_type ptr_type;	/* pointer type for load/store insns */
 		unsigned long map_state;	/* pointer/poison value for maps */
 		s32 call_imm;			/* saved imm field of call insn */
+		u32 alu_limit;			/* limit for add/sub register with pointer */
 	};
 	int ctx_field_size; /* the ctx field size for load insn, maybe 0 */
 	int sanitize_stack_off; /* stack slot to be cleared */
 	bool seen; /* this insn was processed by the verifier */
+	u8 alu_state; /* used in combination with alu_limit */
 };
 
 #define MAX_USED_MAPS 64 /* max number of maps accessed by one eBPF program */
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 8e5da1ce5da4..f6bc62a9ee8e 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -710,6 +710,7 @@ static int copy_verifier_state(struct bpf_verifier_state *dst_state,
 		free_func_state(dst_state->frame[i]);
 		dst_state->frame[i] = NULL;
 	}
+	dst_state->speculative = src->speculative;
 	dst_state->curframe = src->curframe;
 	for (i = 0; i <= src->curframe; i++) {
 		dst = dst_state->frame[i];
@@ -754,7 +755,8 @@ static int pop_stack(struct bpf_verifier_env *env, int *prev_insn_idx,
 }
 
 static struct bpf_verifier_state *push_stack(struct bpf_verifier_env *env,
-					     int insn_idx, int prev_insn_idx)
+					     int insn_idx, int prev_insn_idx,
+					     bool speculative)
 {
 	struct bpf_verifier_state *cur = env->cur_state;
 	struct bpf_verifier_stack_elem *elem;
@@ -772,6 +774,7 @@ static struct bpf_verifier_state *push_stack(struct bpf_verifier_env *env,
 	err = copy_verifier_state(&elem->st, cur);
 	if (err)
 		goto err;
+	elem->st.speculative |= speculative;
 	if (env->stack_size > BPF_COMPLEXITY_LIMIT_STACK) {
 		verbose(env, "BPF program is too complex\n");
 		goto err;
@@ -3067,6 +3070,102 @@ static bool check_reg_sane_offset(struct bpf_verifier_env *env,
 	return true;
 }
 
+static struct bpf_insn_aux_data *cur_aux(struct bpf_verifier_env *env)
+{
+	return &env->insn_aux_data[env->insn_idx];
+}
+
+static int retrieve_ptr_limit(const struct bpf_reg_state *ptr_reg,
+			      u32 *ptr_limit, u8 opcode, bool off_is_neg)
+{
+	bool mask_to_left = (opcode == BPF_ADD &&  off_is_neg) ||
+			    (opcode == BPF_SUB && !off_is_neg);
+	u32 off;
+
+	switch (ptr_reg->type) {
+	case PTR_TO_STACK:
+		off = ptr_reg->off + ptr_reg->var_off.value;
+		if (mask_to_left)
+			*ptr_limit = MAX_BPF_STACK + off;
+		else
+			*ptr_limit = -off;
+		return 0;
+	case PTR_TO_MAP_VALUE:
+		if (mask_to_left) {
+			*ptr_limit = ptr_reg->umax_value + ptr_reg->off;
+		} else {
+			off = ptr_reg->smin_value + ptr_reg->off;
+			*ptr_limit = ptr_reg->map_ptr->value_size - off;
+		}
+		return 0;
+	default:
+		return -EINVAL;
+	}
+}
+
+static int sanitize_ptr_alu(struct bpf_verifier_env *env,
+			    struct bpf_insn *insn,
+			    const struct bpf_reg_state *ptr_reg,
+			    struct bpf_reg_state *dst_reg,
+			    bool off_is_neg)
+{
+	struct bpf_verifier_state *vstate = env->cur_state;
+	struct bpf_insn_aux_data *aux = cur_aux(env);
+	bool ptr_is_dst_reg = ptr_reg == dst_reg;
+	u8 opcode = BPF_OP(insn->code);
+	u32 alu_state, alu_limit;
+	struct bpf_reg_state tmp;
+	bool ret;
+
+	if (env->allow_ptr_leaks || BPF_SRC(insn->code) == BPF_K)
+		return 0;
+
+	/* We already marked aux for masking from non-speculative
+	 * paths, thus we got here in the first place. We only care
+	 * to explore bad access from here.
+	 */
+	if (vstate->speculative)
+		goto do_sim;
+
+	alu_state  = off_is_neg ? BPF_ALU_NEG_VALUE : 0;
+	alu_state |= ptr_is_dst_reg ?
+		     BPF_ALU_SANITIZE_SRC : BPF_ALU_SANITIZE_DST;
+
+	if (retrieve_ptr_limit(ptr_reg, &alu_limit, opcode, off_is_neg))
+		return 0;
+
+	/* If we arrived here from different branches with different
+	 * limits to sanitize, then this won't work.
+	 */
+	if (aux->alu_state &&
+	    (aux->alu_state != alu_state ||
+	     aux->alu_limit != alu_limit))
+		return -EACCES;
+
+	/* Corresponding fixup done in fixup_bpf_calls(). */
+	aux->alu_state = alu_state;
+	aux->alu_limit = alu_limit;
+
+do_sim:
+	/* Simulate and find potential out-of-bounds access under
+	 * speculative execution from truncation as a result of
+	 * masking when off was not within expected range. If off
+	 * sits in dst, then we temporarily need to move ptr there
+	 * to simulate dst (== 0) +/-= ptr. Needed, for example,
+	 * for cases where we use K-based arithmetic in one direction
+	 * and truncated reg-based in the other in order to explore
+	 * bad access.
+	 */
+	if (!ptr_is_dst_reg) {
+		tmp = *dst_reg;
+		*dst_reg = *ptr_reg;
+	}
+	ret = push_stack(env, env->insn_idx + 1, env->insn_idx, true);
+	if (!ptr_is_dst_reg)
+		*dst_reg = tmp;
+	return !ret ? -EFAULT : 0;
+}
+
 /* Handles arithmetic on a pointer and a scalar: computes new min/max and var_off.
  * Caller should also handle BPF_MOV case separately.
  * If we return -EACCES, caller may want to try again treating pointer as a
@@ -3087,6 +3186,7 @@ static int adjust_ptr_min_max_vals(struct bpf_verifier_env *env,
 	    umin_ptr = ptr_reg->umin_value, umax_ptr = ptr_reg->umax_value;
 	u32 dst = insn->dst_reg, src = insn->src_reg;
 	u8 opcode = BPF_OP(insn->code);
+	int ret;
 
 	dst_reg = &regs[dst];
 
@@ -3142,6 +3242,11 @@ static int adjust_ptr_min_max_vals(struct bpf_verifier_env *env,
 
 	switch (opcode) {
 	case BPF_ADD:
+		ret = sanitize_ptr_alu(env, insn, ptr_reg, dst_reg, smin_val < 0);
+		if (ret < 0) {
+			verbose(env, "R%d tried to add from different maps or paths\n", dst);
+			return ret;
+		}
 		/* We can take a fixed offset as long as it doesn't overflow
 		 * the s32 'off' field
 		 */
@@ -3192,6 +3297,11 @@ static int adjust_ptr_min_max_vals(struct bpf_verifier_env *env,
 		}
 		break;
 	case BPF_SUB:
+		ret = sanitize_ptr_alu(env, insn, ptr_reg, dst_reg, smin_val < 0);
+		if (ret < 0) {
+			verbose(env, "R%d tried to sub from different maps or paths\n", dst);
+			return ret;
+		}
 		if (dst_reg == off_reg) {
 			/* scalar -= pointer.  Creates an unknown scalar */
 			verbose(env, "R%d tried to subtract pointer from scalar\n",
@@ -4389,7 +4499,8 @@ static int check_cond_jmp_op(struct bpf_verifier_env *env,
 		}
 	}
 
-	other_branch = push_stack(env, *insn_idx + insn->off + 1, *insn_idx);
+	other_branch = push_stack(env, *insn_idx + insn->off + 1, *insn_idx,
+				  false);
 	if (!other_branch)
 		return -EFAULT;
 	other_branch_regs = other_branch->frame[other_branch->curframe]->regs;
@@ -5499,6 +5610,12 @@ static bool states_equal(struct bpf_verifier_env *env,
 	if (old->curframe != cur->curframe)
 		return false;
 
+	/* Verification state from speculative execution simulation
+	 * must never prune a non-speculative execution one.
+	 */
+	if (old->speculative && !cur->speculative)
+		return false;
+
 	/* for states to be equal callsites have to be the same
 	 * and all frame states need to be equivalent
 	 */
@@ -5700,6 +5817,7 @@ static int do_check(struct bpf_verifier_env *env)
 	if (!state)
 		return -ENOMEM;
 	state->curframe = 0;
+	state->speculative = false;
 	state->frame[0] = kzalloc(sizeof(struct bpf_func_state), GFP_KERNEL);
 	if (!state->frame[0]) {
 		kfree(state);
@@ -5739,8 +5857,10 @@ static int do_check(struct bpf_verifier_env *env)
 			/* found equivalent state, can prune the search */
 			if (env->log.level) {
 				if (do_print_state)
-					verbose(env, "\nfrom %d to %d: safe\n",
-						env->prev_insn_idx, env->insn_idx);
+					verbose(env, "\nfrom %d to %d%s: safe\n",
+						env->prev_insn_idx, env->insn_idx,
+						env->cur_state->speculative ?
+						" (speculative execution)" : "");
 				else
 					verbose(env, "%d: safe\n", env->insn_idx);
 			}
@@ -5757,8 +5877,10 @@ static int do_check(struct bpf_verifier_env *env)
 			if (env->log.level > 1)
 				verbose(env, "%d:", env->insn_idx);
 			else
-				verbose(env, "\nfrom %d to %d:",
-					env->prev_insn_idx, env->insn_idx);
+				verbose(env, "\nfrom %d to %d%s:",
+					env->prev_insn_idx, env->insn_idx,
+					env->cur_state->speculative ?
+					" (speculative execution)" : "");
 			print_verifier_state(env, state->frame[state->curfram
... [diff truncated at 9000 chars; the touched functions are all above]

```


---
## f6b1b3bf0d5f — bpf: fix subprog verifier bypass by div/mod by 0 exception

```diff
 kernel/bpf/core.c     |  8 --------
 kernel/bpf/verifier.c | 38 ++++++++++++++++++++++++++++++--------
 2 files changed, 30 insertions(+), 16 deletions(-)

diff --git a/kernel/bpf/core.c b/kernel/bpf/core.c
index 8301de2d1f96..5f35f93dcab2 100644
--- a/kernel/bpf/core.c
+++ b/kernel/bpf/core.c
@@ -999,14 +999,10 @@ static u64 ___bpf_prog_run(u64 *regs, const struct bpf_insn *insn, u64 *stack)
 		(*(s64 *) &DST) >>= IMM;
 		CONT;
 	ALU64_MOD_X:
-		if (unlikely(SRC == 0))
-			return 0;
 		div64_u64_rem(DST, SRC, &tmp);
 		DST = tmp;
 		CONT;
 	ALU_MOD_X:
-		if (unlikely((u32)SRC == 0))
-			return 0;
 		tmp = (u32) DST;
 		DST = do_div(tmp, (u32) SRC);
 		CONT;
@@ -1019,13 +1015,9 @@ static u64 ___bpf_prog_run(u64 *regs, const struct bpf_insn *insn, u64 *stack)
 		DST = do_div(tmp, (u32) IMM);
 		CONT;
 	ALU64_DIV_X:
-		if (unlikely(SRC == 0))
-			return 0;
 		DST = div64_u64(DST, SRC);
 		CONT;
 	ALU_DIV_X:
-		if (unlikely((u32)SRC == 0))
-			return 0;
 		tmp = (u32) DST;
 		do_div(tmp, (u32) SRC);
 		DST = (u32) tmp;
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 0c5269415090..5fb69a85d967 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -5400,15 +5400,37 @@ static int fixup_bpf_calls(struct bpf_verifier_env *env)
 	int i, cnt, delta = 0;
 
 	for (i = 0; i < insn_cnt; i++, insn++) {
-		if (insn->code == (BPF_ALU | BPF_MOD | BPF_X) ||
+		if (insn->code == (BPF_ALU64 | BPF_MOD | BPF_X) ||
+		    insn->code == (BPF_ALU64 | BPF_DIV | BPF_X) ||
+		    insn->code == (BPF_ALU | BPF_MOD | BPF_X) ||
 		    insn->code == (BPF_ALU | BPF_DIV | BPF_X)) {
-			/* due to JIT bugs clear upper 32-bits of src register
-			 * before div/mod operation
-			 */
-			insn_buf[0] = BPF_MOV32_REG(insn->src_reg, insn->src_reg);
-			insn_buf[1] = *insn;
-			cnt = 2;
-			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
+			bool is64 = BPF_CLASS(insn->code) == BPF_ALU64;
+			struct bpf_insn mask_and_div[] = {
+				BPF_MOV32_REG(insn->src_reg, insn->src_reg),
+				/* Rx div 0 -> 0 */
+				BPF_JMP_IMM(BPF_JNE, insn->src_reg, 0, 2),
+				BPF_ALU32_REG(BPF_XOR, insn->dst_reg, insn->dst_reg),
+				BPF_JMP_IMM(BPF_JA, 0, 0, 1),
+				*insn,
+			};
+			struct bpf_insn mask_and_mod[] = {
+				BPF_MOV32_REG(insn->src_reg, insn->src_reg),
+				/* Rx mod 0 -> Rx */
+				BPF_JMP_IMM(BPF_JEQ, insn->src_reg, 0, 1),
+				*insn,
+			};
+			struct bpf_insn *patchlet;
+
+			if (insn->code == (BPF_ALU64 | BPF_DIV | BPF_X) ||
+			    insn->code == (BPF_ALU | BPF_DIV | BPF_X)) {
+				patchlet = mask_and_div + (is64 ? 1 : 0);
+				cnt = ARRAY_SIZE(mask_and_div) - (is64 ? 1 : 0);
+			} else {
+				patchlet = mask_and_mod + (is64 ? 1 : 0);
+				cnt = ARRAY_SIZE(mask_and_mod) - (is64 ? 1 : 0);
+			}
+
+			new_prog = bpf_patch_insn_data(env, i + delta, patchlet, cnt);
 			if (!new_prog)
 				return -ENOMEM;
 

```


---
## bb7f0f989ca7 — bpf: fix integer overflows

```diff
 include/linux/bpf_verifier.h |  4 ++--
 kernel/bpf/verifier.c        | 48 ++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 50 insertions(+), 2 deletions(-)

diff --git a/include/linux/bpf_verifier.h b/include/linux/bpf_verifier.h
index c561b986bab0..1632bb13ad8a 100644
--- a/include/linux/bpf_verifier.h
+++ b/include/linux/bpf_verifier.h
@@ -15,11 +15,11 @@
  * In practice this is far bigger than any realistic pointer offset; this limit
  * ensures that umax_value + (int)off + (int)size cannot overflow a u64.
  */
-#define BPF_MAX_VAR_OFF	(1ULL << 31)
+#define BPF_MAX_VAR_OFF	(1 << 29)
 /* Maximum variable size permitted for ARG_CONST_SIZE[_OR_ZERO].  This ensures
  * that converting umax_value to int cannot overflow.
  */
-#define BPF_MAX_VAR_SIZ	INT_MAX
+#define BPF_MAX_VAR_SIZ	(1 << 29)
 
 /* Liveness marks, used for registers and spilled-regs (in stack slots).
  * Read marks propagate upwards until they find a write mark; they record that
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 982bd9ec721a..86dfe6b5c243 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -1819,6 +1819,41 @@ static bool signed_sub_overflows(s64 a, s64 b)
 	return res > a;
 }
 
+static bool check_reg_sane_offset(struct bpf_verifier_env *env,
+				  const struct bpf_reg_state *reg,
+				  enum bpf_reg_type type)
+{
+	bool known = tnum_is_const(reg->var_off);
+	s64 val = reg->var_off.value;
+	s64 smin = reg->smin_value;
+
+	if (known && (val >= BPF_MAX_VAR_OFF || val <= -BPF_MAX_VAR_OFF)) {
+		verbose(env, "math between %s pointer and %lld is not allowed\n",
+			reg_type_str[type], val);
+		return false;
+	}
+
+	if (reg->off >= BPF_MAX_VAR_OFF || reg->off <= -BPF_MAX_VAR_OFF) {
+		verbose(env, "%s pointer offset %d is not allowed\n",
+			reg_type_str[type], reg->off);
+		return false;
+	}
+
+	if (smin == S64_MIN) {
+		verbose(env, "math between %s pointer and register with unbounded min value is not allowed\n",
+			reg_type_str[type]);
+		return false;
+	}
+
+	if (smin >= BPF_MAX_VAR_OFF || smin <= -BPF_MAX_VAR_OFF) {
+		verbose(env, "value %lld makes %s pointer be out of bounds\n",
+			smin, reg_type_str[type]);
+		return false;
+	}
+
+	return true;
+}
+
 /* Handles arithmetic on a pointer and a scalar: computes new min/max and var_off.
  * Caller should also handle BPF_MOV case separately.
  * If we return -EACCES, caller may want to try again treating pointer as a
@@ -1887,6 +1922,10 @@ static int adjust_ptr_min_max_vals(struct bpf_verifier_env *env,
 	dst_reg->type = ptr_reg->type;
 	dst_reg->id = ptr_reg->id;
 
+	if (!check_reg_sane_offset(env, off_reg, ptr_reg->type) ||
+	    !check_reg_sane_offset(env, ptr_reg, ptr_reg->type))
+		return -EINVAL;
+
 	switch (opcode) {
 	case BPF_ADD:
 		/* We can take a fixed offset as long as it doesn't overflow
@@ -2017,6 +2056,9 @@ static int adjust_ptr_min_max_vals(struct bpf_verifier_env *env,
 		return -EACCES;
 	}
 
+	if (!check_reg_sane_offset(env, dst_reg, ptr_reg->type))
+		return -EINVAL;
+
 	__update_reg_bounds(dst_reg);
 	__reg_deduce_bounds(dst_reg);
 	__reg_bound_offset(dst_reg);
@@ -2046,6 +2088,12 @@ static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
 	src_known = tnum_is_const(src_reg.var_off);
 	dst_known = tnum_is_const(dst_reg->var_off);
 
+	if (!src_known &&
+	    opcode != BPF_ADD && opcode != BPF_SUB && opcode != BPF_AND) {
+		__mark_reg_unknown(dst_reg);
+		return 0;
+	}
+
 	switch (opcode) {
 	case BPF_ADD:
 		if (signed_add_overflows(dst_reg->smin_value, smin_val) ||

```


---
## 4cabc5b186b5 — bpf: fix mixed signed/unsigned derived min/max value bounds

```diff
 include/linux/bpf_verifier.h |   1 +
 kernel/bpf/verifier.c        | 108 +++++++++++++++++++++++++++++++++++++------
 2 files changed, 95 insertions(+), 14 deletions(-)

diff --git a/include/linux/bpf_verifier.h b/include/linux/bpf_verifier.h
index 621076f56251..8e5d31f6faef 100644
--- a/include/linux/bpf_verifier.h
+++ b/include/linux/bpf_verifier.h
@@ -43,6 +43,7 @@ struct bpf_reg_state {
 	u32 min_align;
 	u32 aux_off;
 	u32 aux_off_align;
+	bool value_from_signed;
 };
 
 enum bpf_stack_slot_type {
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 6a86723c5b64..af9e84a4944e 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -504,6 +504,7 @@ static void reset_reg_range_values(struct bpf_reg_state *regs, u32 regno)
 {
 	regs[regno].min_value = BPF_REGISTER_MIN_RANGE;
 	regs[regno].max_value = BPF_REGISTER_MAX_RANGE;
+	regs[regno].value_from_signed = false;
 	regs[regno].min_align = 0;
 }
 
@@ -777,12 +778,13 @@ static int check_ctx_access(struct bpf_verifier_env *env, int insn_idx, int off,
 	return -EACCES;
 }
 
-static bool is_pointer_value(struct bpf_verifier_env *env, int regno)
+static bool __is_pointer_value(bool allow_ptr_leaks,
+			       const struct bpf_reg_state *reg)
 {
-	if (env->allow_ptr_leaks)
+	if (allow_ptr_leaks)
 		return false;
 
-	switch (env->cur_state.regs[regno].type) {
+	switch (reg->type) {
 	case UNKNOWN_VALUE:
 	case CONST_IMM:
 		return false;
@@ -791,6 +793,11 @@ static bool is_pointer_value(struct bpf_verifier_env *env, int regno)
 	}
 }
 
+static bool is_pointer_value(struct bpf_verifier_env *env, int regno)
+{
+	return __is_pointer_value(env->allow_ptr_leaks, &env->cur_state.regs[regno]);
+}
+
 static int check_pkt_ptr_alignment(const struct bpf_reg_state *reg,
 				   int off, int size, bool strict)
 {
@@ -1832,10 +1839,24 @@ static void adjust_reg_min_max_vals(struct bpf_verifier_env *env,
 	dst_align = dst_reg->min_align;
 
 	/* We don't know anything about what was done to this register, mark it
-	 * as unknown.
+	 * as unknown. Also, if both derived bounds came from signed/unsigned
+	 * mixed compares and one side is unbounded, we cannot really do anything
+	 * with them as boundaries cannot be trusted. Thus, arithmetic of two
+	 * regs of such kind will get invalidated bounds on the dst side.
 	 */
-	if (min_val == BPF_REGISTER_MIN_RANGE &&
-	    max_val == BPF_REGISTER_MAX_RANGE) {
+	if ((min_val == BPF_REGISTER_MIN_RANGE &&
+	     max_val == BPF_REGISTER_MAX_RANGE) ||
+	    (BPF_SRC(insn->code) == BPF_X &&
+	     ((min_val != BPF_REGISTER_MIN_RANGE &&
+	       max_val == BPF_REGISTER_MAX_RANGE) ||
+	      (min_val == BPF_REGISTER_MIN_RANGE &&
+	       max_val != BPF_REGISTER_MAX_RANGE) ||
+	      (dst_reg->min_value != BPF_REGISTER_MIN_RANGE &&
+	       dst_reg->max_value == BPF_REGISTER_MAX_RANGE) ||
+	      (dst_reg->min_value == BPF_REGISTER_MIN_RANGE &&
+	       dst_reg->max_value != BPF_REGISTER_MAX_RANGE)) &&
+	     regs[insn->dst_reg].value_from_signed !=
+	     regs[insn->src_reg].value_from_signed)) {
 		reset_reg_range_values(regs, insn->dst_reg);
 		return;
 	}
@@ -2023,6 +2044,7 @@ static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
 			regs[insn->dst_reg].max_value = insn->imm;
 			regs[insn->dst_reg].min_value = insn->imm;
 			regs[insn->dst_reg].min_align = calc_align(insn->imm);
+			regs[insn->dst_reg].value_from_signed = false;
 		}
 
 	} else if (opcode > BPF_END) {
@@ -2198,40 +2220,63 @@ static void reg_set_min_max(struct bpf_reg_state *true_reg,
 			    struct bpf_reg_state *false_reg, u64 val,
 			    u8 opcode)
 {
+	bool value_from_signed = true;
+	bool is_range = true;
+
 	switch (opcode) {
 	case BPF_JEQ:
 		/* If this is false then we know nothing Jon Snow, but if it is
 		 * true then we know for sure.
 		 */
 		true_reg->max_value = true_reg->min_value = val;
+		is_range = false;
 		break;
 	case BPF_JNE:
 		/* If this is true we know nothing Jon Snow, but if it is false
 		 * we know the value for sure;
 		 */
 		false_reg->max_value = false_reg->min_value = val;
+		is_range = false;
 		break;
 	case BPF_JGT:
-		/* Unsigned comparison, the minimum value is 0. */
-		false_reg->min_value = 0;
+		value_from_signed = false;
 		/* fallthrough */
 	case BPF_JSGT:
+		if (true_reg->value_from_signed != value_from_signed)
+			reset_reg_range_values(true_reg, 0);
+		if (false_reg->value_from_signed != value_from_signed)
+			reset_reg_range_values(false_reg, 0);
+		if (opcode == BPF_JGT) {
+			/* Unsigned comparison, the minimum value is 0. */
+			false_reg->min_value = 0;
+		}
 		/* If this is false then we know the maximum val is val,
 		 * otherwise we know the min val is val+1.
 		 */
 		false_reg->max_value = val;
+		false_reg->value_from_signed = value_from_signed;
 		true_reg->min_value = val + 1;
+		true_reg->value_from_signed = value_from_signed;
 		break;
 	case BPF_JGE:
-		/* Unsigned comparison, the minimum value is 0. */
-		false_reg->min_value = 0;
+		value_from_signed = false;
 		/* fallthrough */
 	case BPF_JSGE:
+		if (true_reg->value_from_signed != value_from_signed)
+			reset_reg_range_values(true_reg, 0);
+		if (false_reg->value_from_signed != value_from_signed)
+			reset_reg_range_values(false_reg, 0);
+		if (opcode == BPF_JGE) {
+			/* Unsigned comparison, the minimum value is 0. */
+			false_reg->min_value = 0;
+		}
 		/* If this is false then we know the maximum value is val - 1,
 		 * otherwise we know the mimimum value is val.
 		 */
 		false_reg->max_value = val - 1;
+		false_reg->value_from_signed = value_from_signed;
 		true_reg->min_value = val;
+		true_reg->value_from_signed = value_from_signed;
 		break;
 	default:
 		break;
@@ -2239,6 +2284,12 @@ static void reg_set_min_max(struct bpf_reg_state *true_reg,
 
 	check_reg_overflow(false_reg);
 	check_reg_overflow(true_reg);
+	if (is_range) {
+		if (__is_pointer_value(false, false_reg))
+			reset_reg_range_values(false_reg, 0);
+		if (__is_pointer_value(false, true_reg))
+			reset_reg_range_values(true_reg, 0);
+	}
 }
 
 /* Same as above, but for the case that dst_reg is a CONST_IMM reg and src_reg
@@ -2248,41 +2299,64 @@ static void reg_set_min_max_inv(struct bpf_reg_state *true_reg,
 				struct bpf_reg_state *false_reg, u64 val,
 				u8 opcode)
 {
+	bool value_from_signed = true;
+	bool is_range = true;
+
 	switch (opcode) {
 	case BPF_JEQ:
 		/* If this is false then we know nothing Jon Snow, but if it is
 		 * true then we know for sure.
 		 */
 		true_reg->max_value = true_reg->min_value = val;
+		is_range = false;
 		break;
 	case BPF_JNE:
 		/* If this is true we know nothing Jon Snow, but if it is false
 		 * we know the value for sure;
 		 */
 		false_reg->max_value = false_reg->min_value = val;
+		is_range = false;
 		break;
 	case BPF_JGT:
-		/* Unsigned comparison, the minimum value is 0. */
-		true_reg->min_value = 0;
+		value_from_signed = false;
 		/* fallthrough */
 	case BPF_JSGT:
+		if (true_reg->value_from_signed != value_from_signed)
+			reset_reg_range_values(true_reg, 0);
+		if (false_reg->value_from_signed != value_from_signed)
+			reset_reg_range_values(false_reg, 0);
+		if (opcode == BPF_JGT) {
+			/* Unsigned comparison, the minimum value is 0. */
+			true_reg->min_value = 0;
+		}
 		/*
 		 * If this is false, then the val is <= the register, if it is
 		 * true the register <= to the val.
 		 */
 		false_reg->min_value = val;
+		false_reg->value_from_signed = value_from_signed;
 		true_reg->max_value = val - 1;
+		true_reg->value_from_signed = value_from_signed;
 		break;
 	case BPF_JGE:
-		/* Unsigned comparison, the minimum value is 0. */
-		true_reg->min_value = 0;
+		value_from_signed = false;
 		/* fallthrough */
 	case BPF_JSGE:
+		if (true_reg->value_from_signed != value_from_signed)
+			reset_reg_range_values(true_reg, 0);
+		if (false_reg->value_from_signed != value_from_signed)
+			reset_reg_range_values(false_reg, 0);
+		if (opcode == BPF_JGE) {
+			/* Unsigned comparison, the minimum value is 0. */
+			true_reg->min_value = 0;
+		}
 		/* If this is false then constant < register, if it is true then
 		 * the register < constant.
 		 */
 		false_reg->min_value = val + 1;
+		false_reg->value_from_signed = value_from_signed;
 		true_reg->max_value = val;
+		true_reg->value_from_signed = value_from_signed;
 		break;
 	default:
 		break;
@@ -2290,6 +2364,12 @@ static void reg_set_min_max_inv(struct bpf_reg_state *true_reg,
 
 	check_reg_overflow(false_reg);
 	check_reg_overflow(true_reg);
+	if (is_range) {
+		if (__is_pointer_value(false, false_reg))
+			reset_reg_range_values(false_reg, 0);
+		if (__is_pointer_value(false, true_reg))
+			reset_reg_range_values(true_reg, 0);
+	}
 }
 
 static void mark_map_reg(struct bpf_reg_state *regs, u32 regno, u32 id,

```


---
## 6bdf6abc56b5 — bpf: prevent leaking pointer via xadd on unpriviledged

```diff
 kernel/bpf/verifier.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 339c8a1371de..a8a725697bed 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -989,6 +989,11 @@ static int check_xadd(struct bpf_verifier_env *env, struct bpf_insn *insn)
 	if (err)
 		return err;
 
+	if (is_pointer_value(env, insn->src_reg)) {
+		verbose("R%d leaks addr into mem\n", insn->src_reg);
+		return -EACCES;
+	}
+
 	/* check whether atomic_add can read the memory */
 	err = check_mem_access(env, insn->dst_reg, insn->off,
 			       BPF_SIZE(insn->code), BPF_READ, -1);

```


---
## 1ad2f5838d34 — bpf: fix incorrect pruning decision when alignment must be tracked

```diff
 kernel/bpf/verifier.c | 19 ++++++++++---------
 1 file changed, 10 insertions(+), 9 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index c72cd41f5b8b..e37e06b1229d 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -843,9 +843,6 @@ static int check_ptr_alignment(struct bpf_verifier_env *env,
 {
 	bool strict = env->strict_alignment;
 
-	if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
-		strict = true;
-
 	switch (reg->type) {
 	case PTR_TO_PACKET:
 		return check_pkt_ptr_alignment(reg, off, size, strict);
@@ -2696,7 +2693,8 @@ static int check_cfg(struct bpf_verifier_env *env)
 /* the following conditions reduce the number of explored insns
  * from ~140k to ~80k for ultra large programs that use a lot of ptr_to_packet
  */
-static bool compare_ptrs_to_packet(struct bpf_reg_state *old,
+static bool compare_ptrs_to_packet(struct bpf_verifier_env *env,
+				   struct bpf_reg_state *old,
 				   struct bpf_reg_state *cur)
 {
 	if (old->id != cur->id)
@@ -2739,7 +2737,7 @@ static bool compare_ptrs_to_packet(struct bpf_reg_state *old,
 	 * 'if (R4 > data_end)' and all further insn were already good with r=20,
 	 * so they will be good with r=30 and we can prune the search.
 	 */
-	if (old->off <= cur->off &&
+	if (!env->strict_alignment && old->off <= cur->off &&
 	    old->off >= old->range && cur->off >= cur->range)
 		return true;
 
@@ -2810,7 +2808,7 @@ static bool states_equal(struct bpf_verifier_env *env,
 			continue;
 
 		if (rold->type == PTR_TO_PACKET && rcur->type == PTR_TO_PACKET &&
-		    compare_ptrs_to_packet(rold, rcur))
+		    compare_ptrs_to_packet(env, rold, rcur))
 			continue;
 
 		return false;
@@ -3588,10 +3586,10 @@ int bpf_check(struct bpf_prog **prog, union bpf_attr *attr)
 	} else {
 		log_level = 0;
 	}
-	if (attr->prog_flags & BPF_F_STRICT_ALIGNMENT)
+
+	env->strict_alignment = !!(attr->prog_flags & BPF_F_STRICT_ALIGNMENT);
+	if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
 		env->strict_alignment = true;
-	else
-		env->strict_alignment = false;
 
 	ret = replace_map_fd_with_map_ptr(env);
 	if (ret < 0)
@@ -3697,7 +3695,10 @@ int bpf_analyzer(struct bpf_prog *prog, const struct bpf_ext_analyzer_ops *ops,
 	mutex_lock(&bpf_verifier_lock);
 
 	log_level = 0;
+
 	env->strict_alignment = false;
+	if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
+		env->strict_alignment = true;
 
 	env->explored_states = kcalloc(env->prog->len,
 				       sizeof(struct bpf_verifier_state_list *),

```


---
## 79adffcd6489 — bpf, verifier: fix rejection of unaligned access checks for map_value_adj

```diff
 kernel/bpf/verifier.c | 58 +++++++++++++++++++++++++++++++++------------------
 1 file changed, 38 insertions(+), 20 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 86deddecff25..a834068a400e 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -765,38 +765,56 @@ static bool is_pointer_value(struct bpf_verifier_env *env, int regno)
 	}
 }
 
-static int check_ptr_alignment(struct bpf_verifier_env *env,
-			       struct bpf_reg_state *reg, int off, int size)
+static int check_pkt_ptr_alignment(const struct bpf_reg_state *reg,
+				   int off, int size)
 {
-	if (reg->type != PTR_TO_PACKET && reg->type != PTR_TO_MAP_VALUE_ADJ) {
-		if (off % size != 0) {
-			verbose("misaligned access off %d size %d\n",
-				off, size);
-			return -EACCES;
-		} else {
-			return 0;
-		}
-	}
-
-	if (IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
-		/* misaligned access to packet is ok on x86,arm,arm64 */
-		return 0;
-
 	if (reg->id && size != 1) {
-		verbose("Unknown packet alignment. Only byte-sized access allowed\n");
+		verbose("Unknown alignment. Only byte-sized access allowed in packet access.\n");
 		return -EACCES;
 	}
 
 	/* skb->data is NET_IP_ALIGN-ed */
-	if (reg->type == PTR_TO_PACKET &&
-	    (NET_IP_ALIGN + reg->off + off) % size != 0) {
+	if ((NET_IP_ALIGN + reg->off + off) % size != 0) {
 		verbose("misaligned packet access off %d+%d+%d size %d\n",
 			NET_IP_ALIGN, reg->off, off, size);
 		return -EACCES;
 	}
+
 	return 0;
 }
 
+static int check_val_ptr_alignment(const struct bpf_reg_state *reg,
+				   int size)
+{
+	if (size != 1) {
+		verbose("Unknown alignment. Only byte-sized access allowed in value access.\n");
+		return -EACCES;
+	}
+
+	return 0;
+}
+
+static int check_ptr_alignment(const struct bpf_reg_state *reg,
+			       int off, int size)
+{
+	switch (reg->type) {
+	case PTR_TO_PACKET:
+		return IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) ? 0 :
+		       check_pkt_ptr_alignment(reg, off, size);
+	case PTR_TO_MAP_VALUE_ADJ:
+		return IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) ? 0 :
+		       check_val_ptr_alignment(reg, size);
+	default:
+		if (off % size != 0) {
+			verbose("misaligned access off %d size %d\n",
+				off, size);
+			return -EACCES;
+		}
+
+		return 0;
+	}
+}
+
 /* check whether memory at (regno + off) is accessible for t = (read | write)
  * if t==write, value_regno is a register which value is stored into memory
  * if t==read, value_regno is a register which will receive the value from memory
@@ -818,7 +836,7 @@ static int check_mem_access(struct bpf_verifier_env *env, u32 regno, int off,
 	if (size < 0)
 		return size;
 
-	err = check_ptr_alignment(env, reg, off, size);
+	err = check_ptr_alignment(reg, off, size);
 	if (err)
 		return err;
 

```


---
## fce366a9dd0d — bpf, verifier: fix alu ops against map_value{, _adj} register types

```diff
 kernel/bpf/verifier.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 5e6202e62265..86deddecff25 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -1925,6 +1925,7 @@ static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
 		 * register as unknown.
 		 */
 		if (env->allow_ptr_leaks &&
+		    BPF_CLASS(insn->code) == BPF_ALU64 && opcode == BPF_ADD &&
 		    (dst_reg->type == PTR_TO_MAP_VALUE ||
 		     dst_reg->type == PTR_TO_MAP_VALUE_ADJ))
 			dst_reg->type = PTR_TO_MAP_VALUE_ADJ;

```


---
## 2d2be8cab26e — bpf: fix range propagation on direct packet access

```diff
 kernel/bpf/verifier.c | 55 +++++++++++++++++++++++++++++++++++++--------------
 1 file changed, 40 insertions(+), 15 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 48c2705db22c..90493a66dddd 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -1637,21 +1637,42 @@ static int check_alu_op(struct verifier_env *env, struct bpf_insn *insn)
 	return 0;
 }
 
-static void find_good_pkt_pointers(struct verifier_env *env,
-				   struct reg_state *dst_reg)
+static void find_good_pkt_pointers(struct verifier_state *state,
+				   const struct reg_state *dst_reg)
 {
-	struct verifier_state *state = &env->cur_state;
 	struct reg_state *regs = state->regs, *reg;
 	int i;
-	/* r2 = r3;
-	 * r2 += 8
-	 * if (r2 > pkt_end) goto somewhere
-	 * r2 == dst_reg, pkt_end == src_reg,
-	 * r2=pkt(id=n,off=8,r=0)
-	 * r3=pkt(id=n,off=0,r=0)
-	 * find register r3 and mark its range as r3=pkt(id=n,off=0,r=8)
-	 * so that range of bytes [r3, r3 + 8) is safe to access
+
+	/* LLVM can generate two kind of checks:
+	 *
+	 * Type 1:
+	 *
+	 *   r2 = r3;
+	 *   r2 += 8;
+	 *   if (r2 > pkt_end) goto <handle exception>
+	 *   <access okay>
+	 *
+	 *   Where:
+	 *     r2 == dst_reg, pkt_end == src_reg
+	 *     r2=pkt(id=n,off=8,r=0)
+	 *     r3=pkt(id=n,off=0,r=0)
+	 *
+	 * Type 2:
+	 *
+	 *   r2 = r3;
+	 *   r2 += 8;
+	 *   if (pkt_end >= r2) goto <access okay>
+	 *   <handle exception>
+	 *
+	 *   Where:
+	 *     pkt_end == dst_reg, r2 == src_reg
+	 *     r2=pkt(id=n,off=8,r=0)
+	 *     r3=pkt(id=n,off=0,r=0)
+	 *
+	 * Find register r3 and mark its range as r3=pkt(id=n,off=0,r=8)
+	 * so that range of bytes [r3, r3 + 8) is safe to access.
 	 */
+
 	for (i = 0; i < MAX_BPF_REG; i++)
 		if (regs[i].type == PTR_TO_PACKET && regs[i].id == dst_reg->id)
 			regs[i].range = dst_reg->off;
@@ -1668,8 +1689,8 @@ static void find_good_pkt_pointers(struct verifier_env *env,
 static int check_cond_jmp_op(struct verifier_env *env,
 			     struct bpf_insn *insn, int *insn_idx)
 {
-	struct reg_state *regs = env->cur_state.regs, *dst_reg;
-	struct verifier_state *other_branch;
+	struct verifier_state *other_branch, *this_branch = &env->cur_state;
+	struct reg_state *regs = this_branch->regs, *dst_reg;
 	u8 opcode = BPF_OP(insn->code);
 	int err;
 
@@ -1750,13 +1771,17 @@ static int check_cond_jmp_op(struct verifier_env *env,
 	} else if (BPF_SRC(insn->code) == BPF_X && opcode == BPF_JGT &&
 		   dst_reg->type == PTR_TO_PACKET &&
 		   regs[insn->src_reg].type == PTR_TO_PACKET_END) {
-		find_good_pkt_pointers(env, dst_reg);
+		find_good_pkt_pointers(this_branch, dst_reg);
+	} else if (BPF_SRC(insn->code) == BPF_X && opcode == BPF_JGE &&
+		   dst_reg->type == PTR_TO_PACKET_END &&
+		   regs[insn->src_reg].type == PTR_TO_PACKET) {
+		find_good_pkt_pointers(other_branch, &regs[insn->src_reg]);
 	} else if (is_pointer_value(env, insn->dst_reg)) {
 		verbose("R%d pointer comparison prohibited\n", insn->dst_reg);
 		return -EACCES;
 	}
 	if (log_level)
-		print_verifier_state(&env->cur_state);
+		print_verifier_state(this_branch);
 	return 0;
 }
 

```


---
## 1f415a74b0ca — bpf: fix method of PTR_TO_PACKET reg id generation

```diff
 kernel/bpf/verifier.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index f72f23b8fdab..7094c69ac199 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -194,6 +194,7 @@ struct verifier_env {
 	struct verifier_state_list **explored_states; /* search pruning optimization */
 	struct bpf_map *used_maps[MAX_USED_MAPS]; /* array of map's used by eBPF program */
 	u32 used_map_cnt;		/* number of used maps */
+	u32 id_gen;			/* used to generate unique reg IDs */
 	bool allow_ptr_leaks;
 };
 
@@ -1301,7 +1302,7 @@ static int check_packet_ptr_add(struct verifier_env *env, struct bpf_insn *insn)
 		/* dst_reg stays as pkt_ptr type and since some positive
 		 * integer value was added to the pointer, increment its 'id'
 		 */
-		dst_reg->id++;
+		dst_reg->id = ++env->id_gen;
 
 		/* something was added to pkt_ptr, set range and off to zero */
 		dst_reg->off = 0;

```


---
## 1b9b69ecb3a5 — bpf: teach verifier to recognize imm += ptr pattern

```diff
 kernel/bpf/verifier.c | 18 +++++++++++++++++-
 1 file changed, 17 insertions(+), 1 deletion(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index d54e34874579..668e07903c8f 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -1245,6 +1245,7 @@ static int check_packet_ptr_add(struct verifier_env *env, struct bpf_insn *insn)
 	struct reg_state *regs = env->cur_state.regs;
 	struct reg_state *dst_reg = &regs[insn->dst_reg];
 	struct reg_state *src_reg = &regs[insn->src_reg];
+	struct reg_state tmp_reg;
 	s32 imm;
 
 	if (BPF_SRC(insn->code) == BPF_K) {
@@ -1267,6 +1268,19 @@ static int check_packet_ptr_add(struct verifier_env *env, struct bpf_insn *insn)
 		 */
 		dst_reg->off += imm;
 	} else {
+		if (src_reg->type == PTR_TO_PACKET) {
+			/* R6=pkt(id=0,off=0,r=62) R7=imm22; r7 += r6 */
+			tmp_reg = *dst_reg;  /* save r7 state */
+			*dst_reg = *src_reg; /* copy pkt_ptr state r6 into r7 */
+			src_reg = &tmp_reg;  /* pretend it's src_reg state */
+			/* if the checks below reject it, the copy won't matter,
+			 * since we're rejecting the whole program. If all ok,
+			 * then imm22 state will be added to r7
+			 * and r7 will be pkt(id=0,off=22,r=62) while
+			 * r6 will stay as pkt(id=0,off=0,r=62)
+			 */
+		}
+
 		if (src_reg->type == CONST_IMM) {
 			/* pkt_ptr += reg where reg is known constant */
 			imm = src_reg->imm;
@@ -1565,7 +1579,9 @@ static int check_alu_op(struct verifier_env *env, struct bpf_insn *insn)
 			return 0;
 		} else if (opcode == BPF_ADD &&
 			   BPF_CLASS(insn->code) == BPF_ALU64 &&
-			   dst_reg->type == PTR_TO_PACKET) {
+			   (dst_reg->type == PTR_TO_PACKET ||
+			    (BPF_SRC(insn->code) == BPF_X &&
+			     regs[insn->src_reg].type == PTR_TO_PACKET))) {
 			/* ptr_to_packet += K|X */
 			return check_packet_ptr_add(env, insn);
 		} else if (BPF_CLASS(insn->code) == BPF_ALU64 &&

```


---
## d91b28ed42de — bpf: support decreasing order in direct packet access

```diff
 kernel/bpf/verifier.c | 12 ++++--------
 1 file changed, 4 insertions(+), 8 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index a08d66215245..d54e34874579 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -683,15 +683,11 @@ static int check_packet_access(struct verifier_env *env, u32 regno, int off,
 {
 	struct reg_state *regs = env->cur_state.regs;
 	struct reg_state *reg = &regs[regno];
-	int linear_size = (int) reg->range - (int) reg->off;
 
-	if (linear_size < 0 || linear_size >= MAX_PACKET_OFF) {
-		verbose("verifier bug\n");
-		return -EFAULT;
-	}
-	if (off < 0 || off + size > linear_size) {
-		verbose("invalid access to packet, off=%d size=%d, allowed=%d\n",
-			off, size, linear_size);
+	off += reg->off;
+	if (off < 0 || off + size > reg->range) {
+		verbose("invalid access to packet, off=%d size=%d, R%d(id=%d,off=%d,r=%d)\n",
+			off, size, regno, reg->id, reg->off, reg->range);
 		return -EACCES;
 	}
 	return 0;

```
