# RATER PACKET — 28 kernel fixes, one question each

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
## 00244bdaa423 — bpf: Fix sleepable check for tracing/lsm prog

```diff
 kernel/bpf/verifier.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 4db151e24355..d925197c2e5f 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -19022,6 +19022,9 @@ static int btf_id_allow_sleepable(u32 btf_id, unsigned long addr, const struct b
 	const struct btf_type *t;
 	const char *tname;
 
+	if (!btf_is_kernel(btf))
+		return -EINVAL;
+
 	switch (prog->type) {
 	case BPF_PROG_TYPE_TRACING:
 		t = btf_type_by_id(btf, btf_id);

```


---
## 00750788dfc6 — bpf: Fix indentation issue in epilogue_idx

```diff
 kernel/bpf/verifier.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 8bfb14d1eb7a..b806afeba212 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -19800,7 +19800,7 @@ static int convert_ctx_accesses(struct bpf_verifier_env *env)
 				 * least one ctx ptr saving insn before the
 				 * epilogue.
 				 */
-				 epilogue_idx = i + delta;
+				epilogue_idx = i + delta;
 			}
 			goto patch_insn_buf;
 		} else {

```


---
## 0108a4e9f358 — bpf: ensure main program has an extable

```diff
 kernel/bpf/verifier.c | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 0dd8adc7a159..cf5f230360f5 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -17217,9 +17217,10 @@ static int jit_subprogs(struct bpf_verifier_env *env)
 	}
 
 	/* finally lock prog and jit images for all functions and
-	 * populate kallsysm
+	 * populate kallsysm. Begin at the first subprogram, since
+	 * bpf_prog_load will add the kallsyms for the main program.
 	 */
-	for (i = 0; i < env->subprog_cnt; i++) {
+	for (i = 1; i < env->subprog_cnt; i++) {
 		bpf_prog_lock_ro(func[i]);
 		bpf_prog_kallsyms_add(func[i]);
 	}
@@ -17245,6 +17246,8 @@ static int jit_subprogs(struct bpf_verifier_env *env)
 	prog->jited = 1;
 	prog->bpf_func = func[0]->bpf_func;
 	prog->jited_len = func[0]->jited_len;
+	prog->aux->extable = func[0]->aux->extable;
+	prog->aux->num_exentries = func[0]->aux->num_exentries;
 	prog->aux->func = func;
 	prog->aux->func_cnt = env->subprog_cnt;
 	bpf_prog_jit_attempt_done(prog);

```


---
## 032547272eb0 — bpf: Avoid warning on unexpected map for tail call

```diff
 kernel/bpf/verifier.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 9f09dcd2eabb..29e0dddc22f8 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -11082,8 +11082,8 @@ record_func_key(struct bpf_verifier_env *env, struct bpf_call_arg_meta *meta,
 	if (func_id != BPF_FUNC_tail_call)
 		return 0;
 	if (!map || map->map_type != BPF_MAP_TYPE_PROG_ARRAY) {
-		verifier_bug(env, "expected array map for tail call");
-		return -EFAULT;
+		verbose(env, "expected prog array map for tail call");
+		return -EINVAL;
 	}
 
 	reg = &regs[BPF_REG_3];

```


---
## 05670f81d128 — bpf: fix compilation error without CGROUPS

```diff
 kernel/bpf/helpers.c   | 8 +++++---
 kernel/bpf/task_iter.c | 4 ++++
 kernel/bpf/verifier.c  | 8 ++++++++
 3 files changed, 17 insertions(+), 3 deletions(-)

diff --git a/kernel/bpf/helpers.c b/kernel/bpf/helpers.c
index e46ac288a108..95449ea7cc1b 100644
--- a/kernel/bpf/helpers.c
+++ b/kernel/bpf/helpers.c
@@ -2564,15 +2564,17 @@ BTF_ID_FLAGS(func, bpf_iter_num_destroy, KF_ITER_DESTROY)
 BTF_ID_FLAGS(func, bpf_iter_task_vma_new, KF_ITER_NEW | KF_RCU)
 BTF_ID_FLAGS(func, bpf_iter_task_vma_next, KF_ITER_NEXT | KF_RET_NULL)
 BTF_ID_FLAGS(func, bpf_iter_task_vma_destroy, KF_ITER_DESTROY)
+#ifdef CONFIG_CGROUPS
 BTF_ID_FLAGS(func, bpf_iter_css_task_new, KF_ITER_NEW | KF_TRUSTED_ARGS)
 BTF_ID_FLAGS(func, bpf_iter_css_task_next, KF_ITER_NEXT | KF_RET_NULL)
 BTF_ID_FLAGS(func, bpf_iter_css_task_destroy, KF_ITER_DESTROY)
-BTF_ID_FLAGS(func, bpf_iter_task_new, KF_ITER_NEW | KF_TRUSTED_ARGS | KF_RCU_PROTECTED)
-BTF_ID_FLAGS(func, bpf_iter_task_next, KF_ITER_NEXT | KF_RET_NULL)
-BTF_ID_FLAGS(func, bpf_iter_task_destroy, KF_ITER_DESTROY)
 BTF_ID_FLAGS(func, bpf_iter_css_new, KF_ITER_NEW | KF_TRUSTED_ARGS | KF_RCU_PROTECTED)
 BTF_ID_FLAGS(func, bpf_iter_css_next, KF_ITER_NEXT | KF_RET_NULL)
 BTF_ID_FLAGS(func, bpf_iter_css_destroy, KF_ITER_DESTROY)
+#endif
+BTF_ID_FLAGS(func, bpf_iter_task_new, KF_ITER_NEW | KF_TRUSTED_ARGS | KF_RCU_PROTECTED)
+BTF_ID_FLAGS(func, bpf_iter_task_next, KF_ITER_NEXT | KF_RET_NULL)
+BTF_ID_FLAGS(func, bpf_iter_task_destroy, KF_ITER_DESTROY)
 BTF_ID_FLAGS(func, bpf_dynptr_adjust)
 BTF_ID_FLAGS(func, bpf_dynptr_is_null)
 BTF_ID_FLAGS(func, bpf_dynptr_is_rdonly)
diff --git a/kernel/bpf/task_iter.c b/kernel/bpf/task_iter.c
index 654601dd6b49..8967d1ac7551 100644
--- a/kernel/bpf/task_iter.c
+++ b/kernel/bpf/task_iter.c
@@ -892,6 +892,8 @@ __bpf_kfunc void bpf_iter_task_vma_destroy(struct bpf_iter_task_vma *it)
 
 __diag_pop();
 
+#ifdef CONFIG_CGROUPS
+
 struct bpf_iter_css_task {
 	__u64 __opaque[1];
 } __attribute__((aligned(8)));
@@ -950,6 +952,8 @@ __bpf_kfunc void bpf_iter_css_task_destroy(struct bpf_iter_css_task *it)
 
 __diag_pop();
 
+#endif /* CONFIG_CGROUPS */
+
 struct bpf_iter_task {
 	__u64 __opaque[3];
 } __attribute__((aligned(8)));
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 857d76694517..8c91e0e54e27 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -5388,7 +5388,9 @@ static bool in_rcu_cs(struct bpf_verifier_env *env)
 /* Once GCC supports btf_type_tag the following mechanism will be replaced with tag check */
 BTF_SET_START(rcu_protected_types)
 BTF_ID(struct, prog_test_ref_kfunc)
+#ifdef CONFIG_CGROUPS
 BTF_ID(struct, cgroup)
+#endif
 BTF_ID(struct, bpf_cpumask)
 BTF_ID(struct, task_struct)
 BTF_SET_END(rcu_protected_types)
@@ -10835,7 +10837,9 @@ BTF_ID(func, bpf_dynptr_clone)
 BTF_ID(func, bpf_percpu_obj_new_impl)
 BTF_ID(func, bpf_percpu_obj_drop_impl)
 BTF_ID(func, bpf_throw)
+#ifdef CONFIG_CGROUPS
 BTF_ID(func, bpf_iter_css_task_new)
+#endif
 BTF_SET_END(special_kfunc_set)
 
 BTF_ID_LIST(special_kfunc_list)
@@ -10861,7 +10865,11 @@ BTF_ID(func, bpf_dynptr_clone)
 BTF_ID(func, bpf_percpu_obj_new_impl)
 BTF_ID(func, bpf_percpu_obj_drop_impl)
 BTF_ID(func, bpf_throw)
+#ifdef CONFIG_CGROUPS
 BTF_ID(func, bpf_iter_css_task_new)
+#else
+BTF_ID_UNUSED
+#endif
 
 static bool is_kfunc_ret_null(struct bpf_kfunc_call_arg_meta *meta)
 {

```


---
## 0613d8ca9ab3 — bpf: Fix mask generation for 32-bit narrow loads of 64-bit fields

```diff
 kernel/bpf/verifier.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index fbcf5a4e2fcd..5871aa78d01a 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -17033,7 +17033,7 @@ static int convert_ctx_accesses(struct bpf_verifier_env *env)
 					insn_buf[cnt++] = BPF_ALU64_IMM(BPF_RSH,
 									insn->dst_reg,
 									shift);
-				insn_buf[cnt++] = BPF_ALU64_IMM(BPF_AND, insn->dst_reg,
+				insn_buf[cnt++] = BPF_ALU32_IMM(BPF_AND, insn->dst_reg,
 								(1ULL << size * 8) - 1);
 			}
 		}

```


---
## 06d686f771dd — bpf: Fix kfunc callback register type handling

```diff
 kernel/bpf/verifier.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 5ccb50fd74e5..a7178ecf676d 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -11407,6 +11407,10 @@ static int check_kfunc_args(struct bpf_verifier_env *env, struct bpf_kfunc_call_
 			break;
 		}
 		case KF_ARG_PTR_TO_CALLBACK:
+			if (reg->type != PTR_TO_FUNC) {
+				verbose(env, "arg%d expected pointer to func\n", i);
+				return -EINVAL;
+			}
 			meta->subprogno = reg->subprogno;
 			break;
 		case KF_ARG_PTR_TO_REFCOUNTED_KPTR:

```


---
## 082cdc69a465 — bpf: Remove misleading spec_v1 check on var-offset stack read

```diff
 kernel/bpf/verifier.c | 16 ++++++----------
 1 file changed, 6 insertions(+), 10 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 15b5c5c729f9..d62b7127ff2a 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -4303,17 +4303,13 @@ static int check_stack_read(struct bpf_verifier_env *env,
 	}
 	/* Variable offset is prohibited for unprivileged mode for simplicity
 	 * since it requires corresponding support in Spectre masking for stack
-	 * ALU. See also retrieve_ptr_limit().
+	 * ALU. See also retrieve_ptr_limit(). The check in
+	 * check_stack_access_for_ptr_arithmetic() called by
+	 * adjust_ptr_min_max_vals() prevents users from creating stack pointers
+	 * with variable offsets, therefore no check is required here. Further,
+	 * just checking it here would be insufficient as speculative stack
+	 * writes could still lead to unsafe speculative behaviour.
 	 */
-	if (!env->bypass_spec_v1 && var_off) {
-		char tn_buf[48];
-
-		tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
-		verbose(env, "R%d variable offset stack access prohibited for !root, var_off=%s\n",
-				ptr_regno, tn_buf);
-		return -EACCES;
-	}
-
 	if (!var_off) {
 		off += reg->var_off.value;
 		err = check_stack_read_fixed_off(env, state, off, size,

```


---
## 09c447564fca — bpf: Keep fault protection when merging pointer types

```diff
 include/linux/bpf_verifier.h | 10 +++++++++
 kernel/bpf/verifier.c        | 49 +++++++++++++++++++++-----------------------
 2 files changed, 33 insertions(+), 26 deletions(-)

diff --git a/include/linux/bpf_verifier.h b/include/linux/bpf_verifier.h
index bc2af02547fe..ae0274a4bf35 100644
--- a/include/linux/bpf_verifier.h
+++ b/include/linux/bpf_verifier.h
@@ -1308,6 +1308,16 @@ static inline u32 type_flag(u32 type)
 	return type & ~BPF_BASE_TYPE_MASK;
 }
 
+static inline bool bpf_may_fault_on_deref(enum bpf_reg_type type)
+{
+	/*
+	 * The pointer types which must not be dereferenced without fault
+	 * protection, that is, the ones bpf_convert_ctx_accesses() has to
+	 * turn a BPF_LDX into a BPF_PROBE_MEM one for.
+	 */
+	return type == PTR_TO_BTF_ID || (type_flag(type) & PTR_UNTRUSTED);
+}
+
 static inline bool bpf_prog_has_arena_ctx_arg(const struct bpf_prog *prog)
 {
 	int i;
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 93463caf5c9a..9ec23a9c6592 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -5025,19 +5025,11 @@ static bool is_load_acq_unsafe(struct bpf_verifier_env *env, int regno,
 	 * A BPF_LOAD_ACQ is not rewritten to a BPF_PROBE_MEM load by the
 	 * verifier, unlike a regular BPF_LDX. The JIT would emit a plain load
 	 * with no exception table entry, so a fault (e.g. NULL deref) crashes
-	 * the kernel instead of being handled.
-	 *
-	 * Reject the source pointer types that a BPF_LDX would have had that
-	 * fault protection applied to, i.e. the ones bpf_convert_ctx_accesses()
-	 * turns into BPF_PROBE_MEM: a bare PTR_TO_BTF_ID and any PTR_UNTRUSTED
-	 * pointer (untrusted btf ids, untrusted MEM_ALLOC, rdonly untrusted
-	 * memory). A PTR_TRUSTED pointer is not among them, is not converted,
-	 * and stays allowed. Same for the other flagged PTR_TO_BTF_ID variants
-	 * (MEM_ALLOC, MEM_RCU, ...), hence the exact match on the base type.
+	 * the kernel instead of being handled. Reject the source pointer types
+	 * that would have needed that protection, the remaining ones stay
+	 * allowed.
 	 */
-	return insn->imm == BPF_LOAD_ACQ &&
-	       (reg->type == PTR_TO_BTF_ID ||
-		(type_flag(reg->type) & PTR_UNTRUSTED));
+	return insn->imm == BPF_LOAD_ACQ && bpf_may_fault_on_deref(reg->type);
 }
 
 /* Return false if @regno contains a pointer whose type isn't supported for
@@ -17862,11 +17854,24 @@ static bool is_ptr_to_mem(enum bpf_reg_type type)
 	return base_type(type) == PTR_TO_MEM;
 }
 
+static enum bpf_reg_type merge_ptr_types(enum bpf_reg_type type_a,
+					 enum bpf_reg_type type_b)
+{
+	bool to_mem = is_ptr_to_mem(type_a) || is_ptr_to_mem(type_b);
+	enum bpf_reg_type type_merged = to_mem ? PTR_TO_MEM : PTR_TO_BTF_ID;
+
+	if (bpf_may_fault_on_deref(type_a) || bpf_may_fault_on_deref(type_b))
+		type_merged |= to_mem ? MEM_RDONLY | PTR_UNTRUSTED :
+					PTR_UNTRUSTED;
+	else
+		type_merged |= ((type_a | type_b) & MEM_RDONLY);
+	return type_merged;
+}
+
 static int save_aux_ptr_type(struct bpf_verifier_env *env, enum bpf_reg_type type,
 			     bool allow_trust_mismatch)
 {
 	enum bpf_reg_type *prev_type = &env->insn_aux_data[env->insn_idx].ptr_type;
-	enum bpf_reg_type merged_type;
 
 	if (*prev_type == NOT_INIT) {
 		/* Saw a valid insn
@@ -17887,20 +17892,12 @@ static int save_aux_ptr_type(struct bpf_verifier_env *env, enum bpf_reg_type typ
 		    is_ptr_to_mem_or_btf_id(*prev_type)) {
 			/*
 			 * Have to support a use case when one path through
-			 * the program yields TRUSTED pointer while another
-			 * is UNTRUSTED. Fallback to UNTRUSTED to generate
-			 * BPF_PROBE_MEM/BPF_PROBE_MEMSX.
-			 * Same behavior of MEM_RDONLY flag.
+			 * the program yields a TRUSTED pointer while another
+			 * is UNTRUSTED. Merge them into a type which keeps
+			 * the BPF_PROBE_MEM/BPF_PROBE_MEMSX rewrite when
+			 * either side needs it.
 			 */
-			if (is_ptr_to_mem(type) || is_ptr_to_mem(*prev_type))
-				merged_type = PTR_TO_MEM;
-			else
-				merged_type = PTR_TO_BTF_ID;
-			if ((type & PTR_UNTRUSTED) || (*prev_type & PTR_UNTRUSTED))
-				merged_type |= PTR_UNTRUSTED;
-			if ((type & MEM_RDONLY) || (*prev_type & MEM_RDONLY))
-				merged_type |= MEM_RDONLY;
-			*prev_type = merged_type;
+			*prev_type = merge_ptr_types(type, *prev_type);
 		} else {
 			verbose(env, "same insn cannot be used with different pointers\n");
 			return -EINVAL;

```


---
## 0acd03a5bd18 — bpf: enforce precision of R0 on callback return

```diff
 kernel/bpf/verifier.c | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 25b9d470957e..849fbf47b5f3 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -9590,6 +9590,13 @@ static int prepare_func_exit(struct bpf_verifier_env *env, int *insn_idx)
 			verbose(env, "R0 not a scalar value\n");
 			return -EACCES;
 		}
+
+		/* we are going to rely on register's precise value */
+		err = mark_reg_read(env, r0, r0->parent, REG_LIVE_READ64);
+		err = err ?: mark_chain_precision(env, BPF_REG_0);
+		if (err)
+			return err;
+
 		if (!tnum_in(range, r0->var_off)) {
 			verbose_invalid_scalar(env, r0, &range, "callback return", "R0");
 			return -EINVAL;

```


---
## 0db63c0b86e9 — bpf: Fix verifier assumptions about socket->sk

```diff
 kernel/bpf/verifier.c | 23 ++++++++++++++++++-----
 1 file changed, 18 insertions(+), 5 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 87ff414899cf..5d42db05315e 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -2368,6 +2368,8 @@ static void mark_btf_ld_reg(struct bpf_verifier_env *env,
 	regs[regno].type = PTR_TO_BTF_ID | flag;
 	regs[regno].btf = btf;
 	regs[regno].btf_id = btf_id;
+	if (type_may_be_null(flag))
+		regs[regno].id = ++env->id_gen;
 }
 
 #define DEF_NOT_SUBREG	(0)
@@ -5400,8 +5402,6 @@ static int check_map_kptr_access(struct bpf_verifier_env *env, u32 regno,
 		 */
 		mark_btf_ld_reg(env, cur_regs(env), value_regno, PTR_TO_BTF_ID, kptr_field->kptr.btf,
 				kptr_field->kptr.btf_id, btf_ld_kptr_type(env, kptr_field));
-		/* For mark_ptr_or_null_reg */
-		val_reg->id = ++env->id_gen;
 	} else if (class == BPF_STX) {
 		val_reg = reg_state(env, value_regno);
 		if (!register_is_null(val_reg) &&
@@ -5719,7 +5719,8 @@ static bool is_trusted_reg(const struct bpf_reg_state *reg)
 		return true;
 
 	/* Types listed in the reg2btf_ids are always trusted */
-	if (reg2btf_ids[base_type(reg->type)])
+	if (reg2btf_ids[base_type(reg->type)] &&
+	    !bpf_type_has_unsafe_modifiers(reg->type))
 		return true;
 
 	/* If a register is not referenced, it is trusted if it has the
@@ -6339,6 +6340,7 @@ static int bpf_map_direct_read(struct bpf_map *map, int off, int size, u64 *val,
 #define BTF_TYPE_SAFE_RCU(__type)  __PASTE(__type, __safe_rcu)
 #define BTF_TYPE_SAFE_RCU_OR_NULL(__type)  __PASTE(__type, __safe_rcu_or_null)
 #define BTF_TYPE_SAFE_TRUSTED(__type)  __PASTE(__type, __safe_trusted)
+#define BTF_TYPE_SAFE_TRUSTED_OR_NULL(__type)  __PASTE(__type, __safe_trusted_or_null)
 
 /*
  * Allow list few fields as RCU trusted or full trusted.
@@ -6402,7 +6404,7 @@ BTF_TYPE_SAFE_TRUSTED(struct dentry) {
 	struct inode *d_inode;
 };
 
-BTF_TYPE_SAFE_TRUSTED(struct socket) {
+BTF_TYPE_SAFE_TRUSTED_OR_NULL(struct socket) {
 	struct sock *sk;
 };
 
@@ -6437,11 +6439,20 @@ static bool type_is_trusted(struct bpf_verifier_env *env,
 	BTF_TYPE_EMIT(BTF_TYPE_SAFE_TRUSTED(struct linux_binprm));
 	BTF_TYPE_EMIT(BTF_TYPE_SAFE_TRUSTED(struct file));
 	BTF_TYPE_EMIT(BTF_TYPE_SAFE_TRUSTED(struct dentry));
-	BTF_TYPE_EMIT(BTF_TYPE_SAFE_TRUSTED(struct socket));
 
 	return btf_nested_type_is_trusted(&env->log, reg, field_name, btf_id, "__safe_trusted");
 }
 
+static bool type_is_trusted_or_null(struct bpf_verifier_env *env,
+				    struct bpf_reg_state *reg,
+				    const char *field_name, u32 btf_id)
+{
+	BTF_TYPE_EMIT(BTF_TYPE_SAFE_TRUSTED_OR_NULL(struct socket));
+
+	return btf_nested_type_is_trusted(&env->log, reg, field_name, btf_id,
+					  "__safe_trusted_or_null");
+}
+
 static int check_ptr_to_btf_access(struct bpf_verifier_env *env,
 				   struct bpf_reg_state *regs,
 				   int regno, int off, int size,
@@ -6550,6 +6561,8 @@ static int check_ptr_to_btf_access(struct bpf_verifier_env *env,
 		 */
 		if (type_is_trusted(env, reg, field_name, btf_id)) {
 			flag |= PTR_TRUSTED;
+		} else if (type_is_trusted_or_null(env, reg, field_name, btf_id)) {
+			flag |= PTR_TRUSTED | PTR_MAYBE_NULL;
 		} else if (in_rcu_cs(env) && !type_may_be_null(reg->type)) {
 			if (type_is_rcu(env, reg, field_name, btf_id)) {
 				/* ignore __rcu tag and mark it MEM_RCU */

```


---
## 10e14e9652bf — bpf: fix control-flow graph checking in privileged mode

```diff
 kernel/bpf/verifier.c | 23 ++++++++---------------
 1 file changed, 8 insertions(+), 15 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 484c742f733e..a2267d5ed14e 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -15403,8 +15403,7 @@ enum {
  * w - next instruction
  * e - edge
  */
-static int push_insn(int t, int w, int e, struct bpf_verifier_env *env,
-		     bool loop_ok)
+static int push_insn(int t, int w, int e, struct bpf_verifier_env *env)
 {
 	int *insn_stack = env->cfg.insn_stack;
 	int *insn_state = env->cfg.insn_state;
@@ -15436,7 +15435,7 @@ static int push_insn(int t, int w, int e, struct bpf_verifier_env *env,
 		insn_stack[env->cfg.cur_stack++] = w;
 		return KEEP_EXPLORING;
 	} else if ((insn_state[w] & 0xF0) == DISCOVERED) {
-		if (loop_ok && env->bpf_capable)
+		if (env->bpf_capable)
 			return DONE_EXPLORING;
 		verbose_linfo(env, t, "%d: ", t);
 		verbose_linfo(env, w, "%d: ", w);
@@ -15459,7 +15458,7 @@ static int visit_func_call_insn(int t, struct bpf_insn *insns,
 	int ret, insn_sz;
 
 	insn_sz = bpf_is_ldimm64(&insns[t]) ? 2 : 1;
-	ret = push_insn(t, t + insn_sz, FALLTHROUGH, env, false);
+	ret = push_insn(t, t + insn_sz, FALLTHROUGH, env);
 	if (ret)
 		return ret;
 
@@ -15469,12 +15468,7 @@ static int visit_func_call_insn(int t, struct bpf_insn *insns,
 
 	if (visit_callee) {
 		mark_prune_point(env, t);
-		ret = push_insn(t, t + insns[t].imm + 1, BRANCH, env,
-				/* It's ok to allow recursion from CFG point of
-				 * view. __check_func_call() will do the actual
-				 * check.
-				 */
-				bpf_pseudo_func(insns + t));
+		ret = push_insn(t, t + insns[t].imm + 1, BRANCH, env);
 	}
 	return ret;
 }
@@ -15496,7 +15490,7 @@ static int visit_insn(int t, struct bpf_verifier_env *env)
 	if (BPF_CLASS(insn->code) != BPF_JMP &&
 	    BPF_CLASS(insn->code) != BPF_JMP32) {
 		insn_sz = bpf_is_ldimm64(insn) ? 2 : 1;
-		return push_insn(t, t + insn_sz, FALLTHROUGH, env, false);
+		return push_insn(t, t + insn_sz, FALLTHROUGH, env);
 	}
 
 	switch (BPF_OP(insn->code)) {
@@ -15543,8 +15537,7 @@ static int visit_insn(int t, struct bpf_verifier_env *env)
 			off = insn->imm;
 
 		/* unconditional jump with single edge */
-		ret = push_insn(t, t + off + 1, FALLTHROUGH, env,
-				true);
+		ret = push_insn(t, t + off + 1, FALLTHROUGH, env);
 		if (ret)
 			return ret;
 
@@ -15557,11 +15550,11 @@ static int visit_insn(int t, struct bpf_verifier_env *env)
 		/* conditional jump with two edges */
 		mark_prune_point(env, t);
 
-		ret = push_insn(t, t + 1, FALLTHROUGH, env, true);
+		ret = push_insn(t, t + 1, FALLTHROUGH, env);
 		if (ret)
 			return ret;
 
-		return push_insn(t, t + insn->off + 1, BRANCH, env, true);
+		return push_insn(t, t + insn->off + 1, BRANCH, env);
 	}
 }
 

```


---
## 122fdbd2a030 — bpf: verifier: reject addr_space_cast insn without arena

```diff
 kernel/bpf/verifier.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 2cd7e0e79283..0bfc0050db28 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -14022,6 +14022,10 @@ static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
 					verbose(env, "addr_space_cast insn can only convert between address space 1 and 0\n");
 					return -EINVAL;
 				}
+				if (!env->prog->aux->arena) {
+					verbose(env, "addr_space_cast insn can only be used in a program that has an associated arena\n");
+					return -EINVAL;
+				}
 			} else {
 				if ((insn->off != 0 && insn->off != 8 && insn->off != 16 &&
 				     insn->off != 32) || insn->imm) {

```


---
## 12659d28615d — bpf: Ensure reg is PTR_TO_STACK in process_iter_arg

```diff
 kernel/bpf/verifier.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 1c4ebb326785..358a3566bb60 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -8189,6 +8189,11 @@ static int process_iter_arg(struct bpf_verifier_env *env, int regno, int insn_id
 	const struct btf_type *t;
 	int spi, err, i, nr_slots, btf_id;
 
+	if (reg->type != PTR_TO_STACK) {
+		verbose(env, "arg#%d expected pointer to an iterator on stack\n", regno - 1);
+		return -EINVAL;
+	}
+
 	/* For iter_{new,next,destroy} functions, btf_check_iter_kfuncs()
 	 * ensures struct convention, so we wouldn't need to do any BTF
 	 * validation here. But given iter state can be passed as a parameter

```


---
## 17c4b65a2493 — bpf: Allow return values 0 and 1 for kprobe session

```diff
 kernel/bpf/verifier.c | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 7958d6ff6b73..7d8ed377b35d 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -16024,6 +16024,15 @@ static int check_return_code(struct bpf_verifier_env *env, int regno, const char
 			return -ENOTSUPP;
 		}
 		break;
+	case BPF_PROG_TYPE_KPROBE:
+		switch (env->prog->expected_attach_type) {
+		case BPF_TRACE_KPROBE_SESSION:
+			range = retval_range(0, 1);
+			break;
+		default:
+			return 0;
+		}
+		break;
 	case BPF_PROG_TYPE_SK_LOOKUP:
 		range = retval_range(SK_DROP, SK_PASS);
 		break;

```


---
## 180c7000712d — bpf: Invalidate RCU pointers after final spin unlock

```diff
 kernel/bpf/verifier.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index b274004fccfd..7439afdc851a 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -206,6 +206,7 @@ static int acquire_reference(struct bpf_verifier_env *env, int insn_idx, int par
 static int release_reference_nomark(struct bpf_verifier_state *state, int id);
 static int release_reference(struct bpf_verifier_env *env, int id);
 static void invalidate_non_owning_refs(struct bpf_verifier_env *env);
+static void invalidate_rcu_protected_refs(struct bpf_verifier_env *env);
 static bool in_rbtree_lock_required_cb(struct bpf_verifier_env *env);
 static bool is_tracing_prog_type(enum bpf_prog_type type);
 static int ref_set_non_owning(struct bpf_verifier_env *env,
@@ -7165,6 +7166,7 @@ static int process_spin_lock(struct bpf_verifier_env *env, struct bpf_reg_state
 			return err;
 		}
 	} else {
+		bool was_in_rcu_cs;
 		void *ptr;
 		int type;
 
@@ -7192,10 +7194,13 @@ static int process_spin_lock(struct bpf_verifier_env *env, struct bpf_reg_state
 			verbose(env, "%s_unlock cannot be out of order\n", lock_str);
 			return -EINVAL;
 		}
+		was_in_rcu_cs = in_rcu_cs(env);
 		if (release_lock_state(cur, type, reg->id, ptr)) {
 			verbose(env, "%s_unlock of different lock\n", lock_str);
 			return -EINVAL;
 		}
+		if (was_in_rcu_cs && !in_rcu_cs(env))
+			invalidate_rcu_protected_refs(env);
 
 		invalidate_non_owning_refs(env);
 	}

```


---
## 18752d73c189 — bpf: Improve check_raw_mode_ok test for MEM_UNINIT-tagged types

```diff
 kernel/bpf/verifier.c | 16 +++++++++++-----
 1 file changed, 11 insertions(+), 5 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 7d62fd576089..7df5c29293a4 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -8291,6 +8291,12 @@ static bool arg_type_is_mem_size(enum bpf_arg_type type)
 	       type == ARG_CONST_SIZE_OR_ZERO;
 }
 
+static bool arg_type_is_raw_mem(enum bpf_arg_type type)
+{
+	return base_type(type) == ARG_PTR_TO_MEM &&
+	       type & MEM_UNINIT;
+}
+
 static bool arg_type_is_release(enum bpf_arg_type type)
 {
 	return type & OBJ_RELEASE;
@@ -9340,15 +9346,15 @@ static bool check_raw_mode_ok(const struct bpf_func_proto *fn)
 {
 	int count = 0;
 
-	if (fn->arg1_type == ARG_PTR_TO_UNINIT_MEM)
+	if (arg_type_is_raw_mem(fn->arg1_type))
 		count++;
-	if (fn->arg2_type == ARG_PTR_TO_UNINIT_MEM)
+	if (arg_type_is_raw_mem(fn->arg2_type))
 		count++;
-	if (fn->arg3_type == ARG_PTR_TO_UNINIT_MEM)
+	if (arg_type_is_raw_mem(fn->arg3_type))
 		count++;
-	if (fn->arg4_type == ARG_PTR_TO_UNINIT_MEM)
+	if (arg_type_is_raw_mem(fn->arg4_type))
 		count++;
-	if (fn->arg5_type == ARG_PTR_TO_UNINIT_MEM)
+	if (arg_type_is_raw_mem(fn->arg5_type))
 		count++;
 
 	/* We only support one arg being in raw mode at the moment,

```


---
## 18cdd90aba79 — x86/bpf: Fix BPF percpu accesses

```diff
 kernel/bpf/verifier.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 9971c03adfd5..f74263b206e4 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -21692,7 +21692,7 @@ static int do_misc_fixups(struct bpf_verifier_env *env)
 			 * way, it's fine to back out this inlining logic
 			 */
 #ifdef CONFIG_SMP
-			insn_buf[0] = BPF_MOV32_IMM(BPF_REG_0, (u32)(unsigned long)&pcpu_hot.cpu_number);
+			insn_buf[0] = BPF_MOV64_IMM(BPF_REG_0, (u32)(unsigned long)&pcpu_hot.cpu_number);
 			insn_buf[1] = BPF_MOV64_PERCPU_REG(BPF_REG_0, BPF_REG_0);
 			insn_buf[2] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0, 0);
 			cnt = 3;

```


---
## 1ae497c78f01 — bpf: use type_may_be_null() helper for nullable-param check

```diff
 include/linux/bpf_verifier.h | 5 +++++
 kernel/bpf/verifier.c        | 5 -----
 2 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/include/linux/bpf_verifier.h b/include/linux/bpf_verifier.h
index 8458632824a4..4513372c5bc8 100644
--- a/include/linux/bpf_verifier.h
+++ b/include/linux/bpf_verifier.h
@@ -927,6 +927,11 @@ static inline bool type_is_sk_pointer(enum bpf_reg_type type)
 		type == PTR_TO_XDP_SOCK;
 }
 
+static inline bool type_may_be_null(u32 type)
+{
+	return type & PTR_MAYBE_NULL;
+}
+
 static inline void mark_reg_scratched(struct bpf_verifier_env *env, u32 regno)
 {
 	env->scratched_regs |= 1U << regno;
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index b806afeba212..53d0556fbbf3 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -383,11 +383,6 @@ static void verbose_invalid_scalar(struct bpf_verifier_env *env,
 	verbose(env, " should have been in [%d, %d]\n", range.minval, range.maxval);
 }
 
-static bool type_may_be_null(u32 type)
-{
-	return type & PTR_MAYBE_NULL;
-}
-
 static bool reg_not_null(const struct bpf_reg_state *reg)
 {
 	enum bpf_reg_type type;

```


---
## 1b30d4441727 — bpf: Fix memory leak of bpf_scc_info objects

```diff
 kernel/bpf/verifier.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 0806295945e4..c4f69a9e9af6 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -23114,6 +23114,8 @@ static void free_states(struct bpf_verifier_env *env)
 
 	for (i = 0; i < env->scc_cnt; ++i) {
 		info = env->scc_info[i];
+		if (!info)
+			continue;
 		for (j = 0; j < info->num_visits; j++)
 			free_backedges(&info->visits[j]);
 		kvfree(info);
@@ -24554,6 +24556,7 @@ static int compute_scc(struct bpf_verifier_env *env)
 		err = -ENOMEM;
 		goto exit;
 	}
+	env->scc_cnt = next_scc_id;
 exit:
 	kvfree(stack);
 	kvfree(pre);

```


---
## 1ffc85d9298e — bpf: Verify scalar ids mapping in regsafe() using check_ids()

```diff
 include/linux/bpf_verifier.h | 17 ++++++---
 kernel/bpf/verifier.c        | 91 +++++++++++++++++++++++++++++++++-----------
 2 files changed, 79 insertions(+), 29 deletions(-)

diff --git a/include/linux/bpf_verifier.h b/include/linux/bpf_verifier.h
index 22fb13c738a9..f70f9ac884d2 100644
--- a/include/linux/bpf_verifier.h
+++ b/include/linux/bpf_verifier.h
@@ -313,11 +313,6 @@ struct bpf_idx_pair {
 	u32 idx;
 };
 
-struct bpf_id_pair {
-	u32 old;
-	u32 cur;
-};
-
 #define MAX_CALL_FRAMES 8
 /* Maximum number of register states that can exist at once */
 #define BPF_ID_MAP_SIZE ((MAX_BPF_REG + MAX_BPF_STACK / BPF_REG_SIZE) * MAX_CALL_FRAMES)
@@ -557,6 +552,16 @@ struct backtrack_state {
 	u64 stack_masks[MAX_CALL_FRAMES];
 };
 
+struct bpf_id_pair {
+	u32 old;
+	u32 cur;
+};
+
+struct bpf_idmap {
+	u32 tmp_id_gen;
+	struct bpf_id_pair map[BPF_ID_MAP_SIZE];
+};
+
 struct bpf_idset {
 	u32 count;
 	u32 ids[BPF_ID_MAP_SIZE];
@@ -594,7 +599,7 @@ struct bpf_verifier_env {
 	struct bpf_verifier_log log;
 	struct bpf_subprog_info subprog_info[BPF_MAX_SUBPROGS + 1];
 	union {
-		struct bpf_id_pair idmap_scratch[BPF_ID_MAP_SIZE];
+		struct bpf_idmap idmap_scratch;
 		struct bpf_idset idset_scratch;
 	};
 	struct {
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 064aef5cd186..fa43dc8e85b9 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -12934,12 +12934,14 @@ static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
 		if (BPF_SRC(insn->code) == BPF_X) {
 			struct bpf_reg_state *src_reg = regs + insn->src_reg;
 			struct bpf_reg_state *dst_reg = regs + insn->dst_reg;
+			bool need_id = src_reg->type == SCALAR_VALUE && !src_reg->id &&
+				       !tnum_is_const(src_reg->var_off);
 
 			if (BPF_CLASS(insn->code) == BPF_ALU64) {
 				/* case: R1 = R2
 				 * copy register state to dest reg
 				 */
-				if (src_reg->type == SCALAR_VALUE && !src_reg->id)
+				if (need_id)
 					/* Assign src and dst registers the same ID
 					 * that will be used by find_equal_scalars()
 					 * to propagate min/max range.
@@ -12958,7 +12960,7 @@ static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
 				} else if (src_reg->type == SCALAR_VALUE) {
 					bool is_src_reg_u32 = src_reg->umax_value <= U32_MAX;
 
-					if (is_src_reg_u32 && !src_reg->id)
+					if (is_src_reg_u32 && need_id)
 						src_reg->id = ++env->id_gen;
 					copy_register_state(dst_reg, src_reg);
 					/* Make sure ID is cleared if src_reg is not in u32 range otherwise
@@ -15114,8 +15116,9 @@ static bool range_within(struct bpf_reg_state *old,
  * So we look through our idmap to see if this old id has been seen before.  If
  * so, we require the new id to match; otherwise, we add the id pair to the map.
  */
-static bool check_ids(u32 old_id, u32 cur_id, struct bpf_id_pair *idmap)
+static bool check_ids(u32 old_id, u32 cur_id, struct bpf_idmap *idmap)
 {
+	struct bpf_id_pair *map = idmap->map;
 	unsigned int i;
 
 	/* either both IDs should be set or both should be zero */
@@ -15126,20 +15129,34 @@ static bool check_ids(u32 old_id, u32 cur_id, struct bpf_id_pair *idmap)
 		return true;
 
 	for (i = 0; i < BPF_ID_MAP_SIZE; i++) {
-		if (!idmap[i].old) {
+		if (!map[i].old) {
 			/* Reached an empty slot; haven't seen this id before */
-			idmap[i].old = old_id;
-			idmap[i].cur = cur_id;
+			map[i].old = old_id;
+			map[i].cur = cur_id;
 			return true;
 		}
-		if (idmap[i].old == old_id)
-			return idmap[i].cur == cur_id;
+		if (map[i].old == old_id)
+			return map[i].cur == cur_id;
+		if (map[i].cur == cur_id)
+			return false;
 	}
 	/* We ran out of idmap slots, which should be impossible */
 	WARN_ON_ONCE(1);
 	return false;
 }
 
+/* Similar to check_ids(), but allocate a unique temporary ID
+ * for 'old_id' or 'cur_id' of zero.
+ * This makes pairs like '0 vs unique ID', 'unique ID vs 0' valid.
+ */
+static bool check_scalar_ids(u32 old_id, u32 cur_id, struct bpf_idmap *idmap)
+{
+	old_id = old_id ? old_id : ++idmap->tmp_id_gen;
+	cur_id = cur_id ? cur_id : ++idmap->tmp_id_gen;
+
+	return check_ids(old_id, cur_id, idmap);
+}
+
 static void clean_func_state(struct bpf_verifier_env *env,
 			     struct bpf_func_state *st)
 {
@@ -15238,7 +15255,7 @@ static void clean_live_states(struct bpf_verifier_env *env, int insn,
 
 static bool regs_exact(const struct bpf_reg_state *rold,
 		       const struct bpf_reg_state *rcur,
-		       struct bpf_id_pair *idmap)
+		       struct bpf_idmap *idmap)
 {
 	return memcmp(rold, rcur, offsetof(struct bpf_reg_state, id)) == 0 &&
 	       check_ids(rold->id, rcur->id, idmap) &&
@@ -15247,7 +15264,7 @@ static bool regs_exact(const struct bpf_reg_state *rold,
 
 /* Returns true if (rold safe implies rcur safe) */
 static bool regsafe(struct bpf_verifier_env *env, struct bpf_reg_state *rold,
-		    struct bpf_reg_state *rcur, struct bpf_id_pair *idmap)
+		    struct bpf_reg_state *rcur, struct bpf_idmap *idmap)
 {
 	if (!(rold->live & REG_LIVE_READ))
 		/* explored state didn't use this */
@@ -15284,15 +15301,42 @@ static bool regsafe(struct bpf_verifier_env *env, struct bpf_reg_state *rold,
 
 	switch (base_type(rold->type)) {
 	case SCALAR_VALUE:
-		if (regs_exact(rold, rcur, idmap))
-			return true;
-		if (env->explore_alu_limits)
-			return false;
+		if (env->explore_alu_limits) {
+			/* explore_alu_limits disables tnum_in() and range_within()
+			 * logic and requires everything to be strict
+			 */
+			return memcmp(rold, rcur, offsetof(struct bpf_reg_state, id)) == 0 &&
+			       check_scalar_ids(rold->id, rcur->id, idmap);
+		}
 		if (!rold->precise)
 			return true;
-		/* new val must satisfy old val knowledge */
+		/* Why check_ids() for scalar registers?
+		 *
+		 * Consider the following BPF code:
+		 *   1: r6 = ... unbound scalar, ID=a ...
+		 *   2: r7 = ... unbound scalar, ID=b ...
+		 *   3: if (r6 > r7) goto +1
+		 *   4: r6 = r7
+		 *   5: if (r6 > X) goto ...
+		 *   6: ... memory operation using r7 ...
+		 *
+		 * First verification path is [1-6]:
+		 * - at (4) same bpf_reg_state::id (b) would be assigned to r6 and r7;
+		 * - at (5) r6 would be marked <= X, find_equal_scalars() would also mark
+		 *   r7 <= X, because r6 and r7 share same id.
+		 * Next verification path is [1-4, 6].
+		 *
+		 * Instruction (6) would be reached in two states:
+		 *   I.  r6{.id=b}, r7{.id=b} via path 1-6;
+		 *   II. r6{.id=a}, r7{.id=b} via path 1-4, 6.
+		 *
+		 * Use check_ids() to distinguish these states.
+		 * ---
+		 * Also verify that new value satisfies old value range knowledge.
+		 */
 		return range_within(rold, rcur) &&
-		       tnum_in(rold->var_off, rcur->var_off);
+		       tnum_in(rold->var_off, rcur->var_off) &&
+		       check_scalar_ids(rold->id, rcur->id, idmap);
 	case PTR_TO_MAP_KEY:
 	case PTR_TO_MAP_VALUE:
 	case PTR_TO_MEM:
@@ -15338,7 +15382,7 @@ static bool regsafe(struct bpf_verifier_env *env, struct bpf_reg_state *rold,
 }
 
 static bool stacksafe(struct bpf_verifier_env *env, struct bpf_func_state *old,
-		      struct bpf_func_state *cur, struct bpf_id_pair *idmap)
+		      struct bpf_func_state *cur, struct bpf_idmap *idmap)
 {
 	int i, spi;
 
@@ -15441,7 +15485,7 @@ static bool stacksafe(struct bpf_verifier_env *env, struct bpf_func_state *old,
 }
 
 static bool refsafe(struct bpf_func_state *old, struct bpf_func_state *cur,
-		    struct bpf_id_pair *idmap)
+		    struct bpf_idmap *idmap)
 {
 	int i;
 
@@ -15489,13 +15533,13 @@ static bool func_states_equal(struct bpf_verifier_env *env, struct bpf_func_stat
 
 	for (i = 0; i < MAX_BPF_REG; i++)
 		if (!regsafe(env, &old->regs[i], &cur->regs[i],
-			     env->idmap_scratch))
+			     &env->idmap_scratch))
 			return false;
 
-	if (!stacksafe(env, old, cur, env->idmap_scratch))
+	if (!stacksafe(env, old, cur, &env->idmap_scratch))
 		return false;
 
-	if (!refsafe(old, cur, env->idmap_scratch))
+	if (!refsafe(old, cur, &env->idmap_scratch))
 		return false;
 
 	return true;
@@ -15510,7 +15554,8 @@ static bool states_equal(struct bpf_verifier_env *env,
 	if (old->curframe != cur->curframe)
 		return false;
 
-	memset(env->idmap_scratch, 0, sizeof(env->idmap_scratch));
+	env->idmap_scratch.tmp_id_gen = env->id_gen;
+	memset(&env->idmap_scratch.map, 0, sizeof(env->idmap_scratch.map));
 
 	/* Verification state from speculative execution simulation
 	 * must never prune a non-speculative execution one.
@@ -15528,7 +15573,7 @@ static bool states_equal(struct bpf_verifier_env *env,
 		return false;
 
 	if (old->active_lock.id &&
-	    !check_ids(old->active_lock.id, cur->active_lock.id, env->idmap_scratch))
+	    !check_ids(old->active_lock.id, cur->active_lock.id, &env->idmap_scratch))
 		return false;
 
 	if (old->active_rcu_lock != cur->active_rcu_lock)

```


---
## 2658a1720a19 — bpf: collect only live registers in linked regs

```diff
 kernel/bpf/verifier.c | 13 ++++++++++---
 1 file changed, 10 insertions(+), 3 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index f960b382fdb3..836ceb128d19 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -17359,17 +17359,24 @@ static void __collect_linked_regs(struct linked_regs *reg_set, struct bpf_reg_st
  * in verifier state, save R in linked_regs if R->id == id.
  * If there are too many Rs sharing same id, reset id for leftover Rs.
  */
-static void collect_linked_regs(struct bpf_verifier_state *vstate, u32 id,
+static void collect_linked_regs(struct bpf_verifier_env *env,
+				struct bpf_verifier_state *vstate,
+				u32 id,
 				struct linked_regs *linked_regs)
 {
+	struct bpf_insn_aux_data *aux = env->insn_aux_data;
 	struct bpf_func_state *func;
 	struct bpf_reg_state *reg;
+	u16 live_regs;
 	int i, j;
 
 	id = id & ~BPF_ADD_CONST;
 	for (i = vstate->curframe; i >= 0; i--) {
+		live_regs = aux[frame_insn_idx(vstate, i)].live_regs_before;
 		func = vstate->frame[i];
 		for (j = 0; j < BPF_REG_FP; j++) {
+			if (!(live_regs & BIT(j)))
+				continue;
 			reg = &func->regs[j];
 			__collect_linked_regs(linked_regs, reg, id, i, j, true);
 		}
@@ -17584,9 +17591,9 @@ static int check_cond_jmp_op(struct bpf_verifier_env *env,
 	 * if parent state is created.
 	 */
 	if (BPF_SRC(insn->code) == BPF_X && src_reg->type == SCALAR_VALUE && src_reg->id)
-		collect_linked_regs(this_branch, src_reg->id, &linked_regs);
+		collect_linked_regs(env, this_branch, src_reg->id, &linked_regs);
 	if (dst_reg->type == SCALAR_VALUE && dst_reg->id)
-		collect_linked_regs(this_branch, dst_reg->id, &linked_regs);
+		collect_linked_regs(env, this_branch, dst_reg->id, &linked_regs);
 	if (linked_regs.cnt > 1) {
 		err = push_jmp_history(env, this_branch, 0, linked_regs_pack(&linked_regs));
 		if (err)

```


---
## 2b2efe1937ca — bpf: Fix may_goto with negative offset.

```diff
 kernel/bpf/verifier.c | 9 ++++++---
 1 file changed, 6 insertions(+), 3 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 5586a571bf55..214a9fa8c6fb 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -17460,11 +17460,11 @@ static int is_state_visited(struct bpf_verifier_env *env, int insn_idx)
 				goto skip_inf_loop_check;
 			}
 			if (is_may_goto_insn_at(env, insn_idx)) {
-				if (states_equal(env, &sl->state, cur, RANGE_WITHIN)) {
+				if (sl->state.may_goto_depth != cur->may_goto_depth &&
+				    states_equal(env, &sl->state, cur, RANGE_WITHIN)) {
 					update_loop_entry(cur, &sl->state);
 					goto hit;
 				}
-				goto skip_inf_loop_check;
 			}
 			if (calls_callback(env, insn_idx)) {
 				if (states_equal(env, &sl->state, cur, RANGE_WITHIN))
@@ -20049,7 +20049,10 @@ static int do_misc_fixups(struct bpf_verifier_env *env)
 
 			stack_depth_extra = 8;
 			insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_10, stack_off);
-			insn_buf[1] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_AX, 0, insn->off + 2);
+			if (insn->off >= 0)
+				insn_buf[1] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_AX, 0, insn->off + 2);
+			else
+				insn_buf[1] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_AX, 0, insn->off - 1);
 			insn_buf[2] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_AX, 1);
 			insn_buf[3] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_AX, stack_off);
 			cnt = 4;

```


---
## 3a354149bcea — bpf: Preserve pointer spill metadata during half-slot cleanup

```diff
 kernel/bpf/states.c | 13 +++++++------
 1 file changed, 7 insertions(+), 6 deletions(-)

diff --git a/kernel/bpf/states.c b/kernel/bpf/states.c
index 32f346ce3ffc..ea2153cf28d0 100644
--- a/kernel/bpf/states.c
+++ b/kernel/bpf/states.c
@@ -436,12 +436,10 @@ static void __clean_func_state(struct bpf_verifier_env *env,
 				continue;
 
 			/*
-			 * Only destroy spilled_ptr when hi half is dead.
-			 * If hi half is still live with STACK_SPILL, the
-			 * spilled_ptr metadata is needed for correct state
-			 * comparison in stacksafe().
-			 * is_spilled_reg() is using slot_type[7], but
-			 * is_spilled_scalar_after() check either slot_type[0] or [4]
+			 * Only scalar spills can be degraded to raw stack bytes
+			 * when their high half is dead. Pointer spills need the
+			 * saved spilled_ptr metadata so partial fills keep
+			 * rejecting as non-scalar register fills.
 			 */
 			if (!hi_live) {
 				struct bpf_reg_state *spill = &st->stack[i].spilled_ptr;
@@ -449,6 +447,9 @@ static void __clean_func_state(struct bpf_verifier_env *env,
 				if (lo_live && stype == STACK_SPILL) {
 					u8 val = STACK_MISC;
 
+					if (spill->type != SCALAR_VALUE)
+						continue;
+
 					/*
 					 * 8 byte spill of scalar 0 where half slot is dead
 					 * should become STACK_ZERO in lo 4 bytes.

```


---
## 3d562d35a044 — bpf: Check global subprog exception paths

```diff
 include/linux/bpf_verifier.h |  2 ++
 kernel/bpf/cfg.c             | 13 ++++++++++++-
 kernel/bpf/verifier.c        | 23 +++++++++++++++++------
 3 files changed, 31 insertions(+), 7 deletions(-)

diff --git a/include/linux/bpf_verifier.h b/include/linux/bpf_verifier.h
index b148f816f25b..185b2aa43a42 100644
--- a/include/linux/bpf_verifier.h
+++ b/include/linux/bpf_verifier.h
@@ -729,6 +729,7 @@ struct bpf_subprog_info {
 	 */
 	s16 fastcall_stack_off;
 	bool has_tail_call: 1;
+	bool might_throw: 1;
 	bool tail_call_reachable: 1;
 	bool has_ld_abs: 1;
 	bool is_cb: 1;
@@ -1308,6 +1309,7 @@ void bpf_fmt_stack_mask(char *buf, ssize_t buf_sz, u64 stack_mask);
 bool bpf_subprog_is_global(const struct bpf_verifier_env *env, int subprog);
 
 int bpf_find_subprog(struct bpf_verifier_env *env, int off);
+bool bpf_is_throw_kfunc(struct bpf_insn *insn);
 int bpf_compute_const_regs(struct bpf_verifier_env *env);
 int bpf_prune_dead_branches(struct bpf_verifier_env *env);
 int bpf_check_cfg(struct bpf_verifier_env *env);
diff --git a/kernel/bpf/cfg.c b/kernel/bpf/cfg.c
index 998f42a8189a..26d37066465f 100644
--- a/kernel/bpf/cfg.c
+++ b/kernel/bpf/cfg.c
@@ -64,11 +64,19 @@ static void mark_subprog_might_sleep(struct bpf_verifier_env *env, int off)
 	subprog->might_sleep = true;
 }
 
+static void mark_subprog_might_throw(struct bpf_verifier_env *env, int off)
+{
+	struct bpf_subprog_info *subprog;
+
+	subprog = bpf_find_containing_subprog(env, off);
+	subprog->might_throw = true;
+}
+
 /* 't' is an index of a call-site.
  * 'w' is a callee entry point.
  * Eventually this function would be called when env->cfg.insn_state[w] == EXPLORED.
  * Rely on DFS traversal order and absence of recursive calls to guarantee that
- * callee's change_pkt_data marks would be correct at that moment.
+ * callee's effect marks would be correct at that moment.
  */
 static void merge_callee_effects(struct bpf_verifier_env *env, int t, int w)
 {
@@ -78,6 +86,7 @@ static void merge_callee_effects(struct bpf_verifier_env *env, int t, int w)
 	callee = bpf_find_containing_subprog(env, w);
 	caller->changes_pkt_data |= callee->changes_pkt_data;
 	caller->might_sleep |= callee->might_sleep;
+	caller->might_throw |= callee->might_throw;
 }
 
 enum {
@@ -509,6 +518,8 @@ static int visit_insn(int t, struct bpf_verifier_env *env)
 				mark_subprog_might_sleep(env, t);
 			if (ret == 0 && bpf_is_kfunc_pkt_changing(&meta))
 				mark_subprog_changes_pkt_data(env, t);
+			if (ret == 0 && bpf_is_throw_kfunc(insn))
+				mark_subprog_might_throw(env, t);
 		}
 		return visit_func_call_insn(t, insns, env, insn->src_reg == BPF_PSEUDO_CALL);
 
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 88b40c979b56..7fb88e1cd7c4 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -442,7 +442,6 @@ static bool is_dynptr_ref_function(enum bpf_func_id func_id)
 static bool is_sync_callback_calling_kfunc(u32 btf_id);
 static bool is_async_callback_calling_kfunc(u32 btf_id);
 static bool is_callback_calling_kfunc(u32 btf_id);
-static bool is_bpf_throw_kfunc(struct bpf_insn *insn);
 
 static bool is_bpf_wq_set_callback_kfunc(u32 btf_id);
 static bool is_task_work_add_kfunc(u32 func_id);
@@ -5405,7 +5404,7 @@ static int check_max_stack_depth_subprog(struct bpf_verifier_env *env, int idx,
 		if (bpf_pseudo_kfunc_call(insn + i) && !insn[i].off) {
 			bool err = false;
 
-			if (!is_bpf_throw_kfunc(insn + i))
+			if (!bpf_is_throw_kfunc(insn + i))
 				continue;
 			for (tmp = idx; tmp >= 0 && !err; tmp = dinfo[tmp].caller) {
 				if (subprog[tmp].is_cb) {
@@ -9499,6 +9498,9 @@ static int push_callback_call(struct bpf_verifier_env *env, struct bpf_insn *ins
 	return 0;
 }
 
+static int process_bpf_exit_full(struct bpf_verifier_env *env,
+				 bool *do_print_state, bool exception_exit);
+
 static int check_func_call(struct bpf_verifier_env *env, struct bpf_insn *insn,
 			   int *insn_idx)
 {
@@ -9552,6 +9554,17 @@ static int check_func_call(struct bpf_verifier_env *env, struct bpf_insn *insn,
 			caller->regs[BPF_REG_0].subreg_def = DEF_NOT_SUBREG;
 		}
 
+		if (env->subprog_info[subprog].might_throw) {
+			struct bpf_verifier_state *branch;
+
+			branch = push_stack(env, *insn_idx + 1, *insn_idx, false);
+			if (IS_ERR(branch)) {
+				verbose(env, "failed to push state for global subprog exception path\n");
+				return PTR_ERR(branch);
+			}
+			return process_bpf_exit_full(env, NULL, true);
+		}
+
 		/* continue with next insn after call */
 		return 0;
 	}
@@ -11782,7 +11795,7 @@ static bool is_async_callback_calling_kfunc(u32 btf_id)
 	       is_task_work_add_kfunc(btf_id);
 }
 
-static bool is_bpf_throw_kfunc(struct bpf_insn *insn)
+bool bpf_is_throw_kfunc(struct bpf_insn *insn)
 {
 	return bpf_pseudo_kfunc_call(insn) && insn->off == 0 &&
 	       insn->imm == special_kfunc_list[KF_bpf_throw];
@@ -12972,8 +12985,6 @@ static int check_special_kfunc(struct bpf_verifier_env *env, struct bpf_kfunc_ca
 }
 
 static int check_return_code(struct bpf_verifier_env *env, int regno, const char *reg_name);
-static int process_bpf_exit_full(struct bpf_verifier_env *env,
-				 bool *do_print_state, bool exception_exit);
 
 static int check_kfunc_call(struct bpf_verifier_env *env, struct bpf_insn *insn,
 			    int *insn_idx_p)
@@ -13354,7 +13365,7 @@ static int check_kfunc_call(struct bpf_verifier_env *env, struct bpf_insn *insn,
 	if (meta.func_id == special_kfunc_list[KF_bpf_session_cookie])
 		env->prog->call_session_cookie = true;
 
-	if (is_bpf_throw_kfunc(insn))
+	if (bpf_is_throw_kfunc(insn))
 		return process_bpf_exit_full(env, NULL, true);
 
 	return 0;

```


---
## 41025f441fe6 — bpf: Compare parent_id in refsafe() for REF_TYPE_PTR

```diff
 kernel/bpf/states.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/bpf/states.c b/kernel/bpf/states.c
index 5945956a7573..06d9ae24f006 100644
--- a/kernel/bpf/states.c
+++ b/kernel/bpf/states.c
@@ -890,6 +890,9 @@ static bool refsafe(struct bpf_verifier_state *old, struct bpf_verifier_state *c
 			return false;
 		switch (old->refs[i].type) {
 		case REF_TYPE_PTR:
+			if (!check_ids(old->refs[i].parent_id, cur->refs[i].parent_id, idmap))
+				return false;
+			break;
 		case REF_TYPE_IRQ:
 			break;
 		case REF_TYPE_LOCK:

```


---
## 52c2b005a3c1 — bpf: take into account liveness when propagating precision

```diff
 kernel/bpf/verifier.c | 6 ++++--
 1 file changed, 4 insertions(+), 2 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 13fd4c893f3b..0aaf7703326b 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -15058,7 +15058,8 @@ static int propagate_precision(struct bpf_verifier_env *env,
 		state_reg = state->regs;
 		for (i = 0; i < BPF_REG_FP; i++, state_reg++) {
 			if (state_reg->type != SCALAR_VALUE ||
-			    !state_reg->precise)
+			    !state_reg->precise ||
+			    !(state_reg->live & REG_LIVE_READ))
 				continue;
 			if (env->log.level & BPF_LOG_LEVEL2)
 				verbose(env, "frame %d: propagating r%d\n", i, fr);
@@ -15072,7 +15073,8 @@ static int propagate_precision(struct bpf_verifier_env *env,
 				continue;
 			state_reg = &state->stack[i].spilled_ptr;
 			if (state_reg->type != SCALAR_VALUE ||
-			    !state_reg->precise)
+			    !state_reg->precise ||
+			    !(state_reg->live & REG_LIVE_READ))
 				continue;
 			if (env->log.level & BPF_LOG_LEVEL2)
 				verbose(env, "frame %d: propagating fp%d\n",

```


---
## 713274f1f2c8 — bpf: Fix verifier id tracking of scalars on spill

```diff
 kernel/bpf/verifier.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 5871aa78d01a..0dd8adc7a159 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -3868,6 +3868,9 @@ static int check_stack_write_fixed_off(struct bpf_verifier_env *env,
 				return err;
 		}
 		save_register_state(state, spi, reg, size);
+		/* Break the relation on a narrowing spill. */
+		if (fls64(reg->umax_value) > BITS_PER_BYTE * size)
+			state->stack[spi].spilled_ptr.id = 0;
 	} else if (!reg && !(off % BPF_REG_SIZE) && is_bpf_st_mem(insn) &&
 		   insn->imm != 0 && env->bpf_capable) {
 		struct bpf_reg_state fake_reg = {};

```
