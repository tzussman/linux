// SPDX-License-Identifier: GPL-2.0
/*
 * Test for KVM_X86_DET_FENCE: the guest stops exactly at the requested
 * tick count, whether the target lies beyond the interrupt margin,
 * inside it, or across a return to userspace, and instruction offsets
 * step past the target.
 */
#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

#define LOOP_ITERS	4000000UL

static noinline void run_loop(unsigned long iters)
{
	asm volatile("1:	dec %0\n\t"
		     "	jnz 1b"
		     : "+r"(iters) :: "cc");
}

static void guest_code(void)
{
	GUEST_SYNC(0);
	run_loop(LOOP_ITERS);
	GUEST_SYNC(1);
	run_loop(LOOP_ITERS);
	GUEST_SYNC(2);
	/* A PIO exit completed by KVM, immediately followed by HLT. */
	asm volatile("out %%al, $0x7f\n\t"
		     "hlt" ::: "memory");
	GUEST_SYNC(3);
	GUEST_DONE();
}

static u64 get_ticks(struct kvm_vcpu *vcpu)
{
	u64 ticks;

	vcpu_device_attr_get(vcpu, KVM_VCPU_DET_CTRL, KVM_VCPU_DET_TICKS, &ticks);
	return ticks;
}

static void set_fence(struct kvm_vcpu *vcpu, u64 ticks, u64 insns)
{
	struct kvm_x86_det_fence fence = { .ticks = ticks, .insns = insns };

	vcpu_device_attr_set(vcpu, KVM_VCPU_DET_CTRL, KVM_VCPU_DET_FENCE, &fence);
}

static void expect_sync(struct kvm_vcpu *vcpu, u64 val)
{
	struct ucall uc;

	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);
	switch (get_ucall(vcpu, &uc)) {
	case UCALL_SYNC:
		TEST_ASSERT_EQ(uc.args[1], val);
		break;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	default:
		TEST_FAIL("Unexpected ucall %lu", uc.cmd);
	}
}

/* Run to a fence and check the stop is exact. */
static void expect_fence(struct kvm_vcpu *vcpu, u64 target, u64 insns)
{
	struct kvm_x86_det_fence fence;
	struct kvm_regs regs;
	u64 ticks;

	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_X86_DET_FENCE);
	ticks = get_ticks(vcpu);
	TEST_ASSERT_EQ(vcpu->run->det_fence.ticks, ticks);
	if (insns)
		TEST_ASSERT(ticks >= target && ticks <= target + insns,
			    "Stopped at %lu, expected %lu plus at most %lu",
			    ticks, target, insns);
	else
		TEST_ASSERT(ticks == target, "Stopped at %lu, expected %lu",
			    ticks, target);

	vcpu_device_attr_get(vcpu, KVM_VCPU_DET_CTRL, KVM_VCPU_DET_FENCE, &fence);
	TEST_ASSERT_EQ(fence.ticks, KVM_X86_DET_FENCE_NONE);

	/* An exact stop lands inside the loop function. */
	vcpu_regs_get(vcpu, &regs);
	TEST_ASSERT(insns || (regs.rip >= (u64)run_loop && regs.rip < (u64)run_loop + 64),
		    "RIP %llx outside run_loop", regs.rip);
}

int main(int argc, char *argv[])
{
	struct kvm_enable_cap cap = {
		.cap = KVM_CAP_X86_DETERMINISTIC,
		.args = { KVM_X86_DET_TICKS | KVM_X86_DET_FENCE, 0 },
	};
	struct kvm_x86_det_fence fence;
	struct kvm_guest_debug debug = { 0 };
	struct kvm_mp_state mp_state;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	u64 t0, t1, target;
	int i;

	TEST_REQUIRE(kvm_check_cap(KVM_CAP_X86_DETERMINISTIC) & KVM_X86_DET_FENCE);

	if (argc > 1)
		cap.args[1] = strtoull(argv[1], NULL, 0);

	vm = vm_create(1);
	vm_enable_cap(vm, KVM_CAP_PMU_CAPABILITY, KVM_PMU_CAP_DISABLE);
	vm_ioctl(vm, KVM_ENABLE_CAP, &cap);
	vcpu = vm_vcpu_add(vm, 0, guest_code);

	vcpu_run(vcpu);
	expect_sync(vcpu, 0);
	t0 = get_ticks(vcpu);

	/* A fence in the past is refused. */
	fence.ticks = t0 - 1;
	fence.insns = 0;
	TEST_ASSERT_EQ(__vcpu_device_attr_set(vcpu, KVM_VCPU_DET_CTRL,
					      KVM_VCPU_DET_FENCE, &fence), -1);
	TEST_ASSERT_EQ(errno, EINVAL);

	/* Far beyond the margin: interrupt, then step. */
	target = t0 + 1000000;
	set_fence(vcpu, target, 0);
	expect_fence(vcpu, target, 0);

	/* Inside the margin: step from the start. */
	target += 10;
	set_fence(vcpu, target, 0);
	expect_fence(vcpu, target, 0);

	/* Consecutive exact stops, each one tick apart. */
	for (i = 0; i < 20; i++) {
		target += 1;
		set_fence(vcpu, target, 0);
		expect_fence(vcpu, target, 0);
	}

	/* Instruction offset past the target. */
	target += 100000;
	set_fence(vcpu, target, 7);
	expect_fence(vcpu, target, 7);

	/* Re-arming replaces the pending fence. */
	set_fence(vcpu, target + 5000000, 0);
	target += 100000;
	set_fence(vcpu, target, 0);
	expect_fence(vcpu, target, 0);

	/* A fence beyond the next userspace exit survives it. */
	target = t0 + LOOP_ITERS + 100;
	set_fence(vcpu, target, 0);
	vcpu_run(vcpu);
	expect_sync(vcpu, 1);
	t1 = get_ticks(vcpu);
	TEST_ASSERT(t1 < target, "Sync 1 at %lu, fence at %lu", t1, target);
	expect_fence(vcpu, target, 0);

	/* Disarm and run to the next sync. */
	set_fence(vcpu, target + 1000, 0);
	set_fence(vcpu, KVM_X86_DET_FENCE_NONE, 0);
	vcpu_run(vcpu);

	/*
	 * A fence that fires inside an instruction whose completion is itself
	 * an exit does not claim that exit: it is flagged instead.  With TF
	 * single-stepping, completing the OUT reports KVM_EXIT_DEBUG; the
	 * fence at the current count fires on that same step.
	 */
	expect_sync(vcpu, 2);
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);
	TEST_ASSERT_EQ(vcpu->run->io.port, 0x7f);
	debug.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
	vcpu_guest_debug_set(vcpu, &debug);
	set_fence(vcpu, get_ticks(vcpu), 0);
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_DEBUG);
	TEST_ASSERT(vcpu->run->flags & KVM_RUN_X86_DET_FENCE,
		    "Fence hit during a debug exit not flagged");
	vcpu_device_attr_get(vcpu, KVM_VCPU_DET_CTRL, KVM_VCPU_DET_FENCE, &fence);
	TEST_ASSERT_EQ(fence.ticks, KVM_X86_DET_FENCE_NONE);
	debug.control = 0;
	vcpu_guest_debug_set(vcpu, &debug);

	/*
	 * HLT is handled in the kernel with an in-kernel irqchip, so a fence
	 * firing on it is reported as the fence exit; the flag is per run.
	 */
	set_fence(vcpu, get_ticks(vcpu), 0);
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_X86_DET_FENCE);
	TEST_ASSERT(vcpu->run->flags & KVM_RUN_X86_DET_FENCE, "Fence exit not flagged");
	/* The vCPU halted in the kernel; nothing will wake it. */
	mp_state.mp_state = KVM_MP_STATE_RUNNABLE;
	vcpu_mp_state_set(vcpu, &mp_state);
	vcpu_run(vcpu);
	TEST_ASSERT(!(vcpu->run->flags & KVM_RUN_X86_DET_FENCE), "Flag is per run");
	expect_sync(vcpu, 3);
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_DONE);

	kvm_vm_free(vm);
	return 0;
}
