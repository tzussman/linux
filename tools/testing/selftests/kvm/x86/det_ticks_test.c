// SPDX-License-Identifier: GPL-2.0
/*
 * Test for KVM_CAP_X86_DETERMINISTIC tick counting.
 *
 * The guest runs a loop with a statically known number of conditional
 * branches between two synchronization points; the tick count read
 * through KVM_VCPU_DET_TICKS must advance by exactly that number, and
 * an explicitly written count must be honored.
 */
#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

#include <pthread.h>

#define LOOP_ITERS	1000000UL
#define TICK_RESET	0x123456789abUL

static void run_loop(unsigned long iters)
{
	/* One conditional branch per iteration, no others. */
	asm volatile("1:	dec %0\n\t"
		     "	jnz 1b"
		     : "+r"(iters) :: "cc");
}

/*
 * The ucall path between two syncs executes a fixed number of branches
 * of its own, so intervals are compared by difference: the second and
 * third intervals run LOOP_ITERS more than the first.
 */
static void guest_code(void)
{
	GUEST_SYNC(0);
	run_loop(LOOP_ITERS);
	GUEST_SYNC(1);
	run_loop(2 * LOOP_ITERS);
	GUEST_SYNC(2);
	run_loop(2 * LOOP_ITERS);
	GUEST_SYNC(3);
	GUEST_DONE();
}

static void run_to_sync(struct kvm_vcpu *vcpu, u64 expected);

/* The counter follows the vCPU to whichever thread runs it. */
static void *run_from_thread(void *arg)
{
	run_to_sync(arg, 3);
	return NULL;
}

static u64 get_ticks(struct kvm_vcpu *vcpu)
{
	u64 ticks;

	vcpu_device_attr_get(vcpu, KVM_VCPU_DET_CTRL, KVM_VCPU_DET_TICKS, &ticks);
	return ticks;
}

static void run_to_sync(struct kvm_vcpu *vcpu, u64 expected)
{
	struct ucall uc;

	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);

	switch (get_ucall(vcpu, &uc)) {
	case UCALL_SYNC:
		TEST_ASSERT_EQ(uc.args[1], expected);
		break;
	case UCALL_DONE:
		TEST_ASSERT_EQ(expected, -1);
		break;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	default:
		TEST_FAIL("Unexpected ucall %lu", uc.cmd);
	}
}

int main(int argc, char *argv[])
{
	struct kvm_enable_cap cap = {
		.cap = KVM_CAP_X86_DETERMINISTIC,
		.args = { KVM_X86_DET_TICKS, 0 },
	};
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	u64 t0, t1, t2, t3;

	TEST_REQUIRE(kvm_check_cap(KVM_CAP_X86_DETERMINISTIC) & KVM_X86_DET_TICKS);

	/* Optional raw perf event to count instead of KVM's default. */
	if (argc > 1)
		cap.args[1] = strtoull(argv[1], NULL, 0);

	vm = vm_create(1);
	vm_enable_cap(vm, KVM_CAP_PMU_CAPABILITY, KVM_PMU_CAP_DISABLE);
	vm_ioctl(vm, KVM_ENABLE_CAP, &cap);
	vcpu = vm_vcpu_add(vm, 0, guest_code);
	vcpu_has_device_attr(vcpu, KVM_VCPU_DET_CTRL, KVM_VCPU_DET_TICKS);

	run_to_sync(vcpu, 0);
	t0 = get_ticks(vcpu);
	vcpu->run->kvm_valid_regs = KVM_SYNC_X86_DET_TICKS;
	run_to_sync(vcpu, 1);
	t1 = get_ticks(vcpu);
	TEST_ASSERT_EQ(vcpu->run->s.regs.det_ticks, t1);
	vcpu->run->kvm_valid_regs = 0;
	run_to_sync(vcpu, 2);
	t2 = get_ticks(vcpu);
	TEST_ASSERT(t1 - t0 >= LOOP_ITERS && (t2 - t1) - (t1 - t0) == LOOP_ITERS,
		    "Expected intervals to differ by %lu ticks, got %lu and %lu",
		    LOOP_ITERS, t1 - t0, t2 - t1);

	t3 = TICK_RESET;
	vcpu_device_attr_set(vcpu, KVM_VCPU_DET_CTRL, KVM_VCPU_DET_TICKS, &t3);
	TEST_ASSERT_EQ(get_ticks(vcpu), TICK_RESET);
	{
		pthread_t thread;

		TEST_ASSERT_EQ(pthread_create(&thread, NULL, run_from_thread, vcpu), 0);
		TEST_ASSERT_EQ(pthread_join(thread, NULL), 0);
	}
	t3 = get_ticks(vcpu);
	TEST_ASSERT(t3 - TICK_RESET == t2 - t1,
		    "Expected %lu ticks after reset, got %lu", t2 - t1,
		    t3 - TICK_RESET);

	run_to_sync(vcpu, -1);
	kvm_vm_free(vm);
	return 0;
}
