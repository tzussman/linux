// SPDX-License-Identifier: GPL-2.0
/*
 * Test for KVM_X86_DET_TSC: the guest's TSC must be base + ticks * mult,
 * identical across RDTSC, RDTSCP and RDMSR, and advance by exactly the
 * branches executed.
 */
#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

#define LOOP_ITERS	100000UL
#define TSC_BASE	0x1000000000000000UL
#define TSC_MULT	8UL
#define TSC_AUX_VAL	0x1234U

static void run_loop(unsigned long iters)
{
	asm volatile("1:	dec %0\n\t"
		     "	jnz 1b"
		     : "+r"(iters) :: "cc");
}

static void guest_code(void)
{
	u64 t0, t1, t2, t3, t4, t5;
	u32 aux;

	/*
	 * No conditional branch between reads that must agree; the
	 * assertions themselves branch, so they come after the reads.
	 */
	t0 = rdtsc();
	t1 = rdtscp(&aux);
	t2 = rdmsr(MSR_IA32_TSC);
	GUEST_ASSERT_EQ(t0, t1);
	GUEST_ASSERT_EQ(t1, t2);
	GUEST_ASSERT_EQ(aux, TSC_AUX_VAL);

	t2 = rdtsc();
	run_loop(LOOP_ITERS);
	t3 = rdtsc();
	GUEST_ASSERT_EQ(t3 - t2, LOOP_ITERS * TSC_MULT);

	/* A guest write to the TSC is honored exactly. */
	wrmsr(MSR_IA32_TSC, 0x5000);
	t4 = rdtsc();
	run_loop(LOOP_ITERS);
	t5 = rdtsc();
	GUEST_ASSERT_EQ(t4, 0x5000);
	GUEST_ASSERT_EQ(t5 - t4, LOOP_ITERS * TSC_MULT);

	GUEST_SYNC(rdtsc());
	GUEST_DONE();
}

int main(int argc, char *argv[])
{
	struct kvm_enable_cap cap = {
		.cap = KVM_CAP_X86_DETERMINISTIC,
		.args = { KVM_X86_DET_TICKS | KVM_X86_DET_TSC, 0 },
	};
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	u64 val, ticks, tsc;

	TEST_REQUIRE(kvm_check_cap(KVM_CAP_X86_DETERMINISTIC) & KVM_X86_DET_TSC);
	TEST_REQUIRE(kvm_cpu_has(X86_FEATURE_RDTSCP));

	if (argc > 1)
		cap.args[1] = strtoull(argv[1], NULL, 0);

	vm = vm_create(1);
	vm_enable_cap(vm, KVM_CAP_PMU_CAPABILITY, KVM_PMU_CAP_DISABLE);
	vm_ioctl(vm, KVM_ENABLE_CAP, &cap);
	vcpu = vm_vcpu_add(vm, 0, guest_code);

	vcpu_set_msr(vcpu, MSR_TSC_AUX, TSC_AUX_VAL);
	val = TSC_BASE;
	vcpu_device_attr_set(vcpu, KVM_VCPU_DET_CTRL, KVM_VCPU_DET_TSC_BASE, &val);
	val = TSC_MULT;
	vcpu_device_attr_set(vcpu, KVM_VCPU_DET_CTRL, KVM_VCPU_DET_TSC_MULT, &val);

	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);
	switch (get_ucall(vcpu, &uc)) {
	case UCALL_SYNC:
		break;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	default:
		TEST_FAIL("Unexpected ucall %lu", uc.cmd);
	}

	/* A host-initiated TSC_ADJUST write (a restore) does not move the clock. */
	tsc = vcpu_get_msr(vcpu, MSR_IA32_TSC);
	vcpu_set_msr(vcpu, MSR_IA32_TSC_ADJUST, 0x1000);
	TEST_ASSERT_EQ(vcpu_get_msr(vcpu, MSR_IA32_TSC), tsc);
	TEST_ASSERT_EQ(vcpu_get_msr(vcpu, MSR_IA32_TSC_ADJUST), 0x1000);

	/* Host-side reads see the same clock. */
	vcpu_device_attr_get(vcpu, KVM_VCPU_DET_CTRL, KVM_VCPU_DET_TICKS, &ticks);
	vcpu_device_attr_get(vcpu, KVM_VCPU_DET_CTRL, KVM_VCPU_DET_TSC_BASE, &val);
	tsc = vcpu_get_msr(vcpu, MSR_IA32_TSC);
	TEST_ASSERT(tsc == val + ticks * TSC_MULT,
		    "MSR TSC %lx != base %lx + ticks %lu * %lu", tsc, val, ticks,
		    TSC_MULT);
	TEST_ASSERT(tsc >= uc.args[1], "TSC went backwards: %lx < %lx", tsc,
		    uc.args[1]);

	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_DONE);
	kvm_vm_free(vm);
	return 0;
}
