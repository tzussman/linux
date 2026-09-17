// SPDX-License-Identifier: GPL-2.0
/*
 * A deterministic VM whose tick counter cannot be scheduled, because
 * pinned host events occupy every general-purpose counter of the CPU,
 * must not run with a broken clock: KVM_RUN reports
 * KVM_INTERNAL_ERROR_DET_COUNTER.
 */
#include <linux/perf_event.h>
#include <sched.h>
#include <sys/syscall.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

#define NR_GP_COUNTERS 8

static void guest_code(void)
{
	GUEST_SYNC(0);
	GUEST_DONE();
}

/* Pin a CPU-wide event to this CPU; pinned CPU events beat task events. */
static int pin_host_event(int cpu)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_RAW,
		.size = sizeof(attr),
		.config = 0x3c,		/* CPU_CLK_UNHALTED.THREAD_P, any GP counter */
		.pinned = 1,
	};

	return syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
}

int main(int argc, char *argv[])
{
	struct kvm_enable_cap cap = {
		.cap = KVM_CAP_X86_DETERMINISTIC,
		.args = { KVM_X86_DET_TICKS, 0 },
	};
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	cpu_set_t set;
	int cpu, i, nr = 0;

	TEST_REQUIRE(kvm_check_cap(KVM_CAP_X86_DETERMINISTIC) & KVM_X86_DET_TICKS);

	if (argc > 1)
		cap.args[1] = strtoull(argv[1], NULL, 0);

	cpu = sched_getcpu();
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	TEST_ASSERT_EQ(sched_setaffinity(0, sizeof(set), &set), 0);
	for (i = 0; i < NR_GP_COUNTERS; i++)
		if (pin_host_event(cpu) >= 0)
			nr++;
	TEST_REQUIRE(nr >= 4);

	vm = vm_create(1);
	vm_enable_cap(vm, KVM_CAP_PMU_CAPABILITY, KVM_PMU_CAP_DISABLE);
	vm_ioctl(vm, KVM_ENABLE_CAP, &cap);
	vcpu = vm_vcpu_add(vm, 0, guest_code);

	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_INTERNAL_ERROR);
	TEST_ASSERT_EQ(vcpu->run->internal.suberror, KVM_INTERNAL_ERROR_DET_COUNTER);

	kvm_vm_free(vm);
	return 0;
}
