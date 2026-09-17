// SPDX-License-Identifier: GPL-2.0
/*
 * A deterministic VM gets no nested virtualization: the controls its
 * clock relies on are not virtualized for nested guests.  CR4.VMXE must
 * be reserved for such a guest even though the host supports nesting,
 * while an ordinary VM on the same host can set it.
 */
#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

static void guest_code(void)
{
	unsigned long cr4 = get_cr4();
	u8 vector;

	vector = kvm_asm_safe("mov %[cr4], %%cr4", [cr4]"r"(cr4 | X86_CR4_VMXE));
	GUEST_SYNC(vector);
	GUEST_DONE();
}

static u8 run_vcpu(struct kvm_vcpu *vcpu)
{
	struct ucall uc;
	u8 vector;

	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);
	switch (get_ucall(vcpu, &uc)) {
	case UCALL_SYNC:
		vector = uc.args[1];
		break;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	default:
		TEST_FAIL("Unexpected ucall %lu", uc.cmd);
	}
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_DONE);
	return vector;
}

int main(int argc, char *argv[])
{
	struct kvm_enable_cap cap = {
		.cap = KVM_CAP_X86_DETERMINISTIC,
		.args = { KVM_X86_DET_TICKS, 0 },
	};
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	TEST_REQUIRE(kvm_check_cap(KVM_CAP_X86_DETERMINISTIC) & KVM_X86_DET_TICKS);
	TEST_REQUIRE(kvm_cpu_has(X86_FEATURE_VMX));

	if (argc > 1)
		cap.args[1] = strtoull(argv[1], NULL, 0);

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	TEST_ASSERT_EQ(run_vcpu(vcpu), 0);
	kvm_vm_free(vm);

	vm = vm_create(1);
	vm_enable_cap(vm, KVM_CAP_PMU_CAPABILITY, KVM_PMU_CAP_DISABLE);
	vm_ioctl(vm, KVM_ENABLE_CAP, &cap);
	vcpu = vm_vcpu_add(vm, 0, guest_code);
	TEST_ASSERT(kvm_cpu_has(X86_FEATURE_VMX) &&
		    vcpu_cpuid_has(vcpu, X86_FEATURE_VMX),
		    "Expected CPUID to still advertise VMX");
	TEST_ASSERT_EQ(run_vcpu(vcpu), GP_VECTOR);
	kvm_vm_free(vm);
	return 0;
}
