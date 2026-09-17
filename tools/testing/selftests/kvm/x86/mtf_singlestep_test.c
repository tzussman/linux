// SPDX-License-Identifier: GPL-2.0
/*
 * Test KVM_GUESTDBG_USE_MTF: single-step a known instruction sequence,
 * including an instruction KVM completes in userspace (OUT), and check
 * that the guest never observes RFLAGS.TF.
 */
#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

#define DR6_BS_BIT	(1UL << 14)

extern char step_code[];
asm(".text\n"
    ".globl step_code\n"
    "step_code:\n"
    "	nop\n"			/* +0 */
    "	nop\n"			/* +1 */
    "	pushfq\n"		/* +2 */
    "	pop %rax\n"		/* +3 */
    "	nop\n"			/* +4 */
    "	out %al, $0x7f\n"	/* +5, 2 bytes, exits to userspace */
    "	nop\n"			/* +7 */
    "	ret\n"			/* +8 */
    ".previous\n");

static const unsigned long step_offsets[] = { 1, 2, 3, 4, 5, 7, 8 };

static void guest_code(void)
{
	u64 flags;

	GUEST_SYNC(1);
	flags = ((u64 (*)(void))step_code)();
	GUEST_SYNC(2);
	GUEST_ASSERT(!(flags & X86_EFLAGS_TF));
	GUEST_DONE();
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

int main(int argc, char *argv[])
{
	struct kvm_guest_debug debug = { 0 };
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	unsigned long base = (unsigned long)step_code;
	unsigned int i;

	TEST_REQUIRE(kvm_check_cap(KVM_CAP_SET_GUEST_DEBUG2) & KVM_GUESTDBG_USE_MTF);

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);

	vcpu_run(vcpu);
	expect_sync(vcpu, 1);

	debug.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_MTF;
	TEST_ASSERT_EQ(__vcpu_ioctl(vcpu, KVM_SET_GUEST_DEBUG, &debug), -1);
	TEST_ASSERT_EQ(errno, EINVAL);

	debug.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP |
			KVM_GUESTDBG_USE_MTF;
	vcpu_guest_debug_set(vcpu, &debug);

	/* Run to the first instruction of step_code, through the ucall. */
	do {
		vcpu_run(vcpu);
		if (vcpu->run->exit_reason == KVM_EXIT_IO)
			continue;
		TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_DEBUG);
	} while (vcpu->run->debug.arch.pc != base);

	for (i = 0; i < ARRAY_SIZE(step_offsets); i++) {
		vcpu_run(vcpu);
		if (vcpu->run->exit_reason == KVM_EXIT_IO) {
			TEST_ASSERT_EQ(vcpu->run->io.port, 0x7f);
			TEST_ASSERT_EQ(step_offsets[i], 7);
			vcpu_run(vcpu);
		}
		TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_DEBUG);
		TEST_ASSERT(vcpu->run->debug.arch.pc == base + step_offsets[i],
			    "Step %u stopped at +%lu, expected +%lu", i,
			    (unsigned long)vcpu->run->debug.arch.pc - base,
			    step_offsets[i]);
		TEST_ASSERT_EQ(vcpu->run->debug.arch.exception, DB_VECTOR);
		TEST_ASSERT(vcpu->run->debug.arch.dr6 & DR6_BS_BIT, "DR6.BS not set");
	}

	debug.control = 0;
	vcpu_guest_debug_set(vcpu, &debug);
	vcpu_run(vcpu);
	expect_sync(vcpu, 2);
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_DONE);

	kvm_vm_free(vm);
	return 0;
}
