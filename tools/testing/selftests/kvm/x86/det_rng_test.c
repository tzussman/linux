// SPDX-License-Identifier: GPL-2.0
/*
 * Test for KVM_X86_DET_RNG: RDRAND and RDSEED return the xoshiro256**
 * sequence of the state set through KVM_VCPU_DET_RNG_STATE, truncated
 * to the operand size, with CF set.
 */
#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

#define NR_DRAWS 8

static u64 xoshiro256ss(u64 *s)
{
	u64 result = ((s[1] * 5) << 7 | (s[1] * 5) >> 57) * 9;
	u64 t = s[1] << 17;

	s[2] ^= s[0];
	s[3] ^= s[1];
	s[1] ^= s[2];
	s[0] ^= s[3];
	s[2] ^= t;
	s[3] = (s[3] << 45) | (s[3] >> 19);
	return result;
}

static void guest_code(void)
{
	u64 v64, cf;
	u32 v32;
	u16 v16;
	int i;

	for (i = 0; i < NR_DRAWS; i++) {
		asm volatile("rdrand %0; setc %b1" : "=r"(v64), "=r"(cf) :: "cc");
		GUEST_ASSERT(cf & 1);
		GUEST_SYNC(v64);
	}
	asm volatile("rdseed %0" : "=r"(v64) :: "cc");
	GUEST_SYNC(v64);
	asm volatile("rdrand %0" : "=r"(v32) :: "cc");
	GUEST_SYNC(v32);
	v64 = 0xdead0000dead0000UL;
	asm volatile("rdrand %0" : "=r"(v16) :: "cc");
	GUEST_SYNC(v16);
	/* Upper bits of a 16-bit destination are preserved. */
	asm volatile("mov %1, %0; rdrand %w0" : "=r"(v64) : "r"(v64) : "cc");
	GUEST_SYNC(v64);
	GUEST_DONE();
}

static u64 next_sync(struct kvm_vcpu *vcpu)
{
	struct ucall uc;

	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);
	switch (get_ucall(vcpu, &uc)) {
	case UCALL_SYNC:
		return uc.args[1];
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	default:
		TEST_FAIL("Unexpected ucall %lu", uc.cmd);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct kvm_enable_cap cap = {
		.cap = KVM_CAP_X86_DETERMINISTIC,
		.args = { KVM_X86_DET_TICKS | KVM_X86_DET_RNG, 0 },
	};
	struct kvm_x86_det_rng rng = { { 1, 2, 3, 4 } }, out;
	u64 s[4] = { 1, 2, 3, 4 }, v;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	int i;

	TEST_REQUIRE(kvm_check_cap(KVM_CAP_X86_DETERMINISTIC) & KVM_X86_DET_RNG);
	TEST_REQUIRE(kvm_cpu_has(X86_FEATURE_RDRAND));
	TEST_REQUIRE(kvm_cpu_has(X86_FEATURE_RDSEED));

	if (argc > 1)
		cap.args[1] = strtoull(argv[1], NULL, 0);

	vm = vm_create(1);
	vm_enable_cap(vm, KVM_CAP_PMU_CAPABILITY, KVM_PMU_CAP_DISABLE);
	vm_ioctl(vm, KVM_ENABLE_CAP, &cap);
	vcpu = vm_vcpu_add(vm, 0, guest_code);

	memset(&out, 0, sizeof(out));
	TEST_ASSERT_EQ(__vcpu_device_attr_set(vcpu, KVM_VCPU_DET_CTRL,
					      KVM_VCPU_DET_RNG_STATE, &out), -1);
	vcpu_device_attr_set(vcpu, KVM_VCPU_DET_CTRL, KVM_VCPU_DET_RNG_STATE, &rng);
	vcpu_device_attr_get(vcpu, KVM_VCPU_DET_CTRL, KVM_VCPU_DET_RNG_STATE, &out);
	TEST_ASSERT_EQ(memcmp(&out, &rng, sizeof(rng)), 0);

	for (i = 0; i < NR_DRAWS; i++) {
		v = next_sync(vcpu);
		TEST_ASSERT_EQ(v, xoshiro256ss(s));
	}
	TEST_ASSERT_EQ(next_sync(vcpu), xoshiro256ss(s));
	TEST_ASSERT_EQ(next_sync(vcpu), (u32)xoshiro256ss(s));
	TEST_ASSERT_EQ(next_sync(vcpu), (u16)xoshiro256ss(s));
	TEST_ASSERT_EQ(next_sync(vcpu), 0xdead0000dead0000UL | (u16)xoshiro256ss(s));

	vcpu_device_attr_get(vcpu, KVM_VCPU_DET_CTRL, KVM_VCPU_DET_RNG_STATE, &out);
	TEST_ASSERT_EQ(memcmp(out.s, s, sizeof(s)), 0);

	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_DONE);
	kvm_vm_free(vm);
	return 0;
}
