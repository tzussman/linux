/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_KVM_DET_H
#define ARCH_X86_KVM_DET_H

#include <linux/kvm_host.h>

static inline bool kvm_det_enabled(struct kvm *kvm)
{
	return IS_ENABLED(CONFIG_KVM_X86_DETERMINISTIC) && kvm->arch.det_enabled;
}

static inline bool kvm_det_has(struct kvm *kvm, u32 feature)
{
	return kvm_det_enabled(kvm) && (kvm->arch.det_features & feature);
}

static inline bool kvm_det_stepping(struct kvm_vcpu *vcpu)
{
	return IS_ENABLED(CONFIG_KVM_X86_DETERMINISTIC) && vcpu->arch.det.stepping;
}

#ifdef CONFIG_KVM_X86_DETERMINISTIC
int kvm_det_enable(struct kvm *kvm, u32 features, u64 tick_event);
void kvm_det_vcpu_init(struct kvm_vcpu *vcpu);
int kvm_det_vcpu_run(struct kvm_vcpu *vcpu);
void kvm_det_vcpu_destroy(struct kvm_vcpu *vcpu);
u64 kvm_det_ticks(struct kvm_vcpu *vcpu);
int kvm_det_set_ticks(struct kvm_vcpu *vcpu, u64 ticks);
u64 kvm_det_read_tsc(struct kvm_vcpu *vcpu);
void kvm_det_write_tsc(struct kvm_vcpu *vcpu, u64 tsc);
u64 kvm_det_rand(struct kvm_vcpu *vcpu);
int kvm_det_pre_run(struct kvm_vcpu *vcpu);
void kvm_det_step(struct kvm_vcpu *vcpu);
int kvm_det_complete_exit(struct kvm_vcpu *vcpu, int r);
void kvm_det_post_run(struct kvm_vcpu *vcpu);
int kvm_det_vcpu_has_attr(struct kvm_vcpu *vcpu, struct kvm_device_attr *attr);
int kvm_det_vcpu_get_attr(struct kvm_vcpu *vcpu, struct kvm_device_attr *attr);
int kvm_det_vcpu_set_attr(struct kvm_vcpu *vcpu, struct kvm_device_attr *attr);
#else
static inline int kvm_det_enable(struct kvm *kvm, u32 features, u64 tick_event)
{
	return -EINVAL;
}
static inline void kvm_det_vcpu_init(struct kvm_vcpu *vcpu) {}
static inline int kvm_det_vcpu_run(struct kvm_vcpu *vcpu)
{
	return 0;
}
static inline void kvm_det_vcpu_destroy(struct kvm_vcpu *vcpu) {}
static inline u64 kvm_det_ticks(struct kvm_vcpu *vcpu)
{
	return 0;
}
static inline int kvm_det_set_ticks(struct kvm_vcpu *vcpu, u64 ticks)
{
	return -ENXIO;
}
static inline u64 kvm_det_read_tsc(struct kvm_vcpu *vcpu)
{
	return 0;
}
static inline void kvm_det_write_tsc(struct kvm_vcpu *vcpu, u64 tsc) {}
static inline u64 kvm_det_rand(struct kvm_vcpu *vcpu)
{
	return 0;
}
static inline int kvm_det_pre_run(struct kvm_vcpu *vcpu)
{
	return 1;
}
static inline void kvm_det_step(struct kvm_vcpu *vcpu) {}
static inline int kvm_det_complete_exit(struct kvm_vcpu *vcpu, int r)
{
	return r;
}
static inline void kvm_det_post_run(struct kvm_vcpu *vcpu) {}
static inline int kvm_det_vcpu_has_attr(struct kvm_vcpu *vcpu,
					 struct kvm_device_attr *attr)
{
	return -ENXIO;
}
static inline int kvm_det_vcpu_get_attr(struct kvm_vcpu *vcpu,
					 struct kvm_device_attr *attr)
{
	return -ENXIO;
}
static inline int kvm_det_vcpu_set_attr(struct kvm_vcpu *vcpu,
					 struct kvm_device_attr *attr)
{
	return -ENXIO;
}
#endif

#endif
