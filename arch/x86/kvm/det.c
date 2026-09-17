// SPDX-License-Identifier: GPL-2.0
/*
 * Deterministic execution support.
 *
 * A guest whose observable state depends only on its own instruction
 * stream needs a clock that is a function of that stream.  KVM owns a
 * perf event that counts an exactly-retiring event, conditional
 * branches by default, in guest mode only (switched atomically at every
 * VM-Entry and VM-Exit) and exposes the count as the vCPU's "ticks".
 */
#include <linux/kvm_host.h>
#include <linux/perf_event.h>

#include "det.h"
#include "pmu.h"
#include "x86.h"

int kvm_det_enable(struct kvm *kvm, u32 features, u64 tick_event)
{
	int r = -EINVAL;

	if (!(features & KVM_X86_DET_TICKS) ||
	    (features & ~kvm_caps.supported_det_features))
		return -EINVAL;

	/*
	 * The vendor code picks the default event for this CPU model and
	 * rejects a userspace event with bits that would count outside the
	 * guest, e.g. the sibling hyperthread.
	 */
	r = kvm_pmu_call(det_tick_event)(&tick_event);
	if (r)
		return r;

	mutex_lock(&kvm->lock);
	/*
	 * The guest must not compete with KVM for the counters; userspace
	 * disables the vPMU explicitly through KVM_PMU_CAP_DISABLE first.
	 */
	if (kvm->created_vcpus || kvm->arch.enable_pmu) {
		r = -EINVAL;
	} else {
		kvm->arch.det_enabled = true;
		kvm->arch.det_features = features;
		kvm->arch.det_tick_event = tick_event;
		r = 0;
	}
	mutex_unlock(&kvm->lock);
	return r;
}

static struct perf_event *kvm_det_create_event(struct kvm_vcpu *vcpu)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_RAW,
		.size = sizeof(attr),
		.config = vcpu->kvm->arch.det_tick_event,
		.pinned = true,
		.exclude_host = true,
	};

	return perf_event_create_kernel_counter(&attr, -1, current, NULL, vcpu);
}

/*
 * The counter is a task event: it counts only while its thread runs the
 * vCPU, and it can be read locally from exit handlers.  Bind it to the
 * thread that runs the vCPU; if that changes, fold the count so far
 * into the offset and rebind.
 */
static int kvm_det_bind_event(struct kvm_vcpu *vcpu)
{
	struct kvm_det_vcpu *det = &vcpu->arch.det;
	struct perf_event *event;
	u64 enabled, running;

	if (det->event) {
		if (det->task == current)
			return 0;
		det->tick_offset += perf_event_read_value(det->event, &enabled,
							  &running);
		perf_event_release_kernel(det->event);
		det->event = NULL;
	}

	event = kvm_det_create_event(vcpu);
	if (IS_ERR(event))
		return PTR_ERR(event);

	det->event = event;
	det->task = current;
	return 0;
}

/* Called on every KVM_RUN, before the vCPU is loaded. */
int kvm_det_vcpu_run(struct kvm_vcpu *vcpu)
{
	if (!kvm_det_enabled(vcpu->kvm))
		return 0;

	return kvm_det_bind_event(vcpu);
}

void kvm_det_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	struct kvm_det_vcpu *det = &vcpu->arch.det;

	if (det->event)
		perf_event_release_kernel(det->event);
	det->event = NULL;
}

/*
 * A counter that stops counting takes the guest's clock with it and
 * nothing can be recovered, so remember it and report it on the next
 * VM-Entry rather than run on with a broken clock.  The local read
 * fails for a pinned event that lost its counter; a throttled event
 * stays active but stops.
 */
static u64 kvm_det_count(struct kvm_vcpu *vcpu)
{
	struct kvm_det_vcpu *det = &vcpu->arch.det;
	u64 count = 0, enabled, running;

	if (!det->event)
		return 0;

	if (det->task == current) {
		if (perf_event_read_local(det->event, &count, &enabled, &running)) {
			det->error = true;
			count = 0;
		}
	} else {
		count = perf_event_read_value(det->event, &enabled, &running);
		if (enabled != running)
			det->error = true;
	}
	if (perf_event_is_throttled(det->event))
		det->error = true;
	return count;
}

/* The vCPU's tick count, valid on any thread; zero without the capability. */
u64 kvm_det_ticks(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.det.tick_offset + kvm_det_count(vcpu);
}

int kvm_det_set_ticks(struct kvm_vcpu *vcpu, u64 ticks)
{
	if (!kvm_det_enabled(vcpu->kvm))
		return -ENXIO;
	vcpu->arch.det.tick_offset = ticks - kvm_det_count(vcpu);
	return 0;
}

/*
 * Called before every VM-Entry.  Returns 0 with the run structure filled
 * in if the counter has stopped (a pinned event that lost its counter is
 * in the error state; a throttled one is stopped), else 1.
 */
int kvm_det_pre_run(struct kvm_vcpu *vcpu)
{
	struct kvm_det_vcpu *det = &vcpu->arch.det;
	struct kvm_run *run = vcpu->run;

	if (det->event->state == PERF_EVENT_STATE_ERROR ||
	    perf_event_is_throttled(det->event))
		det->error = true;

	if (likely(!det->error))
		return 1;

	run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	run->internal.suberror = KVM_INTERNAL_ERROR_DET_COUNTER;
	run->internal.ndata = 0;
	return 0;
}

int kvm_det_vcpu_has_attr(struct kvm_vcpu *vcpu, struct kvm_device_attr *attr)
{
	if (!kvm_det_enabled(vcpu->kvm))
		return -ENXIO;

	switch (attr->attr) {
	case KVM_VCPU_DET_TICKS:
		return 0;
	default:
		return -ENXIO;
	}
}

int kvm_det_vcpu_get_attr(struct kvm_vcpu *vcpu, struct kvm_device_attr *attr)
{
	void __user *uaddr = u64_to_user_ptr(attr->addr);
	u64 val;
	int r;

	r = kvm_det_vcpu_has_attr(vcpu, attr);
	if (r)
		return r;

	switch (attr->attr) {
	case KVM_VCPU_DET_TICKS:
		val = kvm_det_ticks(vcpu);
		break;
	default:
		return -ENXIO;
	}
	return put_user(val, (u64 __user *)uaddr) ? -EFAULT : 0;
}

int kvm_det_vcpu_set_attr(struct kvm_vcpu *vcpu, struct kvm_device_attr *attr)
{
	void __user *uaddr = u64_to_user_ptr(attr->addr);
	u64 val;
	int r;

	r = kvm_det_vcpu_has_attr(vcpu, attr);
	if (r)
		return r;

	switch (attr->attr) {
	case KVM_VCPU_DET_TICKS:
		if (get_user(val, (u64 __user *)uaddr))
			return -EFAULT;
		return kvm_det_set_ticks(vcpu, val);
	default:
		return -ENXIO;
	}
}
