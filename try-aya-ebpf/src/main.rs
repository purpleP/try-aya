#![no_std]
#![no_main]

use aya_log_ebpf::{trace, error};

use aya_bpf::{
    macros::kprobe,
    helpers::bpf_get_current_comm,
    programs::ProbeContext,
};

#[kprobe(name="do_execveat_common")]
pub fn trace_execve(ctx: ProbeContext) -> u32 {
    match bpf_get_current_comm() {
        Ok(comm) => {
            unsafe {
                let comm = core::mem::transmute::<_, [u8; 16]>(comm);
                let comm = core::str::from_utf8_unchecked(&comm[..]);
                trace!(&ctx, "Executing {}", comm);
            };
        }
        Err(n) => error!(&ctx, "Error reading command {}", n),
    }
    match unsafe { try_try_aya(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_try_aya(_ctx: ProbeContext) -> Result<u32, u32> {
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}
