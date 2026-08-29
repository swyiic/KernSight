//! uprobe 寄存器采集命令行工具。
//!
//! 用法：`uprobectl <pid> <so_path> <offset_hex>`

#[cfg(any(target_os = "android", target_os = "linux"))]
use ksight_hwbp::UprobeSession;

#[cfg(any(target_os = "android", target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("用法: uprobectl <pid> <so_path> <offset_hex>");
        std::process::exit(1);
    }
    let pid: i32 = args[1].parse()?;
    let target = std::path::PathBuf::from(&args[2]);
    let offset = u64::from_str_radix(args[3].trim_start_matches("0x"), 16)?;
    let object = args
        .get(4)
        .cloned()
        .unwrap_or_else(|| "build/bpf/uprobe_regs.bpf.o".to_owned());

    let mut session = UprobeSession::start(
        &std::path::PathBuf::from(object),
        &target,
        offset,
        Some(pid),
        true,
    )?;
    println!("uprobe 已挂载 @ {}+0x{:x}，等待命中...", args[2], offset);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline && !session.finished() {
        match session.poll_hit()? {
            Some(ctx) => {
                println!(
                    "命中: pc=0x{:x} sp=0x{:x} x0=0x{:x} x1=0x{:x} x2=0x{:x} lr=0x{:x}",
                    ctx.pc,
                    ctx.sp,
                    ctx.regs[0],
                    ctx.regs[1],
                    ctx.regs[2],
                    ctx.link_register()
                );
            }
            None => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    if session.finished() {
        println!("已命中并撤离（BRK 已恢复）");
    } else {
        println!("超时结束");
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn main() {
    eprintln!("uprobectl 仅在 Linux/Android 上可用");
    std::process::exit(1);
}
