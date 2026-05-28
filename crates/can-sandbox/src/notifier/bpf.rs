//! A tiny label-based assembler for classic BPF (seccomp) programs.
//!
//! The notifier prelude (`filter.rs`) used to be a flat allow/USER_NOTIF
//! switch whose jump offsets were a single `remaining + 1` formula. Once
//! the prelude makes *register-based decisions* (deny `SOCK_RAW`, deny
//! `clone` namespace flags, force `clone3` to `ENOSYS`, …) it becomes a
//! multi-clause program, and hand-counted jump offsets stop being
//! auditable. This assembler lets the filter read as labelled clauses:
//!
//! ```ignore
//! let deny = asm.label();
//! asm.ld_abs(OFFSET_NR);
//! asm.jeq(SYS_socket as u32, socket_clause, next);
//! ...
//! asm.mark(deny);
//! asm.ret(RET_ERRNO_EPERM);
//! ```
//!
//! Only forward jumps are supported — seccomp preludes are straight-line
//! decision trees, never loops — and the builder errors if a computed
//! offset cannot be encoded, rather than emitting a silently wrong
//! program.

use super::error::NotifierError;

/// Opaque label handle. Allocate with [`Asm::label`], place with
/// [`Asm::mark`], jump to with the conditional/unconditional emitters.
pub(super) type Label = usize;

enum Item {
    /// A fully-resolved instruction (loads, ALU ops, returns).
    Insn(libc::sock_filter),
    /// Conditional jump with symbolic targets, resolved in `build`.
    Cond {
        code: u16,
        k: u32,
        jt: Label,
        jf: Label,
    },
    /// Unconditional jump (`BPF_JA`) with a symbolic target.
    Jump { target: Label },
    /// Zero-width marker recording where a label resolves to.
    Mark(Label),
}

pub(super) struct Asm {
    items: Vec<Item>,
    next_label: Label,
}

impl Asm {
    pub(super) fn new() -> Self {
        Self {
            items: Vec::new(),
            next_label: 0,
        }
    }

    /// Allocate a fresh, unplaced label.
    pub(super) fn label(&mut self) -> Label {
        let id = self.next_label;
        self.next_label += 1;
        id
    }

    /// Place a previously-allocated label at the current position.
    pub(super) fn mark(&mut self, label: Label) {
        self.items.push(Item::Mark(label));
    }

    /// Load a 32-bit word from `struct seccomp_data` at byte `offset`.
    pub(super) fn ld_abs(&mut self, offset: u32) {
        self.items.push(Item::Insn(libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: offset,
        }));
    }

    /// `A &= mask` (used to mask off `SOCK_NONBLOCK`/`SOCK_CLOEXEC` etc.).
    pub(super) fn alu_and(&mut self, mask: u32) {
        self.items.push(Item::Insn(libc::sock_filter {
            code: (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: mask,
        }));
    }

    /// `if A == k goto jt else goto jf`.
    pub(super) fn jeq(&mut self, k: u32, jt: Label, jf: Label) {
        self.items.push(Item::Cond {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            k,
            jt,
            jf,
        });
    }

    /// `if A & k != 0 goto jt else goto jf`.
    pub(super) fn jset(&mut self, k: u32, jt: Label, jf: Label) {
        self.items.push(Item::Cond {
            code: (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16,
            k,
            jt,
            jf,
        });
    }

    /// Unconditional jump to `target`.
    pub(super) fn ja(&mut self, target: Label) {
        self.items.push(Item::Jump { target });
    }

    /// Emit a `BPF_RET` returning the seccomp action `k`.
    pub(super) fn ret(&mut self, k: u32) {
        self.items.push(Item::Insn(libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k,
        }));
    }

    /// Resolve labels to relative offsets and emit the program.
    ///
    /// Errors (rather than emitting a wrong program) if any jump is
    /// backward, lands on an unplaced label, or exceeds the encodable
    /// offset range (`u8` for conditional jumps).
    pub(super) fn build(self) -> Result<Vec<libc::sock_filter>, NotifierError> {
        // Pass 1: assign each real instruction a program index; record
        // where each label resolves to (the index of the next real insn).
        let mut positions = vec![usize::MAX; self.next_label];
        let mut idx = 0usize;
        for item in &self.items {
            match item {
                Item::Mark(label) => positions[*label] = idx,
                _ => idx += 1,
            }
        }
        let total = idx;

        // Pass 2: emit, computing relative offsets.
        let mut out = Vec::with_capacity(total);
        let mut i = 0usize;
        for item in self.items {
            match item {
                Item::Mark(_) => {}
                Item::Insn(insn) => {
                    out.push(insn);
                    i += 1;
                }
                Item::Cond { code, k, jt, jf } => {
                    let jt_off = relative(jt, i, &positions)?;
                    let jf_off = relative(jf, i, &positions)?;
                    let jt = u8::try_from(jt_off).map_err(|_| offset_err(jt_off))?;
                    let jf = u8::try_from(jf_off).map_err(|_| offset_err(jf_off))?;
                    out.push(libc::sock_filter { code, jt, jf, k });
                    i += 1;
                }
                Item::Jump { target } => {
                    let off = relative(target, i, &positions)?;
                    out.push(libc::sock_filter {
                        code: (libc::BPF_JMP | libc::BPF_JA) as u16,
                        jt: 0,
                        jf: 0,
                        k: off as u32,
                    });
                    i += 1;
                }
            }
        }
        Ok(out)
    }
}

/// Forward offset from the instruction at program index `from` to the
/// instruction `label` resolves to.
fn relative(label: Label, from: usize, positions: &[usize]) -> Result<usize, NotifierError> {
    let target = positions
        .get(label)
        .copied()
        .filter(|p| *p != usize::MAX)
        .ok_or_else(|| NotifierError::InvalidFilter(format!("jump to unplaced label {label}")))?;
    if target <= from {
        return Err(NotifierError::InvalidFilter(format!(
            "non-forward jump from {from} to {target}"
        )));
    }
    Ok(target - from - 1)
}

fn offset_err(off: usize) -> NotifierError {
    NotifierError::InvalidFilter(format!("jump offset {off} exceeds 255"))
}
