//! The plan: every candidate with the guard's verdict and whether it is selected
//! (DESIGN §3.2, §5.1). This is what the UI shows and what `uninstall` executes.

use crate::candidate::{Candidate, Confidence};
use crate::discovery::Scan;
use crate::guard::{Guard, Rejection, Verified};

#[derive(Debug, Clone, Copy, Default)]
pub struct PlanOptions {
    /// Select low-confidence (name-only) matches as well.
    pub include_low: bool,
}

#[derive(Debug, Clone)]
pub struct PlanItem {
    pub candidate: Candidate,
    pub verdict: Result<Verified, Rejection>,
    pub selected: bool,
    /// Owned by another user (usually root): must be moved by the privileged step.
    pub needs_root: bool,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub items: Vec<PlanItem>,
}

impl Plan {
    /// `uid` is the user running maczap: items it does not own need root.
    pub fn new(scan: &Scan, guard: &Guard, options: PlanOptions, uid: u32) -> Self {
        let items = scan
            .candidates
            .iter()
            .map(|candidate| {
                let verdict = guard.verify(candidate.clone());
                let selected = verdict.is_ok()
                    && match candidate.confidence {
                        Confidence::High | Confidence::Curated => true,
                        Confidence::Low => options.include_low,
                        Confidence::Shared => false,
                    };
                let needs_root = verdict.as_ref().is_ok_and(|v| v.fingerprint().uid != uid);
                PlanItem {
                    candidate: candidate.clone(),
                    verdict,
                    selected,
                    needs_root,
                }
            })
            .collect();
        Plan { items }
    }

    /// Changes the selection of one item. Returns whether the item is now in the
    /// requested state; rejected items can never be selected.
    pub fn set_selected(&mut self, index: usize, selected: bool) -> bool {
        let Some(item) = self.items.get_mut(index) else {
            return false;
        };
        if selected && item.verdict.is_err() {
            return false;
        }
        item.selected = selected;
        true
    }

    pub fn selected(&self) -> impl Iterator<Item = &PlanItem> {
        self.items.iter().filter(|i| i.selected)
    }
}
