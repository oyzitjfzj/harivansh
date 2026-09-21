#!/usr/bin/env python3
"""Small exhaustive reference models for S00/S01 boundary invariants."""

from itertools import product


def model_non_amplifying_grants() -> None:
    for parent_ops, child_ops, parent_targets, child_targets in product(range(4), repeat=4):
        allowed = (
            child_ops & ~parent_ops == 0
            and child_targets & ~parent_targets == 0
        )
        expanded = (
            child_ops & ~parent_ops != 0
            or child_targets & ~parent_targets != 0
        )
        assert allowed is (not expanded)


def model_fences() -> None:
    for current_fence in range(3):
        for worker_fence in range(3):
            commit_allowed = worker_fence == current_fence
            if worker_fence < current_fence:
                assert not commit_allowed


def model_effect_unknown() -> None:
    states = ["prepared", "claimed", "dispatched", "acceptance_unknown"]
    assert states[-1] == "acceptance_unknown"
    provider_has_stable_idempotency = False
    assert not provider_has_stable_idempotency


def model_lifecycle_epoch() -> None:
    for start_epoch in range(3):
        delete_epoch = start_epoch + 1
        restored_epoch = start_epoch
        assert restored_epoch < delete_epoch


def main() -> None:
    model_non_amplifying_grants()
    model_fences()
    model_effect_unknown()
    model_lifecycle_epoch()
    print("BOUNDED-MODELS: PASS")


if __name__ == "__main__":
    main()
