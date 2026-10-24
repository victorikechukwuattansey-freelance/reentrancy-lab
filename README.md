# Reentrancy Lab — Findings & Remediations

Three reentrancy variants, each with a working exploit proof-of-concept, a
fix, and a regression test proving normal operation is preserved.

**9 tests, all passing** (`forge test`).

## Why three findings, not one

Reentrancy is not a single bug. It is a class of bugs defined by **which state
is inconsistent, at what moment, and who can observe it**. The DAO exploit
(2016) is one shape. Cross-function reentrancy is another. Read-only reentrancy
— the current frontier — is a third.

A reader who knows the classic shape and stops there will miss the other two.
This repo is arranged so each finding can be read independently, and each
builds on a **different** assumption about what "reentrancy" means.

---

## Scope

| Contract | File | Tests |
| :--- | :--- | :--- |
| `VaultSameFunction` | `src/vulnerable/VaultSameFunction.sol` | `test/SameFunction.t.sol` |
| `VaultCrossFunction` | `src/vulnerable/VaultCrossFunction.sol` | `test/CrossFunction.t.sol` |
| `LendingReadOnly` | `src/vulnerable/LendingReadOnly.sol` | `test/ReadOnly.t.sol` |
| `VaultCEI` (F1 fix) | `src/fixed/VaultCEI.sol` | — |
| `VaultGlobalGuard` (F2 fix) | `src/fixed/VaultGlobalGuard.sol` | — |
| `LendingGuard` (F3 fix) | `src/fixed/LendingGuard.sol` | — |

Run all tests:

```bash
forge test -vv
```

---

## Finding 1 — Same-function reentrancy (Critical)

**Contract:** `VaultSameFunction.sol`

### Root cause

The state update `balances[msg.sender] = 0` sits **after** the external call
`msg.sender.call{value: bal}("")`. The EVM suspends `withdraw` at the `call`
and hands control to the recipient. If the recipient re-enters `withdraw`,
the balance is still unchanged — the second call sees the same value and
pays out again.

### Reproducer

```solidity
// src/vulnerable/VaultSameFunction.sol — the vulnerable line ordering
(bool ok, ) = msg.sender.call{value: bal}("");   // ← callback fires here
require(ok, "send failed");
balances[msg.sender] = 0;                        // ← too late
```

`test_ExploitDrains` deposits 1 ETH, calls `withdraw()`, and re-enters from
`receive()` until the vault is empty. The attacker starts with 1 ETH and ends
with **16 ETH** (their deposit + 15 ETH stolen from two victims). The
`reentryCount()` assertion confirms 15 recursive calls.

Call trace:

```
VaultSameFunction::withdraw
  └─ SameFunctionAttacker::receive
      └─ VaultSameFunction::withdraw
          └─ SameFunctionAttacker::receive
              └─ ... (15 levels)
```

### Impact

Full vault drain. This is the DAO's mechanism, and it is the reason
`ReentrancyGuard` exists as an OpenZeppelin primitive today.

### Remediation

`VaultCEI.sol` applies Checks-Effects-Interactions: zero the balance **before**
the external call. A reentrant `withdraw` finds `balances[msg.sender] == 0` and
reverts with `"no balance"`. The inner revert propagates to `ok == false`, the
outer `require(ok)` fires, the whole attack unwinds.

The fix is two lines reordered. No new state, no new modifier. **The fix
removes the time window during which state is inconsistent** — that is the
entire discipline.

### Retest

- `test_FixedBlocksExploit` — same attacker, redeployed against `VaultCEI`,
  `vm.expectRevert()` on `attack()`. Vault holds 15 ETH, all claims intact.
- `test_NormalOperationStillWorks` — victim1 withdraws normally, receives
  10 ETH, vault balance drops to 5 (victim2's deposit untouched).

---

## Finding 2 — Cross-function reentrancy (High)

**Contract:** `VaultCrossFunction.sol`

### Root cause

The contract has a **local** reentrancy guard on `withdraw`:

```solidity
bool private _withdrawing;

function withdraw() external {
    require(!_withdrawing, "reentrant");
    _withdrawing = true;
    // ... call, then balances[msg.sender] = 0, then _withdrawing = false
}

function transfer(address to, uint256 amount) external {   // ← NOT guarded
    require(balances[msg.sender] >= amount, "insufficient");
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```

`transfer` touches the same `balances` mapping but is **not guarded by
`_withdrawing`**. During the `withdraw` callback, the attacker calls
`transfer(accomplice, amount)`, which moves their still-unzeroed balance to
a second address. The outer `withdraw` then zeroes the original balance —
**but the accomplice now holds a claim the vault has already paid out**.

### Reproducer

`test_ExploitDuplicatesClaim` — victim deposits 10 ETH, attacker deposits
1 ETH and attacks. The local guard on `withdraw` **fires correctly** (the
attacker's `receive()` cannot re-enter `withdraw`), but the attacker re-enters
`transfer` instead. The vault ends up with 10 ETH against 11 ETH in claims —
**insolvent by exactly the attacker's deposit**.

The smoking gun: accomplice can withdraw their 1 ETH; the victim cannot,
because the vault is short.

### Impact

Accounting corruption. The attacker didn't drain the vault directly — they
duplicated their own claim against other users' deposits, and the loss falls
on whichever victim unstakes last.

This finding is the reason **"I use `nonReentrant`" is a starting point, not a
finish line.** The guard protects a function; it does not protect the state
that function touches.

### Remediation

`VaultGlobalGuard.sol` applies `nonReentrant` (OZ's guard) to **every**
external function that reads or writes `balances`: `deposit`, `withdraw`,
`transfer`. A reentrant `transfer` from the callback now reverts with
`ReentrancyGuardReentrantCall`; the outer `withdraw` fails and the whole
attack unwinds.

CEI on `withdraw` is also applied as defense-in-depth, but the guard on
`transfer` is the actual fix — CEI alone would still leave `transfer`
callable from the callback, which is a different correctness problem.

### Retest

- `test_FixedBlocksCrossFunctionExploit` — same attacker, targeted at
  `VaultGlobalGuard`, `vm.expectRevert()`. Vault holds 10 ETH, no dup claim.
- `test_FixedNormalOperationStillWorks` — transfer and withdraw both work
  normally for legitimate users.

---

## Finding 3 — Read-only reentrancy (Medium)

**Contract:** `LendingReadOnly.sol`

### Root cause

`borrow` updates `debt` **before** the external call. During the callback,
`healthFactor` is a public view function that any integrator can read. The
borrower is not yet in a healthy position — the compensating deposit (that
would restore the health factor) hasn't run yet.

A keeper bot subscribed to state changes reads `healthFactor` during the
callback, sees an unhealthy position, and **liquidates**. The borrower loses
all collateral — even though they were about to deposit enough to stay healthy
in the same transaction.

```solidity
function borrow(uint256 amount) external {
    require(healthFactor(msg.sender) >= 1e18, "unhealthy pre-borrow");
    debt[msg.sender] += amount;                    // ← state updated here

    (bool ok, ) = msg.sender.call{value: amount}("");  // ← callback: healthFactor is temporarily low
    require(ok, "borrow failed");
}
```

### Why this is different from Findings 1 and 2

| | Attacker writes state? | Attacker reads state? | Victim |
| :--- | :--- | :--- | :--- |
| F1 — Same-function | yes (reentrant withdraw) | yes | vault depositors |
| F2 — Cross-function | yes (via unguarded `transfer`) | yes | other depositors |
| **F3 — Read-only** | **no** | yes | a **third party** (borrower) via an **integrator** (keeper) |

In Finding 3, the lending contract's own state is coherent at every step. The
failure is in the **consumer** of that state — the keeper reads a number that
is correct-per-the-contract but wrong-per-the-transaction, and acts on it.

### Reproducer

`test_ExploitLiquidatesDuringCallback` — borrower deposits 200 ETH, borrows
100 ETH (HF = 3.0, healthy). Then borrows 200 ETH more. During the callback:

- `debt` has been incremented from 100 → 300
- `collateral` is still 200 (the compensating 200 deposit hasn't run)
- `healthFactor = 200 × 1e18 / 300 = 0.667e18 < 1.2e18 THRESHOLD`

The keeper reads HF = 0.667, calls `liquidate`, seizes 200 ETH of collateral.
Then the callback continues and the borrower's deposit runs — but the position
is already closed and the collateral gone.

Loss to the borrower: their entire collateral position. The keeper gained
200 ETH. No state was written by the attacker.

### Remediation

`LendingGuard.sol` adds `nonReentrant` to `liquidate` and `borrow`. During
`borrow`'s callback, `_status == ENTERED`, so `liquidate` reverts with
`ReentrancyGuardReentrantCall`. The revert propagates:
`liquidate` → `Keeper.checkAndLiquidate` → `Borrower.receive` → `borrow`'s
callback → `require(ok)` → the borrow itself reverts.

The mid-state is no longer **observable by a mutating integrator** — because
the integrator can't enter while the target is mid-transition.

### What this fix does not cover

`nonReentrant` on `liquidate` blocks integrators that **call back into the
lending contract**. It does **not** block integrators that read `healthFactor`
during a callback and act in a **separate transaction** (an oracle-based
liquidator submitting their own tx in the next block).

For that pattern, no in-contract fix exists — the borrower would have to
accept that `healthFactor` is an unsafe reading during callbacks, and the
integrator would have to respect that. The mitigations are:

1. **Documentation** — integrators must not read `healthFactor` during a
   callback (fragile: relies on the integrator's discipline)
2. **Read-your-writes view** — a second view function that reflects in-flight
   state, with the assumption that integrators know to use it
3. **Snapshot discipline** — the lending contract emits an event after each
   state transition, and integrators read from events, not live state

The honest answer is: **Finding 3's fix is a partial mitigation, not a
complete one.** The complete fix requires an integrator-side discipline that
the contract cannot enforce. That boundary belongs in the audit report, not
under the rug.

### Retest

- `test_FixedBlocksLiquidationDuringCallback` — same borrower and keeper,
  targeted at `LendingGuard`. Borrow reverts; collateral unchanged.
- `test_FixedNormalBorrowsStillWork` — two consecutive normal borrows succeed
  without triggering the guard.

---

## Cross-cutting lessons

### 1. The EVM call stack is the attack surface

Every `call` transfers control. Every transfer of control shares state. Every
shared state is potentially inconsistent at the moment of the transfer.
Reentrancy is the consequence of these three facts together.

The fix is not a template. The fix is a **model of what state is inconsistent,
for how long, and who can observe it**. For F1, the window is closed by
reordering. For F2, the window is closed by widening the guard. For F3, the
window is closed by blocking one specific observer.

### 2. Local guards are not global invariants

`nonReentrant` on `withdraw` in Finding 2 is correct code. It fires. It blocks
what it was designed to block. The vulnerability exists because **another
function** reaches the same state. The question to ask is not "did I guard
this function?" but "which functions can reach the state I'm leaving
inconsistent?"

### 3. Reentrancy without re-entry

Finding 3 is reentrancy without a state-modifying re-entry. No attacker state
is written. The attack is a read of a view function at the wrong time. This is
the frontier of reentrancy research, and most "I use `nonReentrant`" answers
don't cover it.

### 4. Every fix needs a regression test

Each finding has a `test_NormalOperationStillWorks`-style test. A fix that
blocks the exploit but breaks legitimate use is a bug, just a quieter one. The
regression test is what turns "the exploit reverts" into "the exploit reverts
and the product still works."

---

## Repository structure

```
src/
├── vulnerable/            ← the three exploit targets
│   ├── VaultSameFunction.sol
│   ├── VaultCrossFunction.sol
│   └── LendingReadOnly.sol
├── attack/                ← attacker contracts, one per finding
│   ├── SameFunctionAttacker.sol
│   ├── CrossFunctionAttacker.sol
│   ├── Borrower.sol
│   └── Keeper.sol
└── fixed/                 ← the three remediations
    ├── VaultCEI.sol
    ├── VaultGlobalGuard.sol
    └── LendingGuard.sol
test/
├── SameFunction.t.sol     ← exploit + fix + regression
├── CrossFunction.t.sol    ← exploit + fix + regression
└── ReadOnly.t.sol         ← exploit + fix + regression
```

## Reproduction

```bash
forge test -vv
```

Expected: **9 passed, 0 failed**.

```bash
# Individual findings
forge test --match-contract SameFunctionTest -vv
forge test --match-contract CrossFunctionTest -vv
forge test --match-contract ReadOnlyTest -vv
```

## Continuous integration

`.github/workflows/test.yml` runs:

```yaml
- forge fmt --check
- forge build
- forge test -vv
```

Every finding's exploit, fix, and regression test runs on every push.

## License

MIT
