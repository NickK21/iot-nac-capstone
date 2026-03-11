# IoT NAC Capstone

This project implements Network Access Control for IoT environments where devices appear dynamically, trust can change quickly, and every access decision needs to be defensible.

## Problem

IoT networks are difficult to secure with static allowlists and manual review. Devices come and go, identity can be spoofed, and policy decisions often happen without clear auditability. The core problem is not just seeing devices, but deciding which devices should be trusted right now and enforcing that decision reliably.

## What This System Does

The system continuously tracks devices, validates identity, evaluates policy, and records outcomes.

- Maintains a live device inventory with current trust and policy state.
- Verifies signed device heartbeats to distinguish authentic reports from spoofed attempts.
- Handles identity risk conditions such as replay attempts and repeated failed verification.
- Applies allow/deny decisions through an enforcement abstraction layer.
- Persists enforcement decisions and security events as an auditable history.
- Exposes an operator-facing control plane for reviewing device posture and managing policy.

## How Trust Decisions Work

1. Discover: A device is observed and added/updated in inventory.  
2. Verify: The device must pass identity validation before being treated as trusted.  
3. Evaluate: Policy rules decide whether the requested access change is acceptable.  
4. Enforce: The decision is applied through the enforcement layer.  
5. Audit: Identity outcomes, policy decisions, and enforcement actions are recorded.

## Why This Matters

This capstone focuses on the full IoT NAC lifecycle: discovery, identity assurance, policy decisioning, enforcement, and auditability. The value is in turning security decisions into a repeatable, traceable process rather than ad-hoc manual control.
