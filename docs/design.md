# IoT NAC — Design Outline

## Goal
Build a small-scale Network Access Control for IoT environments:
- Discover devices on a local LAN
- Identify devices with privacy-preserving IDs
- Allow/deny devices from a dashboard
- Enforce policy as a proof-of-concept


## Architecture (MVP)
React Dashboard -> NestJS API -> (Discovery + Policy) -> SQLite 

## Network Discovery Plan
### Phase 1: ARP/Neighbor discovery
- Gather IP/MAC pairs using ARP/neigh table
- Normalize device records and deduplicate by MAC-derived ID
- Update `lastSeen` when observed again

### Phase 2: ICMP-assisted sweep
- Ping subnet range to populate ARP cache
- Re-read neighbor table to capture additional hosts
- Use rate limiting to avoid flooding

## Privacy-Preserving Identity
- Raw MAC is treated as sensitive metadata.
- Device ID = HMAC-SHA256(secret, MAC)
- Store/display only:
  - hashed device_id
  - vendor (OUI lookup)
  - hostname (if available)
  - lastSeen
  - state (allowed/denied/unknown)

## Policy + Enforcement Plan
### Phase 1: simulated enforcement
- Deny -> record an enforcement event + show status in UI
- Proves lifecycle without requiring root privileges

### Phase 2: firewall proof-of-concept 
- Apply iptables/nftables rules on host to block a denied device
- Safety:
  - explicit opt-in config
  - dry-run mode
  - reversible rule removal

## Risks/Constraints
- Real firewall manipulation may require root and is OS-dependent
- Docker networking may require host networking for discovery/enforcement
- Vendor detection is best-effort 

## Demo flow target
1. Run scan
2. Device appears
3. Mark denied
4. Enforcement triggers (simulated or real)
5. UI + logs update