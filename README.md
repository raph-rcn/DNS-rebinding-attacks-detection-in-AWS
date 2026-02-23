# GuardDuty `MetadataDNSRebind` Triage Script

`gd_metadata_dnsrebind_triage.sh` is a command-line triage tool that gathers AWS evidence to help you decide whether a GuardDuty finding of type:

* `UnauthorizedAccess:EC2/MetadataDNSRebind`

is likely **benign/no impact observed** (e.g., a DNS lookup pattern without exploitation), or **suspicious** (e.g., evidence consistent with credential abuse or an inbound attempt reaching your backend).

This script is designed for repeatable incident response and for producing an evidence bundle (`verdict.json` + raw AWS outputs) you can attach to a ticket.

---

## Background: What is `MetadataDNSRebind`?

GuardDuty raises `UnauthorizedAccess:EC2/MetadataDNSRebind` when an EC2 instance performs DNS lookups that can be used in **DNS rebinding** scenarios targeting the EC2 Instance Metadata Service (IMDS), commonly:

* `169.254.169.254.nip.io`
* `169.254.169.254.sslip.io`

These hostnames resolve to `169.254.169.254`, the link-local IP used by IMDS. In exploitation chains (often SSRF), this can be used to attempt access to instance metadata and potentially retrieve IAM role credentials.

Important nuance:

* GuardDuty detecting this DNS pattern is **not proof** that metadata was accessed, credentials were stolen, or that compromise occurred.
* It is an indicator that warrants verification.

---

## What the script does

The script collects and correlates AWS-side evidence in a defined time window and outputs a verdict:

* `BENIGN_LIKELY`
* `INCONCLUSIVE`
* `SUSPICIOUS`

It performs the following steps:

### 1) EC2 posture and IMDS configuration

Fetches instance details and records relevant configuration:

* Private/Public IP
* VPC/Subnet
* IAM instance profile / role
* IMDS settings:

  * `HttpTokens` (IMDSv2 enforcement)
  * `HttpEndpoint`
  * `HttpPutResponseHopLimit`

Why this matters:

* Enforcing IMDSv2 (`HttpTokens=required`) reduces the risk of classic tokenless metadata access patterns.

### 2) GuardDuty findings for this instance

Retrieves all GuardDuty findings of type:

* `UnauthorizedAccess:EC2/MetadataDNSRebind`

and stores:

* Domain (e.g., `169.254.169.254.nip.io`)
* FirstSeen / LastSeen
* Count
* Severity

### 3) CloudWatch metadata metrics (IMDSv1 usage signals)

Queries per-instance CloudWatch metrics in your chosen time window:

* `MetadataNoToken`
* `MetadataNoTokenRejected`

Interpretation:

* A value > 0 suggests tokenless metadata requests (IMDSv1 behavior) were attempted or rejected.
* A value of 0 / no datapoints suggests no evidence of IMDSv1-style metadata calls in that window.

### 4) CloudTrail evidence for the instance session

Queries CloudTrail for events where:

* `Username == <instance-id>`

This catches API calls made using the EC2 role session name that is often the instance ID.

It flags suspicious patterns such as:

* IAM or STS activity (role/policy changes, token operations)
* EC2 network/security mutations (security group ingress changes, ENI changes, etc.)
* Potentially risky S3 operations (depending on your environment)

It also checks whether SSM activity appears to come from the expected NAT egress (when available), which is useful to rule out “role used from an unexpected source.”

### 5) Network exposure context

Collects:

* Security group rules and whether any inbound rule allows `0.0.0.0/0` or `::/0`
* Subnet route table
* NAT gateway ID and public EIP (if present)

This helps determine if the instance is directly internet reachable and helps interpret CloudTrail `sourceIPAddress`.

### 6) Load balancer discovery and ALB access-log scanning (key step)

If the instance is behind an **internet-facing** ALB, the script attempts to prove whether any inbound requests during the window carried the typical rebinding/IMDS indicators.

Process:

1. Identifies ALBs that route to the instance (via target groups), matching by:

   * instance ID (target type `instance`)
   * private IP (target type `ip`)
2. Selects internet-facing ALBs.
3. Checks whether ALB access logs are enabled and where they are stored in S3.
4. Downloads only the ALB log objects overlapping your time window (5-minute slices).
5. Decompresses and searches for the indicator strings:

   * `nip.io`
   * `sslip.io`
   * `169.254.169.254`
6. Runs the search twice:

   * Across all lines
   * Only on lines routed to the instance’s private IP (target correlation)

If an internet-facing ALB exists but logs cannot be downloaded or found for the window, the script fails closed and returns `INCONCLUSIVE`.

### 7) WAF association (informational)

Checks whether AWS WAFv2 is associated with the ALB:

* `WebACL=null` indicates no WAF attached.
* WAF presence does not change the verdict on its own; it is included as context.

### 8) Verdict computation

The verdict is computed conservatively:

* `SUSPICIOUS` if any of the following are true:

  * Evidence of IMDSv1 usage/rejection (`MetadataNoToken`/`MetadataNoTokenRejected` > 0)
  * Security group inbound is open to the world (`0.0.0.0/0` or `::/0`)
  * Suspicious CloudTrail activity for the instance session
  * ALB logs contain indicator hits (especially those routed to the target instance)

* `INCONCLUSIVE` if:

  * An internet-facing ALB exists but the script cannot obtain logs for the window (permissions/log delivery delay/prefix mismatch), or
  * Any required evidence cannot be collected.

* `BENIGN_LIKELY` if:

  * IMDSv2 is enforced and no IMDSv1 evidence appears in metrics, and
  * CloudTrail does not show suspicious instance-session activity, and
  * If internet-facing ALBs exist: ALB logs were successfully scanned and produced zero indicator hits.

---

## What the script does **not** do

This tool is intentionally AWS-telemetry-based. It does **not**:

* Prove your application is not vulnerable to SSRF or URL injection.
* Inspect the host filesystem, running processes, or application logs on the EC2 instance.
* Decode or detect obfuscated metadata targets (e.g., URL-encoded IPs, alternate IP representations, different rebinding domains). It searches only for the literal indicators listed above.
* Fully detect role credential abuse where stolen credentials are used with a **different session name** than the instance ID (depending on how your environment/session naming works). It focuses on the strongest and most common AWS signal path, but it is not a complete “all possible role usage everywhere” audit.

Because of these limits, `BENIGN_LIKELY` should be read as:

> “No impact observed based on the AWS signals collected by this script.”

---

## Requirements

* **AWS CLI v2** with permissions to read:

  * EC2 instance details
  * GuardDuty findings
  * CloudWatch metrics
  * CloudTrail events
  * ELBv2 target groups / target health / ALB attributes
  * S3 ALB access logs (read-only)
  * WAFv2 association status (optional)
* `jq`
* `python3`
* `gunzip` (gzip)

Recommended:

* Set `AWS_PAGER=""` to avoid interactive paging:

  ```bash
  export AWS_PAGER=""
  ```

---

## Installation

1. Save the script as `gd_metadata_dnsrebind_triage.sh`.
2. Make it executable:

   ```bash
   chmod +x gd_metadata_dnsrebind_triage.sh
   ```

---

## Usage

### Basic usage (event time + window)

```bash
./gd_metadata_dnsrebind_triage.sh \
  -r eu-west-1 \
  -d <GUARDDUTY_DETECTOR_ID> \
  -i <INSTANCE_ID> \
  -t 2026-02-23T12:07:03Z \
  -w 10
```

* `-t` is the event time in UTC (ISO 8601).
* `-w` is the window in minutes on each side of `-t`.

  * Example: `-w 10` scans from `t-10m` to `t+10m`.

### Provide an explicit time window

```bash
./gd_metadata_dnsrebind_triage.sh \
  -r eu-west-1 \
  -d <GUARDDUTY_DETECTOR_ID> \
  -i <INSTANCE_ID> \
  --start 2026-02-23T11:55:00Z \
  --end   2026-02-23T12:20:00Z
```

### Scan only a specific ALB DNS name

If the instance is behind multiple internet-facing ALBs:

```bash
./gd_metadata_dnsrebind_triage.sh \
  -r eu-west-1 \
  -d <GUARDDUTY_DETECTOR_ID> \
  -i <INSTANCE_ID> \
  -t 2026-02-23T12:07:03Z \
  -w 10 \
  --alb-dns app-example-prod-123456.eu-west-1.elb.amazonaws.com
```

---

## Output

Each run creates a new folder like:

```
gd_dnsrebind_triage_<instance-id>_<timestamp>/
```

Key files:

* `verdict.json` — machine-readable summary and verdict
* `describe_instance.json` — raw EC2 instance details
* `rebind_findings.json` — GuardDuty rebinding findings
* `cw_MetadataNoToken_window.json` and `cw_MetadataNoTokenRejected_window.json` — CloudWatch evidence
* `ct_username_instance.json` — CloudTrail evidence for instance session
* `instance_lbs_uniq.jsonl` — discovered ALBs routing to the instance
* `alb_logs_<LB_ID>/...` — downloaded ALB access logs (if scanned)

The script prints a final line like:

```
[+] VERDICT: BENIGN_LIKELY
```

Exit codes:

* `0` — `BENIGN_LIKELY`
* `1` — `SUSPICIOUS`
* `3` — `INCONCLUSIVE`

---

## Performance notes

ALB log scanning can be expensive.

Why:

* ALB logs are delivered in 5-minute slices.
* Each slice may produce multiple files (multiple load balancer nodes).
* Decompressing and scanning many `.gz` logs can take significant time and disk space.

Recommendation:

* Use small windows (e.g., `-w 5` or `-w 10`) aligned to the GuardDuty finding `LastSeen`.
* Only widen if needed.

---

## Interpreting results

### `BENIGN_LIKELY`

Meaning:

* No AWS evidence of IMDSv1 metadata exploitation,
* No suspicious instance-session CloudTrail activity,
* No inbound ALB log indicators associated with the rebinding domains/IP in the scanned window.

Recommended action:

* Downgrade to low severity / informational, attach `verdict.json` to the ticket.
* Consider hardening IMDS hop limit and SSRF protections if not already in place.

### `SUSPICIOUS`

Meaning:

* At least one strong signal exists (IMDSv1 evidence, open ingress, suspicious CloudTrail activity, or ALB indicator hits).

Recommended action:

* Treat as an incident: deeper investigation in application logs, WAF logs (if any), VPC DNS logs, host telemetry, and credential rotation if warranted.

### `INCONCLUSIVE`

Meaning:

* The tool could not collect enough evidence (common causes: missing permissions, ALB logs unavailable/delayed, unexpected S3 prefix, no CloudTrail access).

Recommended action:

* Fix permissions/log delivery and rerun.
* Manually inspect the missing components.

---

## Security and privacy

This tool downloads and scans ALB access logs that can contain:

* client IPs
* request paths and user agents
* sometimes query strings (depending on your app)

Handle the output directory as sensitive incident-response data.

---

## License

Add your preferred license here (e.g., MIT/Apache-2.0) before publishing.
