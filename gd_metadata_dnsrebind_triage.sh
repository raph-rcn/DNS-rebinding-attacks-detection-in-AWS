#!/usr/bin/env bash
# gd_metadata_dnsrebind_triage.sh (v2)
#
# Goal:
#   Gather AWS evidence to classify GuardDuty UnauthorizedAccess:EC2/MetadataDNSRebind
#   as: BENIGN_LIKELY / INCONCLUSIVE / SUSPICIOUS
#
# Key signals:
#   - IMDSv1 CloudWatch metrics (MetadataNoToken / MetadataNoTokenRejected)
#   - CloudTrail: instance session + role usage (public IP anomalies / risky API)
#   - Internet-facing ALB: access log grep for nip.io/sslip.io/169.254.169.254 (and routed-to-target-IP)
#
# Requires:
#   aws, jq, python3, gunzip

set -u

err(){ echo "[!] $*" >&2; }
info(){ echo "[*] $*"; }
ok(){ echo "[+] $*"; }

need_cmd(){ command -v "$1" >/dev/null 2>&1 || { err "Missing dependency: $1"; exit 2; }; }

json_event() {
  # Takes CloudTrailEvent (string or object) and normalizes to object.
  jq -c 'if type=="string" then fromjson else . end'
}

iso_math() {
  python3 - "$1" "$2" <<'PY'
import sys
from datetime import datetime, timedelta, timezone
iso = sys.argv[1].replace("Z","+00:00")
delta = int(sys.argv[2])
dt = datetime.fromisoformat(iso).astimezone(timezone.utc)
dt2 = dt + timedelta(minutes=delta)
print(dt2.strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
}

iso_to_ymd() {
  python3 - "$1" <<'PY'
import sys
from datetime import datetime, timezone
iso = sys.argv[1].replace("Z","+00:00")
dt = datetime.fromisoformat(iso).astimezone(timezone.utc)
print(dt.strftime("%Y/%m/%d"))
PY
}

make_5min_marks() {
  python3 - "$1" "$2" <<'PY'
import sys
from datetime import datetime, timedelta, timezone
s = datetime.fromisoformat(sys.argv[1].replace("Z","+00:00")).astimezone(timezone.utc)
e = datetime.fromisoformat(sys.argv[2].replace("Z","+00:00")).astimezone(timezone.utc)

def floor5(dt):
  m = (dt.minute // 5) * 5
  return dt.replace(minute=m, second=0, microsecond=0)
def ceil5(dt):
  add = (5 - (dt.minute % 5)) % 5
  dt2 = dt + timedelta(minutes=add)
  return dt2.replace(second=0, microsecond=0)

cur = floor5(s)
end = ceil5(e)
seen=set()
while cur <= end:
  seen.add(cur.strftime("%Y%m%dT%H%MZ"))
  cur += timedelta(minutes=5)
for x in sorted(seen):
  print(x)
PY
}

# Conservative helpers
is_aws_service_principal() {
  # Matches e.g. "sqs.amazonaws.com"
  [[ "$1" =~ \.amazonaws\.com$ ]]
}

is_private_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^10\. ]] && return 0
  [[ "$ip" =~ ^192\.168\. ]] && return 0
  [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
  return 1
}

############################
# Args
############################
REGION=""
DETECTOR_ID=""
INSTANCE_ID=""
EVENT_TIME=""
START=""
END=""
WINDOW_MIN=90
WORKDIR=""
ALB_DNS=""

usage(){
  cat <<EOF
Usage:
  $0 -r <region> -d <guardduty_detector_id> -i <instance_id> [-t <event_time_utc>] [-w <minutes>] [--start <iso>] [--end <iso>]
     [--alb-dns <dnsname>] [--workdir <path>]

Example:
  $0 -r eu-west-1 -d <detector> -i <instance> -t 2026-02-23T12:07:03Z -w 90
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -r) REGION="$2"; shift 2;;
    -d) DETECTOR_ID="$2"; shift 2;;
    -i) INSTANCE_ID="$2"; shift 2;;
    -t) EVENT_TIME="$2"; shift 2;;
    -w) WINDOW_MIN="$2"; shift 2;;
    --start) START="$2"; shift 2;;
    --end) END="$2"; shift 2;;
    --alb-dns) ALB_DNS="$2"; shift 2;;
    --workdir) WORKDIR="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) err "Unknown arg: $1"; usage; exit 2;;
  esac
done

if [ -z "$REGION" ] || [ -z "$DETECTOR_ID" ] || [ -z "$INSTANCE_ID" ]; then
  err "Missing required args."
  usage
  exit 2
fi

need_cmd aws
need_cmd jq
need_cmd python3
need_cmd gunzip

if [ -n "$START" ] && [ -n "$END" ]; then
  :
else
  if [ -z "$EVENT_TIME" ]; then
    EVENT_TIME="$(python3 - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)"
    ok "No --start/--end or -t provided; defaulting EVENT_TIME=$EVENT_TIME (now UTC)"
  fi
  START="$(iso_math "$EVENT_TIME" "-$WINDOW_MIN")"
  END="$(iso_math "$EVENT_TIME" "$WINDOW_MIN")"
fi

if [ -z "${WORKDIR:-}" ]; then
  TS="$(python3 - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
PY
)"
  WORKDIR="./gd_dnsrebind_triage_${INSTANCE_ID}_${TS}"
fi
mkdir -p "$WORKDIR"
ok "Workdir: $WORKDIR"
info "Window: START=$START  END=$END"

############################
# 1) Instance posture
############################
info "EC2: describe-instances..."
aws ec2 describe-instances \
  --region "$REGION" \
  --instance-ids "$INSTANCE_ID" \
  --output json > "$WORKDIR/describe_instance.json"

PRIVATE_IP="$(jq -r '.Reservations[0].Instances[0].PrivateIpAddress // empty' "$WORKDIR/describe_instance.json")"
PUBLIC_IP="$(jq -r '.Reservations[0].Instances[0].PublicIpAddress // empty' "$WORKDIR/describe_instance.json")"
VPC_ID="$(jq -r '.Reservations[0].Instances[0].VpcId // empty' "$WORKDIR/describe_instance.json")"
SUBNET_ID="$(jq -r '.Reservations[0].Instances[0].SubnetId // empty' "$WORKDIR/describe_instance.json")"
HTTP_TOKENS="$(jq -r '.Reservations[0].Instances[0].MetadataOptions.HttpTokens // empty' "$WORKDIR/describe_instance.json")"
HTTP_ENDPOINT="$(jq -r '.Reservations[0].Instances[0].MetadataOptions.HttpEndpoint // empty' "$WORKDIR/describe_instance.json")"
HOP_LIMIT="$(jq -r '.Reservations[0].Instances[0].MetadataOptions.HttpPutResponseHopLimit // empty' "$WORKDIR/describe_instance.json")"
PROFILE_ARN="$(jq -r '.Reservations[0].Instances[0].IamInstanceProfile.Arn // empty' "$WORKDIR/describe_instance.json")"

ok "Instance: PrivateIp=${PRIVATE_IP:-N/A} PublicIp=${PUBLIC_IP:-none}"
ok "IMDS: HttpTokens=${HTTP_TOKENS:-N/A} HttpEndpoint=${HTTP_ENDPOINT:-N/A} HopLimit=${HOP_LIMIT:-N/A}"

ROLE_NAME=""
if [ -n "$PROFILE_ARN" ]; then
  PROFILE_NAME="${PROFILE_ARN##*/}"
  aws iam get-instance-profile \
    --instance-profile-name "$PROFILE_NAME" \
    --output json > "$WORKDIR/instance_profile.json"
  ROLE_NAME="$(jq -r '.InstanceProfile.Roles[0].RoleName // empty' "$WORKDIR/instance_profile.json")"
  ok "Instance profile: $PROFILE_NAME  Role: ${ROLE_NAME:-N/A}"
else
  err "No instance profile on instance."
fi

############################
# 2) GuardDuty MetadataDNSRebind findings
############################
info "GuardDuty: list-findings (MetadataDNSRebind)..."
aws guardduty list-findings \
  --region "$REGION" \
  --detector-id "$DETECTOR_ID" \
  --finding-criteria "{
    \"Criterion\": {
      \"resource.instanceDetails.instanceId\": {\"Eq\": [\"$INSTANCE_ID\"]},
      \"type\": {\"Eq\": [\"UnauthorizedAccess:EC2/MetadataDNSRebind\"]},
      \"service.archived\": {\"Eq\": [\"false\"]}
    }
  }" \
  --query 'FindingIds' --output text | tr '\t' '\n' > "$WORKDIR/rebind_finding_ids.txt"

REBIND_COUNT="$(wc -l < "$WORKDIR/rebind_finding_ids.txt" | tr -d ' ')"
ok "Rebind finding IDs: $REBIND_COUNT"

if [ "$REBIND_COUNT" -gt 0 ]; then
  IDS_ARGS="$(tr '\n' ' ' < "$WORKDIR/rebind_finding_ids.txt")"
  aws guardduty get-findings \
    --region "$REGION" \
    --detector-id "$DETECTOR_ID" \
    --finding-ids $IDS_ARGS \
    --output json > "$WORKDIR/rebind_findings.json"
fi

############################
# 3) CloudWatch IMDS metrics
############################
info "CloudWatch: MetadataNoToken / MetadataNoTokenRejected..."
for M in MetadataNoToken MetadataNoTokenRejected; do
  aws cloudwatch get-metric-statistics \
    --region "$REGION" \
    --namespace AWS/EC2 \
    --metric-name "$M" \
    --dimensions Name=InstanceId,Value="$INSTANCE_ID" \
    --statistics Sum \
    --period 300 \
    --start-time "$START" \
    --end-time "$END" \
    --output json > "$WORKDIR/cw_${M}_window.json"
done

############################
# 4) CloudTrail: instance session (Username == instance-id)
############################
info "CloudTrail: lookup-events Username == instance-id..."
aws cloudtrail lookup-events \
  --region "$REGION" \
  --lookup-attributes AttributeKey=Username,AttributeValue="$INSTANCE_ID" \
  --start-time "$START" \
  --end-time "$END" \
  --max-results 200 \
  --output json > "$WORKDIR/ct_username_instance.json" || echo '{"Events":[]}' > "$WORKDIR/ct_username_instance.json"

############################
# 5) SG + Routing + NAT
############################
info "EC2: describe-security-groups..."
SG_IDS="$(jq -r '.Reservations[0].Instances[0].SecurityGroups[].GroupId' "$WORKDIR/describe_instance.json" | tr '\n' ' ')"
if [ -n "${SG_IDS// /}" ]; then
  aws ec2 describe-security-groups \
    --region "$REGION" \
    --group-ids $SG_IDS \
    --output json > "$WORKDIR/describe_sgs.json"
fi

info "EC2: describe-route-tables (subnet assoc)..."
aws ec2 describe-route-tables \
  --region "$REGION" \
  --filters Name=association.subnet-id,Values="$SUBNET_ID" \
  --output json > "$WORKDIR/describe_route_tables.json" || echo '{}' > "$WORKDIR/describe_route_tables.json"

NAT_ID="$(jq -r '.RouteTables[0].Routes[]? | select(.DestinationCidrBlock=="0.0.0.0/0") | .NatGatewayId // empty' "$WORKDIR/describe_route_tables.json" | head -n 1)"
NAT_EIP=""
if [ -n "$NAT_ID" ]; then
  aws ec2 describe-nat-gateways \
    --region "$REGION" \
    --nat-gateway-ids "$NAT_ID" \
    --output json > "$WORKDIR/describe_nat.json"
  NAT_EIP="$(jq -r '.NatGateways[0].NatGatewayAddresses[0].PublicIp // empty' "$WORKDIR/describe_nat.json")"
  ok "NAT: $NAT_ID  EIP=${NAT_EIP:-N/A}"
fi

############################
# 6) ALB discovery (FIXED) + ALB access log scan (fail-closed)
############################
info "ELBv2: find target groups in VPC and determine if instance is a target..."
aws elbv2 describe-target-groups \
  --region "$REGION" \
  --query "TargetGroups[?VpcId=='$VPC_ID'].[TargetGroupArn,TargetType,LoadBalancerArns]" \
  --output json > "$WORKDIR/tgs.json" 2>/dev/null || echo '[]' > "$WORKDIR/tgs.json"

# Collect LB ARNs that actually route to this instance (by instance id or private ip)
: > "$WORKDIR/instance_lbs.jsonl"

jq -c '.[]' "$WORKDIR/tgs.json" | while IFS= read -r row; do
  TG_ARN="$(echo "$row" | jq -r '.[0]')"
  TG_TYPE="$(echo "$row" | jq -r '.[1]')"
  # skip TGs not attached to LBs (LoadBalancerArns empty)
  LB_ARNS_COUNT="$(echo "$row" | jq -r '.[2] | length')"
  [ "$LB_ARNS_COUNT" = "0" ] && continue

  # target match: instance-id OR private-ip
  HIT="$(aws elbv2 describe-target-health \
    --region "$REGION" \
    --target-group-arn "$TG_ARN" \
    --query "TargetHealthDescriptions[?Target.Id=='$INSTANCE_ID' || Target.Id=='$PRIVATE_IP'] | length(@)" \
    --output text 2>/dev/null || echo "0")"

  if [ "$HIT" != "0" ]; then
    echo "$row" | jq -r '.[2][]' | while IFS= read -r LB_ARN; do
      aws elbv2 describe-load-balancers \
        --region "$REGION" \
        --load-balancer-arns "$LB_ARN" \
        --output json 2>/dev/null \
      | jq -c '.LoadBalancers[0] | {LoadBalancerArn, DNSName, Scheme, Type}' \
      >> "$WORKDIR/instance_lbs.jsonl"
    done
  fi
done

sort -u "$WORKDIR/instance_lbs.jsonl" > "$WORKDIR/instance_lbs_uniq.jsonl" 2>/dev/null || true

INTERNET_ALBS_FOUND=0
INTERNET_ALB_ARNS=()
if [ -s "$WORKDIR/instance_lbs_uniq.jsonl" ]; then
  info "ALBs routing to instance:"
  while IFS= read -r line; do
    dns="$(echo "$line" | jq -r '.DNSName')"
    scheme="$(echo "$line" | jq -r '.Scheme')"
    arn="$(echo "$line" | jq -r '.LoadBalancerArn')"
    echo "  - $scheme $(echo "$line" | jq -r '.Type')  $dns"
    if [ "$scheme" = "internet-facing" ]; then
      INTERNET_ALBS_FOUND=1
      if [ -n "$ALB_DNS" ]; then
        [ "$dns" = "$ALB_DNS" ] && INTERNET_ALB_ARNS+=("$arn")
      else
        INTERNET_ALB_ARNS+=("$arn")
      fi
    fi
  done < "$WORKDIR/instance_lbs_uniq.jsonl"
else
  info "No load balancers discovered for this instance."
fi

# ALB access log scan
ALB_SCAN_REQUIRED="$INTERNET_ALBS_FOUND"
ALB_SCAN_COMPLETE=1
ALB_INDICATOR_HITS=0
ALB_TARGETIP_HITS=0
IND_RE='nip\.io|sslip\.io|169\.254\.169\.254'

if [ "$ALB_SCAN_REQUIRED" = "1" ] && [ ${#INTERNET_ALB_ARNS[@]} -eq 0 ]; then
  # internet-facing exists but filtered out by --alb-dns mismatch
  err "Internet-facing ALB exists but none selected (check --alb-dns)."
  ALB_SCAN_COMPLETE=0
fi

# prepare time marks
make_5min_marks "$START" "$END" > "$WORKDIR/time_marks.txt"

for LB_ARN in "${INTERNET_ALB_ARNS[@]}"; do
  LB_ID="$(echo "$LB_ARN" | awk -F/ '{print $NF}')"
  LB_ACCT="$(echo "$LB_ARN" | awk -F: '{print $5}')"
  DNS="$(aws elbv2 describe-load-balancers --region "$REGION" --load-balancer-arns "$LB_ARN" --query 'LoadBalancers[0].DNSName' --output text 2>/dev/null || true)"

  ok "ALB scan: $DNS (id=$LB_ID acct=$LB_ACCT)"

  aws elbv2 describe-load-balancer-attributes \
    --region "$REGION" \
    --load-balancer-arn "$LB_ARN" \
    --output json > "$WORKDIR/alb_attrs_${LB_ID}.json" 2>/dev/null || true

  ENABLED="$(jq -r '.Attributes[]? | select(.Key=="access_logs.s3.enabled") | .Value' "$WORKDIR/alb_attrs_${LB_ID}.json" | head -n 1)"
  BUCKET="$(jq -r '.Attributes[]? | select(.Key=="access_logs.s3.bucket") | .Value' "$WORKDIR/alb_attrs_${LB_ID}.json" | head -n 1)"
  PREFIX="$(jq -r '.Attributes[]? | select(.Key=="access_logs.s3.prefix") | .Value' "$WORKDIR/alb_attrs_${LB_ID}.json" | head -n 1)"

  if [ "$ENABLED" != "true" ] || [ -z "$BUCKET" ]; then
    err "ALB access logs not enabled for $DNS => INCONCLUSIVE."
    ALB_SCAN_COMPLETE=0
    continue
  fi

  # Build base prefix (ALB prefix, if set, precedes AWSLogs/)
  BASE=""
  if [ -n "${PREFIX:-}" ]; then
    BASE="${PREFIX%/}/"
  fi

  D1="$(iso_to_ymd "$START")"
  D2="$(iso_to_ymd "$END")"

  mkdir -p "$WORKDIR/alb_logs_${LB_ID}"
  FOUND_ANY=0

  for D in "$D1" "$D2"; do
    DATE_PREFIX="${BASE}AWSLogs/${LB_ACCT}/elasticloadbalancing/${REGION}/${D}/"
    aws s3api list-objects-v2 \
      --bucket "$BUCKET" \
      --prefix "$DATE_PREFIX" \
      --query 'Contents[].Key' \
      --output text 2>/dev/null \
    | tr '\t' '\n' \
    | grep "$LB_ID" \
    > "$WORKDIR/alb_keys_${LB_ID}_${D//\//}.txt" || true

    : > "$WORKDIR/alb_keys_${LB_ID}_${D//\//}_focus.txt"
    while IFS= read -r MARK; do
      grep -F "$MARK" "$WORKDIR/alb_keys_${LB_ID}_${D//\//}.txt" >> "$WORKDIR/alb_keys_${LB_ID}_${D//\//}_focus.txt" 2>/dev/null || true
    done < "$WORKDIR/time_marks.txt"

    sort -u "$WORKDIR/alb_keys_${LB_ID}_${D//\//}_focus.txt" > "$WORKDIR/alb_keys_${LB_ID}_${D//\//}_focus_uniq.txt" || true
    CNT="$(wc -l < "$WORKDIR/alb_keys_${LB_ID}_${D//\//}_focus_uniq.txt" | tr -d ' ')"

    if [ "$CNT" -gt 0 ]; then
      FOUND_ANY=1
      while IFS= read -r KEY; do
        [ -z "$KEY" ] && continue
        aws s3 cp "s3://$BUCKET/$KEY" "$WORKDIR/alb_logs_${LB_ID}/${KEY##*/}" >/dev/null 2>&1 || true
      done < "$WORKDIR/alb_keys_${LB_ID}_${D//\//}_focus_uniq.txt"
    fi
  done

  if [ "$FOUND_ANY" = "0" ]; then
    # Could be log delivery delay or unexpected prefix. Fail closed.
    err "No ALB log objects found for selected window on $DNS => INCONCLUSIVE."
    ALB_SCAN_COMPLETE=0
    continue
  fi

  # indicator grep
  HITS="$(for f in "$WORKDIR/alb_logs_${LB_ID}"/*.gz; do [ -f "$f" ] && gunzip -c "$f"; done \
    | egrep -i "$IND_RE" | wc -l | tr -d ' ')"
  ALB_INDICATOR_HITS=$((ALB_INDICATOR_HITS + HITS))

  if [ -n "$PRIVATE_IP" ]; then
    H2="$(for f in "$WORKDIR/alb_logs_${LB_ID}"/*.gz; do [ -f "$f" ] && gunzip -c "$f"; done \
      | grep -F "$PRIVATE_IP" | egrep -i "$IND_RE" | wc -l | tr -d ' ')"
    ALB_TARGETIP_HITS=$((ALB_TARGETIP_HITS + H2))
  fi

  ok "ALB indicator hits: $HITS ; hits routed to $PRIVATE_IP: ${H2:-0}"
done

############################
# 7) WAF association (optional)
############################
WAF_STATUS="unknown"
if [ "$INTERNET_ALBS_FOUND" = "1" ] && [ ${#INTERNET_ALB_ARNS[@]} -gt 0 ]; then
  # Query WebACL; null => none attached
  WAF_WEBACL="$(aws wafv2 get-web-acl-for-resource --region "$REGION" --resource-arn "${INTERNET_ALB_ARNS[0]}" --query 'WebACL' --output json 2>/dev/null || echo '"__error__"')"
  echo "$WAF_WEBACL" > "$WORKDIR/waf_webacl.json"
  if echo "$WAF_WEBACL" | jq -e '. == null' >/dev/null 2>&1; then
    WAF_STATUS="none"
    ok "WAF: none attached (WebACL=null)."
  elif [ "$WAF_WEBACL" = '"__error__"' ]; then
    WAF_STATUS="unknown"
    info "WAF: unknown (API error/permissions)."
  else
    WAF_STATUS="attached"
    ok "WAF: attached."
  fi
fi

############################
# 8) Verdict logic (fail-closed)
############################
info "Computing verdict..."

IMDS_V2_ONLY=0
[ "$HTTP_TOKENS" = "required" ] && IMDS_V2_ONLY=1

IMDS_V1_EVIDENCE=0
for M in MetadataNoToken MetadataNoTokenRejected; do
  POS="$(jq -r '[.Datapoints[]?.Sum] | map(select(. > 0)) | length' "$WORKDIR/cw_${M}_window.json" 2>/dev/null || echo "0")"
  [ "${POS:-0}" -gt 0 ] && IMDS_V1_EVIDENCE=1
done

SG_OPEN_WORLD=0
if [ -f "$WORKDIR/describe_sgs.json" ]; then
  OPEN4="$(jq -r '[.SecurityGroups[].IpPermissions[]? | select((.IpRanges[]?.CidrIp // "")=="0.0.0.0/0")] | length' "$WORKDIR/describe_sgs.json" 2>/dev/null || echo "0")"
  OPEN6="$(jq -r '[.SecurityGroups[].IpPermissions[]? | select((.Ipv6Ranges[]?.CidrIpv6 // "")=="::/0")] | length' "$WORKDIR/describe_sgs.json" 2>/dev/null || echo "0")"
  ([ "${OPEN4:-0}" -gt 0 ] || [ "${OPEN6:-0}" -gt 0 ]) && SG_OPEN_WORLD=1
fi

# CloudTrail suspicious patterns (instance session)
CT_SUSPICIOUS=0
if [ -f "$WORKDIR/ct_username_instance.json" ]; then
  CT_BAD="$(cat "$WORKDIR/ct_username_instance.json" | jq -r '
    [.Events[]?
      | (.CloudTrailEvent | '"$(json_event)"') as $e
      | select(
          $e.eventSource=="iam.amazonaws.com"
          or $e.eventSource=="sts.amazonaws.com"
          or ($e.eventSource=="ec2.amazonaws.com" and ($e.eventName|test("AuthorizeSecurityGroupIngress|RevokeSecurityGroupIngress|ModifyInstanceAttribute|ModifyNetworkInterfaceAttribute|CreateSecurityGroup|RunInstances|CreateImage|CreateSnapshot|AttachVolume|CreateTags")))
          or ($e.eventSource=="s3.amazonaws.com" and ($e.eventName|test("PutBucketPolicy|PutBucketAcl|PutObject|GetObject|ListBucket")))
        )
    ] | length' 2>/dev/null || echo "0")"
  [ "${CT_BAD:-0}" -gt 0 ] && CT_SUSPICIOUS=1

  # Also flag if we see public source IPs that are not NAT_EIP and not AWS service principals
  if [ -n "${NAT_EIP:-}" ]; then
    CT_WEIRD_SRC="$(cat "$WORKDIR/ct_username_instance.json" | jq -r '
      [.Events[]?
        | (.CloudTrailEvent | '"$(json_event)"') as $e
        | $e.sourceIPAddress
        | select(type=="string")
        | select(. != "'"$NAT_EIP"'")
        | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))
      ] | length' 2>/dev/null || echo "0")"
    # If non-NAT public IPs exist, mark suspicious (conservative)
    if [ "${CT_WEIRD_SRC:-0}" -gt 0 ]; then
      CT_SUSPICIOUS=1
    fi
  fi
fi

ALB_OK=1
if [ "$ALB_SCAN_REQUIRED" = "1" ]; then
  # Must have completed scan to call benign
  [ "$ALB_SCAN_COMPLETE" -ne 1 ] && ALB_OK=0
  [ "$ALB_INDICATOR_HITS" -gt 0 ] && ALB_OK=0
  [ "$ALB_TARGETIP_HITS" -gt 0 ] && ALB_OK=0
fi

VERDICT="INCONCLUSIVE"
if [ "$IMDS_V1_EVIDENCE" -eq 1 ] || [ "$SG_OPEN_WORLD" -eq 1 ] || [ "$CT_SUSPICIOUS" -eq 1 ] || [ "$ALB_OK" -eq 0 ]; then
  VERDICT="SUSPICIOUS"
  # If ALB scan incomplete (not hits), that’s INCONCLUSIVE rather than SUSPICIOUS
  if [ "$ALB_SCAN_REQUIRED" = "1" ] && [ "$ALB_SCAN_COMPLETE" -ne 1 ] && [ "$ALB_INDICATOR_HITS" -eq 0 ] && [ "$ALB_TARGETIP_HITS" -eq 0 ] && [ "$IMDS_V1_EVIDENCE" -eq 0 ] && [ "$CT_SUSPICIOUS" -eq 0 ]; then
    VERDICT="INCONCLUSIVE"
  fi
else
  if [ "$IMDS_V2_ONLY" -eq 1 ] && [ "$IMDS_V1_EVIDENCE" -eq 0 ] && [ "$CT_SUSPICIOUS" -eq 0 ]; then
    if [ "$ALB_SCAN_REQUIRED" = "1" ]; then
      [ "$ALB_SCAN_COMPLETE" -eq 1 ] && VERDICT="BENIGN_LIKELY"
    else
      VERDICT="BENIGN_LIKELY"
    fi
  fi
fi

cat > "$WORKDIR/verdict.json" <<EOF
{
  "region": "$REGION",
  "detector_id": "$DETECTOR_ID",
  "instance_id": "$INSTANCE_ID",
  "window": {"start":"$START","end":"$END"},
  "imds": {
    "http_tokens": "${HTTP_TOKENS:-}",
    "http_endpoint": "${HTTP_ENDPOINT:-}",
    "hop_limit": "${HOP_LIMIT:-}",
    "imds_v2_only": $IMDS_V2_ONLY,
    "imds_v1_evidence_in_window": $IMDS_V1_EVIDENCE
  },
  "network": {
    "private_ip": "${PRIVATE_IP:-}",
    "public_ip": "${PUBLIC_IP:-}",
    "nat_eip": "${NAT_EIP:-}",
    "sg_open_to_world": $SG_OPEN_WORLD
  },
  "guardduty": {
    "rebind_finding_count": $REBIND_COUNT
  },
  "cloudtrail": {
    "suspicious_instance_session_events": $CT_SUSPICIOUS
  },
  "alb": {
    "internet_albs_found": $INTERNET_ALBS_FOUND,
    "scan_required": $ALB_SCAN_REQUIRED,
    "scan_complete": $ALB_SCAN_COMPLETE,
    "indicator_hits": $ALB_INDICATOR_HITS,
    "indicator_hits_routed_to_target_ip": $ALB_TARGETIP_HITS
  },
  "waf": { "status": "$WAF_STATUS" },
  "verdict": "$VERDICT"
}
EOF

echo
ok "VERDICT: $VERDICT"
info "Artifacts in: $WORKDIR"
info "  - verdict.json"
info "  - rebind_findings.json (if any)"
info "  - cw_MetadataNoToken_window.json / cw_MetadataNoTokenRejected_window.json"
info "  - ct_username_instance.json"
info "  - instance_lbs_uniq.jsonl"
info "  - alb_logs_* (if scanned)"

if [ "$VERDICT" = "BENIGN_LIKELY" ]; then exit 0; fi
if [ "$VERDICT" = "SUSPICIOUS" ]; then exit 1; fi
exit 3
