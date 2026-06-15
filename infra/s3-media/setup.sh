#!/usr/bin/env bash
# © 2026 The AI Lab Intelligence Unobscured, Inc.
# License: TIPCL-1.0
#
# One-command S3 media setup for a TIP node. Same process whether the
# node runs on EC2, in EKS, or on a non-AWS host (incl. a dev laptop):
#
#   1. cp terraform.tfvars.example terraform.tfvars   # fill 3 lines
#   2. ./setup.sh
#   3. paste the printed env block into the node's .env and start it
#
# Node credentials per mode:
#   ec2      -> instance profile (attach the printed profile name)
#   irsa     -> pod service-account annotation (printed role ARN)
#   external -> IAM Roles Anywhere: X.509 cert + aws_signing_helper
#               (hardened path for Hetzner / DO / GCP / bare metal)
#   keys     -> bucket-scoped IAM user access key printed in the env
#               block; paste-anywhere easy path (long-lived secret,
#               rotate every 90 days)

set -euo pipefail
cd "$(dirname "$0")"

say()  { printf '\033[1;36m> %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mx %s\033[0m\n' "$*" >&2; exit 1; }

# == 0. prerequisites =========================================================
command -v terraform >/dev/null || die "terraform not installed. mac: brew install hashicorp/tap/terraform"
# aws CLI is optional when access keys are already in the environment:
# terraform talks to AWS directly via the SDK.
HAVE_AWS_CLI=1; command -v aws >/dev/null || HAVE_AWS_CLI=0
if [ "$HAVE_AWS_CLI" = "0" ] && [ -z "${AWS_ACCESS_KEY_ID:-}" ]; then
  die "Need either the aws CLI (brew install awscli, then aws configure sso)
   or AWS keys in the environment:
       export AWS_ACCESS_KEY_ID=...   AWS_SECRET_ACCESS_KEY=...
   then re-run ./setup.sh"
fi
[ -f terraform.tfvars ]         || die "terraform.tfvars missing. Run: cp terraform.tfvars.example terraform.tfvars   then fill in the 3 values."

REGION=$(awk -F'"' '/^region/ {print $2}' terraform.tfvars)
BUCKET=$(awk -F'"' '/^bucket_name/ {print $2}' terraform.tfvars)
MODE=$(awk -F'"' '/^trust_mode/ {print $2}' terraform.tfvars)
[ -n "$REGION" ] && [ -n "$BUCKET" ] && [ -n "$MODE" ] || die "terraform.tfvars must set bucket_name, region and trust_mode."
case "$BUCKET" in *CHANGEME*) die "bucket_name still contains CHANGEME: pick a globally unique name." ;; esac

# == 1. AWS login (operator credentials, used by terraform only) ==============
PROFILE="${AWS_PROFILE:-default}"
if [ -n "${AWS_ACCESS_KEY_ID:-}" ]; then
  say "using AWS keys from environment"
elif ! aws sts get-caller-identity --profile "$PROFILE" >/dev/null 2>&1; then
  # try an SSO re-login first (covers the common "token expired" case)
  if aws configure list-profiles 2>/dev/null | grep -qx "$PROFILE" && aws sso login --profile "$PROFILE" 2>/dev/null; then
    :
  else
    die "No working AWS credentials for profile \"$PROFILE\".
   First time?   aws configure sso        (SSO accounts, recommended)
            or   aws configure            (IAM access key)
   Then re-run:  AWS_PROFILE=<profile> ./setup.sh"
  fi
fi
if [ "$HAVE_AWS_CLI" = "1" ] && [ -z "${AWS_ACCESS_KEY_ID:-}" ]; then
  CALLER=$(aws sts get-caller-identity --profile "$PROFILE" --query Arn --output text)
  say "AWS identity: $CALLER"
fi

# == 2. external mode: generate CA + node cert BEFORE apply ===================
# The CA private key signs exactly one node certificate and stays on the
# operator's machine (external-credentials/ is gitignored). Terraform only
# receives the PUBLIC CA cert, so no private material enters tfstate.
CERT_DIR="external-credentials"
EXTRA_VARS=()
if [ "$MODE" = "external" ]; then
  command -v openssl >/dev/null || die "openssl required for trust_mode=external."
  if [ ! -f "$CERT_DIR/ca.pem" ]; then
    say "generating CA + node certificate under $CERT_DIR/ (one-time)"
    mkdir -p "$CERT_DIR"
    chmod 700 "$CERT_DIR"
    # CA (10y). CN is informational; the trust anchor pins the exact cert.
    # RSA 2048, not EC: AWS Roles Anywhere rejects EC certificates produced
    # by LibreSSL (macOS default openssl). RSA parses everywhere.
    openssl req -x509 -newkey rsa:2048 -days 3650 \
      -nodes -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.pem" \
      -subj "/CN=tip-media-$BUCKET-ca" \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
    # Node leaf cert (1y; re-run setup.sh after deleting node.pem to rotate).
    openssl req -newkey rsa:2048 -nodes \
      -keyout "$CERT_DIR/node.key" -out "$CERT_DIR/node.csr" \
      -subj "/CN=tip-media-$BUCKET-node" >/dev/null 2>&1
    openssl x509 -req -in "$CERT_DIR/node.csr" -CA "$CERT_DIR/ca.pem" \
      -CAkey "$CERT_DIR/ca.key" -CAcreateserial -days 365 \
      -out "$CERT_DIR/node.pem" \
      -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature") >/dev/null 2>&1
    rm -f "$CERT_DIR/node.csr" "$CERT_DIR/ca.srl"
    chmod 600 "$CERT_DIR"/*.key
  else
    say "reusing existing CA under $CERT_DIR/"
  fi
  EXTRA_VARS=(-var "external_ca_cert_pem=$(cat "$CERT_DIR/ca.pem")")
fi

# == 3. provision (idempotent; re-running is safe) ============================
say "terraform init/apply (bucket=$BUCKET region=$REGION mode=$MODE)"
AWS_PROFILE="$PROFILE" AWS_REGION="$REGION" terraform init -input=false >/dev/null
AWS_PROFILE="$PROFILE" AWS_REGION="$REGION" terraform apply -input=false -auto-approve "${EXTRA_VARS[@]+"${EXTRA_VARS[@]}"}"

ROLE_ARN=$(terraform output -raw node_role_arn)
KMS_ARN=$(terraform output -raw kms_key_arn)

# == 4. credentials wiring per mode ===========================================
NODE_PROFILE="tip-media-node"
case "$MODE" in
  ec2)
    PROFILE_NAME=$(terraform output -raw node_instance_profile_name)
    ;;
  external)
    ANCHOR_ARN=$(terraform output -raw external_trust_anchor_arn)
    RA_PROFILE_ARN=$(terraform output -raw external_profile_arn)
    CERT_ABS="$(pwd)/$CERT_DIR"

    # Normal case: setup.sh is running ON the node machine (operator put
    # the owner's temp keys in env and ran it here). Then the certs are
    # already on the right disk and we can finish the wiring in-place:
    # fetch the signing helper, write the SDK profile, verify against AWS.
    # The manual instructions below remain for the run-elsewhere case.
    EXTERNAL_WIRED=0
    HELPER="$(command -v aws_signing_helper || true)"
    if [ -z "$HELPER" ] && command -v brew >/dev/null; then
      say "installing aws_signing_helper via homebrew"
      brew install rolesanywhere-credential-helper >/dev/null 2>&1 || true
      HELPER="$(command -v aws_signing_helper || true)"
    fi
    if [ -z "$HELPER" ]; then
      say "aws_signing_helper not found and brew unavailable; install it from
   https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html
   then re-run ./setup.sh (manual instructions printed below meanwhile)"
    fi
    if [ -n "$HELPER" ]; then
      say "writing credential_process profile [$NODE_PROFILE] to ~/.aws/config"
      CRED_CMD="$HELPER credential-process --certificate $CERT_ABS/node.pem --private-key $CERT_ABS/node.key --trust-anchor-arn $ANCHOR_ARN --profile-arn $RA_PROFILE_ARN --role-arn $ROLE_ARN"
      python3 - "$NODE_PROFILE" "$REGION" "$CRED_CMD" <<'PYEOF'
import configparser, os, sys
name, region, cred = sys.argv[1:4]
path = os.path.expanduser("~/.aws/config")
os.makedirs(os.path.dirname(path), exist_ok=True)
cp = configparser.ConfigParser()
cp.read(path)
sect = f"profile {name}"
if not cp.has_section(sect):
    cp.add_section(sect)
cp.set(sect, "region", region)
cp.set(sect, "credential_process", cred)
with open(path, "w") as f:
    cp.write(f)
PYEOF
      # Prove the whole chain works before declaring victory: exchange the
      # certificate for real temporary credentials, right now.
      if $CRED_CMD >/dev/null 2>&1; then
        say "verified: AWS accepted the certificate and issued temporary credentials"
        EXTERNAL_WIRED=1
      else
        say "WARNING: credential exchange failed; check the trust anchor / clock skew"
      fi
    fi
    ;;
  keys)
    KEY_ID=$(terraform output -raw node_access_key_id)
    KEY_SECRET=$(terraform output -raw node_secret_access_key)
    ;;
  irsa) : ;;
esac

# == 5. the env block (identical for every mode) ==============================
echo
say "DONE. Add this to the node's .env:"
echo  "--------------------------------------------------------------"
echo  "TIP_MEDIA_BACKEND=s3"
echo  "TIP_MEDIA_S3_BUCKET=$BUCKET"
echo  "TIP_MEDIA_S3_REGION=$REGION"
echo  "TIP_MEDIA_S3_KMS_KEY_ID=$KMS_ARN"
case "$MODE" in
  dev|external) echo "AWS_PROFILE=$NODE_PROFILE" ;;
  keys)
    echo "AWS_ACCESS_KEY_ID=$KEY_ID"
    echo "AWS_SECRET_ACCESS_KEY=$KEY_SECRET"
    ;;
esac
echo  "--------------------------------------------------------------"
case "$MODE" in
  ec2)
    cat <<EOF
Attach the instance profile to the node's EC2 instance (console: EC2 ->
instance -> Actions -> Security -> Modify IAM role, or in terraform):

    iam_instance_profile = ${PROFILE_NAME}

No AWS env vars needed on the node: credentials are ambient.
EOF
    ;;
  irsa)
    cat <<EOF
Annotate the node pod's service account:

    kubectl annotate serviceaccount <sa> eks.amazonaws.com/role-arn=${ROLE_ARN}

No AWS env vars needed on the node: credentials are ambient.
EOF
    ;;
  keys)
    cat <<EOF
That block is everything: paste it into the node's .env on ANY machine on
ANY cloud and start the node. Nothing to install on the node machine.

Treat the two AWS_ lines as a password: send them over a secure channel.
The key can ONLY read/write this one bucket's media/ prefix; it cannot
touch anything else in the AWS account. Rotate it every 90 days:

    terraform apply -replace=aws_iam_access_key.media_node[0]

then send the node the two new lines.
EOF
    ;;
  external)
    if [ "$EXTERNAL_WIRED" = "1" ]; then
      cat <<EOF
THIS machine is fully wired (helper installed, SDK profile written,
certificate verified against AWS). If the node runs HERE, just paste the
env block above into the node's .env and start it. Nothing else to do.

If the node runs on a DIFFERENT machine instead, move these over and
re-create the same ~/.aws/config profile there:
     $CERT_DIR/node.pem  +  $CERT_DIR/node.key  (chmod 600)
     the aws_signing_helper binary

Cert rotation (yearly): delete $CERT_DIR/node.pem, re-run ./setup.sh.
EOF
    else
      cat <<EOF
Wiring was NOT completed automatically on this machine. On the NODE machine:

1. Copy these two files from this machine to the node (e.g. /etc/tip/):
     $CERT_DIR/node.pem
     $CERT_DIR/node.key        (chmod 600; this is the node's only secret)

2. Install the AWS signing helper (one static binary):
     https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html

3. Add this profile to the node's ~/.aws/config:

     [profile $NODE_PROFILE]
     region = $REGION
     credential_process = aws_signing_helper credential-process \\
       --certificate /etc/tip/node.pem \\
       --private-key /etc/tip/node.key \\
       --trust-anchor-arn $ANCHOR_ARN \\
       --profile-arn $RA_PROFILE_ARN \\
       --role-arn $ROLE_ARN

The SDK calls the helper and receives 1h role credentials, refreshed
automatically. To rotate the node cert: delete $CERT_DIR/node.pem here,
re-run ./setup.sh, copy the new pair over.
EOF
    fi
    ;;
esac
