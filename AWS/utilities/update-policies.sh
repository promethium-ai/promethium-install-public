#!/bin/bash

# Usage:
# ./update-policies.sh account_id=... region=... company_name=... policies_dir=... [eks_oidc_id=...] [eks_cluster_name=...]

# Initialize variables
ACCOUNT_ID=""
REGION=""
COMPANY_NAME=""
EKS_OIDC_ID=""
POLICIES_DIR=""
EKS_CLUSTER_NAME=""

# Parse key=value arguments
for ARG in "$@"; do
  case $ARG in
    account_id=*)
      ACCOUNT_ID="${ARG#*=}"
      ;;
    region=*)
      REGION="${ARG#*=}"
      ;;
    company_name=*)
      COMPANY_NAME="${ARG#*=}"
      ;;
    policies_dir=*)
      POLICIES_DIR="${ARG#*=}"
      ;;
    eks_oidc_id=*)
      EKS_OIDC_ID="${ARG#*=}"
      ;;
    eks_cluster_name=*)
      EKS_CLUSTER_NAME="${ARG#*=}"
      ;;
    *)
      echo "Unknown argument: $ARG"
      echo "Usage: $0 account_id=... region=... company_name=... policies_dir=... [eks_oidc_id=...] [eks_cluster_name=...]"
      exit 1
      ;;
  esac
done

# Validate required parameters
if [[ -z "$ACCOUNT_ID" || -z "$REGION" || -z "$COMPANY_NAME" || -z "$POLICIES_DIR" ]]; then
  echo "Missing required arguments."
  echo "Usage: $0 account_id=... region=... company_name=... policies_dir=... [eks_oidc_id=...] [eks_cluster_name=...]"
  exit 1
fi

# Validate policy directory
if [ ! -d "$POLICIES_DIR" ]; then
  echo "Policy directory '$POLICIES_DIR' does not exist."
  exit 1
fi

# Create output directory named after the company
POLICIES_PARENT=$(dirname "$POLICIES_DIR")
OUTPUT_DIR="${POLICIES_PARENT}/${COMPANY_NAME}"
mkdir -p "$OUTPUT_DIR"


# Find all matching policy files
FILES=$(find "$POLICIES_DIR" -maxdepth 1 -type f -name '*.json')

if [ -z "$FILES" ]; then
  echo "No matching policy files found in '$POLICIES_DIR'."
  exit 1
fi

for FILE in $FILES; do
  BASENAME=$(basename "$FILE")
  NEWFILE="${OUTPUT_DIR}/${COMPANY_NAME}-${BASENAME}"

  echo "Creating modified copy: $NEWFILE"

  # Perform replacements
  MODIFIED=$(sed \
    -e "s|<account_id>|$ACCOUNT_ID|gI" \
    -e "s|<region>|$REGION|gI" \
    -e "s|<company name>|$COMPANY_NAME|gI" \
    "$FILE")

  # Optional EKS OIDC replacement
  if [[ -n "$EKS_OIDC_ID" ]]; then
    MODIFIED=$(echo "$MODIFIED" | sed -e "s|<EKS_OIDC_ID>|$EKS_OIDC_ID|gI")
  fi

  # Optional EKS Cluster Name replacement
  if [[ -n "$EKS_CLUSTER_NAME" ]]; then
    MODIFIED=$(echo "$MODIFIED" | sed -e "s|<EKS_CLUSTER_NAME>|$EKS_CLUSTER_NAME|gI")
  fi

  echo "$MODIFIED" > "$NEWFILE"
done

echo "Done. All modified files saved in: $OUTPUT_DIR"
