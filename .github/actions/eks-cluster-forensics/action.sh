#!/usr/bin/env bash
#
# Capture forensic data about an EKS cluster and its AWS resources so that the
# next mid-run teardown names its actor instead of being inferred from the
# absence of nodes. Every probe is best-effort: we deliberately do NOT set -e,
# so a single failing command (the cluster, a nodegroup or a subnet may already
# be gone, and that failure is itself evidence worth recording) never aborts the
# rest of the collection.

set -u

ARTIFACTS_SUFFIX="${1:?artifacts_suffix argument is required}"
PHASE="${2:-post}"

CLUSTER_NAME="${CLUSTER_NAME:?CLUSTER_NAME is required}"
REGION="${REGION:-${AWS_REGION:-${AWS_DEFAULT_REGION:-}}}"
NODE_BASELINE="${NODE_BASELINE:-}"
LOOKBACK_HOURS="${LOOKBACK_HOURS:-12}"
DEST="${DEST:-.}"

OUTDIR="$(mktemp -d)"
echo "Collecting EKS cluster forensics for ${CLUSTER_NAME} (${REGION}) into ${OUTDIR}"

# Pin every probe to the cluster's region, unless the environment already did.
if [ -n "${REGION}" ]; then
  aws() { command aws --region "${REGION}" "$@"; }
fi

START_TIME="$(date -u -d "@$(( $(date +%s) - LOOKBACK_HOURS * 3600 ))" +%Y-%m-%dT%H:%M:%SZ)"
{
  echo "cluster=${CLUSTER_NAME}"
  echo "region=${REGION}"
  echo "phase=${PHASE}"
  echo "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "cloudtrail_start_time=${START_TIME}"
} > "${OUTDIR}/context.txt"

# Kubernetes view: which nodes still exist, and the recent events (cordon,
# NotReady, DeletingNode "because it does not exist in the cloud provider", ...).
kubectl get nodes -o wide > "${OUTDIR}/nodes.txt" 2>&1
kubectl get nodes -o json > "${OUTDIR}/nodes.json" 2>&1
kubectl get events -A --sort-by=.lastTimestamp > "${OUTDIR}/events.txt" 2>&1

# Cluster-level state. A deleted subnet answers InvalidSubnetID.NotFound, which
# is recorded here as a fact rather than left to be inferred later.
aws eks describe-cluster --name "${CLUSTER_NAME}" \
  > "${OUTDIR}/eks-describe-cluster.json" 2>&1
SUBNET_IDS="$(aws eks describe-cluster --name "${CLUSTER_NAME}" \
  --query 'cluster.resourcesVpcConfig.subnetIds' --output text 2>/dev/null)"
if [ -n "${SUBNET_IDS}" ]; then
  # shellcheck disable=SC2086 # word splitting is how the ids are passed
  aws ec2 describe-subnets --subnet-ids ${SUBNET_IDS} \
    > "${OUTDIR}/ec2-describe-subnets.json" 2>&1
fi

# Nodegroup state and, for every nodegroup, the scaling activities of its own
# Auto Scaling Group: a scale-in reads differently from a nodegroup deletion.
aws eks list-nodegroups --cluster-name "${CLUSTER_NAME}" \
  > "${OUTDIR}/eks-list-nodegroups.json" 2>&1
NODEGROUPS="$(aws eks list-nodegroups --cluster-name "${CLUSTER_NAME}" \
  --query 'nodegroups' --output text 2>/dev/null)"
for ng in ${NODEGROUPS}; do
  aws eks describe-nodegroup --cluster-name "${CLUSTER_NAME}" --nodegroup-name "${ng}" \
    > "${OUTDIR}/eks-describe-nodegroup-${ng}.json" 2>&1
  ASGS="$(aws eks describe-nodegroup --cluster-name "${CLUSTER_NAME}" --nodegroup-name "${ng}" \
    --query 'nodegroup.resources.autoScalingGroups[].name' --output text 2>/dev/null)"
  for asg in ${ASGS}; do
    aws autoscaling describe-scaling-activities --auto-scaling-group-name "${asg}" \
      > "${OUTDIR}/asg-activities-${asg}.json" 2>&1
  done
done

# eksctl's CloudFormation stacks. Deleted stacks are only addressable by stack
# id, so resolve ids from list-stacks: a DELETE_IN_PROGRESS timestamp and the
# ClientRequestToken of the delete identify the caller.
aws cloudformation list-stacks \
  --query "StackSummaries[?starts_with(StackName, 'eksctl-${CLUSTER_NAME}')].[StackName,StackId,StackStatus,CreationTime,DeletionTime]" \
  --output json > "${OUTDIR}/cfn-list-stacks.json" 2>&1
STACK_IDS="$(aws cloudformation list-stacks \
  --query "StackSummaries[?starts_with(StackName, 'eksctl-${CLUSTER_NAME}')].StackId" \
  --output text 2>/dev/null)"
for stack_id in ${STACK_IDS}; do
  stack_file="${stack_id##*/}"
  aws cloudformation describe-stacks --stack-name "${stack_id}" \
    > "${OUTDIR}/cfn-describe-stack-${stack_file}.json" 2>&1
  aws cloudformation describe-stack-events --stack-name "${stack_id}" \
    > "${OUTDIR}/cfn-stack-events-${stack_file}.json" 2>&1
done

# Per-instance state. The node list is the union of the baseline taken while the
# cluster was healthy and the live one, so an instance whose Node object was
# already reaped ("DeletingNode ... does not exist in the cloud provider") is
# still interrogated.
{
  kubectl get nodes -o jsonpath='{range .items[*]}{.spec.providerID}{"\n"}{end}' 2>/dev/null
  if [ -n "${NODE_BASELINE}" ] && [ -r "${NODE_BASELINE}" ]; then
    jq -r '.items[].spec.providerID // empty' "${NODE_BASELINE}" 2>/dev/null
  fi
} | sort -u > "${OUTDIR}/provider-ids.txt"

while read -r provider_id; do
  # providerID looks like aws:///us-west-2b/i-0123456789abcdef0
  instance_id="${provider_id##*/}"
  case "${instance_id}" in
  i-*) ;;
  *) continue ;;
  esac

  echo "=== Forensics for instance ${instance_id} (${provider_id}) ==="

  # EC2 instance state and, most importantly, the state-transition reason, which
  # distinguishes a capacity event from a user- or service-initiated shutdown.
  aws ec2 describe-instances --instance-ids "${instance_id}" \
    --query 'Reservations[].Instances[].{state:State.Name,reason:StateTransitionReason,stateReason:StateReason,launchTime:LaunchTime,subnet:SubnetId,tags:Tags}' \
    > "${OUTDIR}/ec2-describe-${instance_id}.json" 2>&1

  aws cloudtrail lookup-events --max-items 100 --start-time "${START_TIME}" \
    --lookup-attributes "AttributeKey=ResourceName,AttributeValue=${instance_id}" \
    > "${OUTDIR}/cloudtrail-resource-${instance_id}.json" 2>&1
done < "${OUTDIR}/provider-ids.txt"

# CloudTrail is the decisive probe: it names the principal behind each delete.
aws cloudtrail lookup-events --max-items 250 --start-time "${START_TIME}" \
  --lookup-attributes "AttributeKey=ResourceName,AttributeValue=${CLUSTER_NAME}" \
  > "${OUTDIR}/cloudtrail-resource-cluster.json" 2>&1
for event in DeleteNodegroup DeleteCluster DeleteStack DeleteSubnet TerminateInstances; do
  aws cloudtrail lookup-events --max-items 250 --start-time "${START_TIME}" \
    --lookup-attributes "AttributeKey=EventName,AttributeValue=${event}" \
    > "${OUTDIR}/cloudtrail-event-${event}.json" 2>&1
done

TARBALL="${DEST}/eks-cluster-forensics-${ARTIFACTS_SUFFIX}-${PHASE}.tar.gz"
tar -czf "${TARBALL}" -C "${OUTDIR}" .
echo "Wrote ${TARBALL}"
