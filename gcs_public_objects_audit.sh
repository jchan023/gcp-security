#!/bin/bash -
#===============================================================================
# Flag GCS exposure that public_access_audit.sh's IAM-binding check doesn't
# see: buckets without Public Access Prevention enforced, buckets still using
# fine-grained (non-uniform) access where legacy ACLs can grant public access
# independently of IAM, and individual objects with a public ACL grant.
#
# Note: the per-object ACL scan only runs on fine-grained buckets (ACLs are
# ignored entirely once uniform bucket-level access is on) and can be slow on
# buckets with very large object counts.
#===============================================================================
set -uo pipefail

FOUND=false

for project in $(gcloud projects list --format="value(projectId)"); do
  BUCKETS=$(gcloud storage buckets list --project="$project" --format="value(name)" 2>/dev/null)

  for bucket in $BUCKETS; do
    # Public Access Prevention not enforced = allUsers/allAuthenticatedUsers
    # grants (IAM or ACL) are not blocked at the bucket level.
    PAP=$(gcloud storage buckets describe "gs://$bucket" \
      --format="value(public_access_prevention)" 2>/dev/null)
    if [ "$PAP" != "enforced" ]; then
      echo "$project [bucket gs://$bucket]: Public Access Prevention not enforced (${PAP:-inherited})"
      FOUND=true
    fi

    # Fine-grained (non-uniform) buckets rely on legacy ACLs, which can grant
    # public access independently of IAM bindings - flag so it gets reviewed.
    UBLA=$(gcloud storage buckets describe "gs://$bucket" \
      --format="value(uniform_bucket_level_access)" 2>/dev/null)
    if [ "$UBLA" != "True" ]; then
      echo "$project [bucket gs://$bucket]: uniform bucket-level access disabled (legacy ACLs in play)"
      FOUND=true

      OBJECT_HITS=$(gcloud storage objects list "gs://$bucket" --format="value(name)" 2>/dev/null | \
        while read -r obj; do
          ACL=$(gcloud storage objects describe "gs://$bucket/$obj" \
            --format="value(acl[].entity)" 2>/dev/null)
          if echo "$ACL" | grep -qE "allUsers|allAuthenticatedUsers"; then
            echo "$obj"
          fi
        done)
      if [ -n "$OBJECT_HITS" ]; then
        echo "$OBJECT_HITS" | sed "s/^/$project [bucket gs:\/\/$bucket] public object: /"
        FOUND=true
      fi
    fi
  done
done

if [ "$FOUND" = false ]; then
  echo "No PAP gaps, non-uniform buckets, or public object ACLs found"
fi
