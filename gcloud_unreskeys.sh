# Loop through every project ID you have access to
for project in $(gcloud projects list --format="value(projectId)"); do
  echo "--- Checking Project: $project ---"
  
  # List keys and format output to show if restrictions exist
  # This filters for keys where the 'restrictions' field is empty
  gcloud services api-keys list --project="$project" \
    --filter="NOT restrictions:*" \
    --format="table(displayName, uid, createTime)"
done
