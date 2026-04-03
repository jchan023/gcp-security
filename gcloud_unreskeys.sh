FOUND_KEYS=false

for project in $(gcloud projects list --format="value(projectId)"); do
  # Store the result in a variable to check if it's empty
  KEYS=$(gcloud services api-keys list --project="$project" \
    --filter="NOT restrictions:*" \
    --format="value(displayName, uid)" 2>/dev/null)

  if [ -n "$KEYS" ]; then
    # If keys exist, print them with the project prefix and set flag to true
    echo "$KEYS" | sed "s/^/$project: /"
    FOUND_KEYS=true
  fi
done

# Final check
if [ "$FOUND_KEYS" = false ]; then
  echo "No unrestricted keys found"
fi
