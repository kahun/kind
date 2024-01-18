#!/bin/bash

# Default provider value
provider="aws"
directory="./images/aws"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in
        -p|--provider)
            provider="$2"
            shift
            shift
            ;;
        -d|--directory)
            directory="$2"
            shift
            shift
            ;;
        *)
            # unknown option
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if the provider is supported
case $provider in
    aws|azure|gcp)
        ;;
    *)
        echo "Provider not supported: $provider"
        exit 1
        ;;
esac

# Check if the directory exists
if [ ! -d "$directory" ]; then
    echo "The directory '$directory' does not exist."
    exit 1
fi

# File that contains the name of the new registry
registry_file="$directory/REGISTRY"

# Check if the registry file exists
if [ ! -f "$registry_file" ]; then
    echo "The registry file '$registry_file' does not exist in the specified directory."
    exit 1
fi

# Read the first line that does not start with '#' from the file
new_registry=$(grep -v '^#' "$registry_file" | grep -m 1 .)

# Process all text files in the directory
for images_file in "$directory"/*.txt; do
    # Check if the file is readable
    if [ -r "$images_file" ]; then
        echo "Processing file: $images_file with new registry: $new_registry"
        
        # Read the file of image lists line by line
        while IFS= read -r line
        do
            # Skip empty lines
            if [ -z "$line" ]; then
                continue
            fi
            
            line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            echo "Downloading the image: $line"
            docker pull "$line"

            # Split the line by "/" and replace only the first element with the new registry
            IFS='/' read -ra parts <<< "$line"
            parts[0]="$new_registry"
            new_image="$(IFS=/ ; echo "${parts[*]}")"

            # Rename the image
            echo "Renaming the image: $new_image"
            docker tag "$line" "$new_image"

            if [ "$provider" == "aws" ]; then
                # Check and create repository only if the provider is AWS
                repository_flag_found=false
                ecr_repo="$(echo $new_image | cut -d "/" -f2- | rev | cut -d ":" -f2- | rev)"
                echo "ecr_repo value $ecr_repo"
                REPO_LIST=$(aws ecr describe-repositories --query "repositories[].repositoryName" --output text --region eu-west-1);
                echo "ok repos"
                for repo in $REPO_LIST; do
                    if [ $ecr_repo = $repo ]; then
                        echo "The repository $repo already exists"
                        repository_flag_found=true
                        break
                    fi
                done

                if [[ "$repository_flag_found" = false ]]; then
                    echo "Creating repository $ecr_repo"
                    aws ecr create-repository --repository-name $ecr_repo 
                fi
            fi

            # Push the image to the new registry
            echo "Pushing the image to the new registry: $new_image"
            docker push "$new_image"

        done < "$images_file"
        
        echo "Process completed for $images_file"
    else
        echo "The file $images_file is not readable. Skipping file."
    fi
done