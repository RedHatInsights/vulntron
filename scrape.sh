#!/bin/bash

if [ "$#" -eq 1 ]; then
    demo_file="$1"

    next_line_flag=false

    # Loop through file
    while IFS= read -r line; do
        if [[ "$line" == "Name:"* ]]; then
            next_line_flag=true
            deployment=$(echo "$line" | awk '{print $2}')
        elif [ "$next_line_flag" = true ] && [[ "$line" == "Namespace:"* ]]; then
            next_line_flag=false
            image_name=$(grep "Image:" "$demo_file" | awk '{print $2}')
            deployment_date=$(grep "CreationTimestamp:" "$demo_file" | awk '{print $3, $4, $5, $6, $7}')
            component_name="$deployment"  

            echo "Running vulntron for image: $image_name"
            bin/vulntron --type auto --config config.yaml --imagename "$image_name" --timestamp "$deployment_date" --component "$component_name"
        fi
    done < "$demo_file"
fi