# Deploy a CloudFormation Wazuh stack

#!/bin/bash

# Path of the parameters JSON file
PARAMS_FILE='./parameters.json'

# Path of the template file
TEMPLATE_FILE='./wazuh_template.yml'

# Stack name
STACK_NAME='sources-311mitre'

# Bucket name
BUCKET_NAME='demo-cloudformation-templates'

# If any file doesn't exist, then break the execution
if ! [ -f "$PARAMS_FILE" ] || ! [ -f "$TEMPLATE_FILE" ]; then
    echo "Missing template path or parameters file."
    exit
fi

# Checking arguments
if [ "$STACK_NAME" == "" ] || [ "$BUCKET_NAME" == "" ]; then
    echo "Missing template path or parameters file."
    exit
fi

# Uploading template to S3
aws s3 cp $TEMPLATE_FILE s3://$BUCKET_NAME

# Getting the template URL
URL="https://demo-cloudformation-templates.s3-us-west-1.amazonaws.com/wazuh_template.yml"
echo "Template URL: $URL"

aws cloudformation create-stack --stack-name ${STACK_NAME} --template-url $URL --parameters file://$PARAMS_FILE --capabilities CAPABILITY_IAM

echo "Done"