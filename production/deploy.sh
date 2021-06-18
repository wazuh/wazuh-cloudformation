# Deploy a CloudFormation Wazuh stack

#!/bin/bash

# Path of the parameters JSON file
PARAMS_FILE='./parameters.json'

# Path of the template file
TEMPLATE_FILE='./wazuh_template.yml'

# Stack name
STACK_NAME='cf-test-w4-16'

# Bucket name
BUCKET_NAME='cloudformation-stack-test-w4-1-5-us-east-1'

# Region
REGION='us-east-1'

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
if [ $REGION == 'us-east-1' ]; then
  URL="https://$BUCKET_NAME.s3.amazonaws.com/wazuh_template.yml"
else
  URL="https://$BUCKET_NAME.s3-$REGION.amazonaws.com/wazuh_template.yml"
fi



echo "Template URL: $URL"

# Set default REGION
export AWS_DEFAULT_REGION=$REGION

aws cloudformation create-stack --stack-name ${STACK_NAME} --template-url $URL --parameters file://$PARAMS_FILE --capabilities CAPABILITY_IAM --tags Key=service_name,Value=demo_info

echo "Done"
