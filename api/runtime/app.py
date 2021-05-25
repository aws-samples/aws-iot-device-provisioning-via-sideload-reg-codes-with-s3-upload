import os
import boto3
from chalice import Chalice, Response
from chalice import IAMAuthorizer
import uuid
import random
import time
import logging
import json
import re

app = Chalice(app_name='device-registration-api')
app.log.setLevel(logging.DEBUG)

authorizer = IAMAuthorizer()

dynamodb = boto3.resource('dynamodb')
dynamodb_table = dynamodb.Table(os.environ.get('APP_TABLE_NAME', ''))
upload_bucket = os.environ.get('APP_UPLOAD_BUCKET', '')

iot_client = boto3.client('iot')

tenant_names = ['acme']
locations = ['bos', 'jfk', 'lax', 'sfo', 'atl', 'chi']
device_type = ['deviceTypeA']


@app.route('/token', methods=['GET'])
def create_token():
    reg_token = str(uuid.uuid4())
    item = {
        'regToken': reg_token,
        'location': random.choice(locations),
        'tenant': random.choice(tenant_names),
        'deviceType': random.choice(device_type),
        'timestamp': int(time.time()),
        'timesUsed': 0
    }
    dynamodb_table.put_item(Item=item)
    return {"registrationToken": reg_token}


@app.route('/certificate', methods=['POST'])
def get_certificate():
    request = app.current_request
    body = request.json_body
    app.log.debug(body)
    if body and 'regToken' in body.keys() and body['regToken']:
        if 'csr' in body.keys() and body['csr']:
            if 'serialNumber' in body.keys() and body['serialNumber']:
                csr = body['csr']
                dynamo_response, status_code = retrieve_metadata_for_token(body)
                if status_code == 200:
                    certificate_pem = register_thing(csr, dynamo_response, body['serialNumber'])
                    response_body = {
                        "certificate": certificate_pem,
                        "tenant": dynamo_response['tenant']
                    }
                else:
                    response_body = dynamo_response
            else:
                response_body = 'Missing serial number'
                status_code = 400
        else:
            response_body = 'Missing or invalid csr'
            status_code = 400
    else:
        response_body = 'Missing or invalid registration token'
        status_code = 400
    return Response(body=response_body, status_code=status_code, headers={'Content-Type': 'application/json'})


@app.route('/upload', methods=['GET'], authorizer=authorizer)
def upload_files():
    request = app.current_request
    context = request.context
    print("Context:")
    print(context)
    caller_identity = context['identity']['caller']
    caller_ex = ":(.+)$"
    cert_id = re.search(caller_ex, caller_identity).group(1)

    iot = boto3.client("iot")

    certificate_arn = iot.describe_certificate(
        certificateId=cert_id
    )['certificateDescription']['certificateArn']

    things = iot.list_principal_things(
        principal=certificate_arn
    )['things']
    thing_name = things[0]
    thing_info = iot.describe_thing(
        thingName=thing_name
    )
    s3 = boto3.client('s3')

    presigned_url = s3.generate_presigned_url(
        "put_object",
        Params={
            'Bucket': upload_bucket,
            'Key': "{0}/{1}/sampledata_{2}".format(
                thing_info['attributes']['tenant'], thing_name, str(uuid.uuid4())[:5]
            )
        },
        ExpiresIn=600
    )
    response = {
        "presignedUrl": presigned_url,
        "uploadBucket": upload_bucket
    }
    return response


def retrieve_metadata_for_token(body):
    key = {
        'regToken': body['regToken']
    }
    dynamo_response = dynamodb_table.get_item(
        Key=key
    )
    app.log.debug("Dynamo returned:")
    app.log.debug(dynamo_response)
    oldest_valid_time = int(time.time()) - 300  # Token expires after 5 minutes
    if 'Item' in dynamo_response.keys():
        item = dynamo_response['Item']
        times_used = int(item['timesUsed'])
        if times_used == 0 and item['timestamp'] >= oldest_valid_time:  # Token expires after 5 minutes
            dynamodb_table.update_item(
                Key=key,
                UpdateExpression="SET timesUsed = timesUsed + :u",
                ExpressionAttributeValues={
                    ':u': 1,
                }
            )
            del item['regToken']
            del item['timesUsed']
            del item['timestamp']
            item['certificate'] = "test"
            response = item, 200
        elif times_used != 0:
            response = 'Token already used', 401
        elif item['timestamp'] < oldest_valid_time:
            response = 'Token expired', 401
        else:
            raise Exception
    else:
        response = 'Missing or invalid registration token', 400
    return response


def register_thing(csr, metadata, serial_number):

    iot_response = iot_client.register_thing(
        templateBody=json.dumps(iot_provisioning_template),
        parameters={
            'Location': metadata['location'],
            'SerialNumber': serial_number,
            'CSR': csr,
            'Tenant': metadata['tenant'],
            'DeviceType': metadata['deviceType']
        }
    )
    return iot_response['certificatePem']


iot_provisioning_template = {
    "Parameters": {
        "SerialNumber": {
            "Type": "String"
        },
        "Location": {
            "Type": "String",
            "Default": "WA"
        },
        "CSR": {
            "Type": "String"
        },
        "Tenant": {
            "Type": "String"
        },
        "DeviceType": {
            "Type": "String"
        }
    },
    "Resources": {
        "thing": {
            "Type": "AWS::IoT::Thing",
            "Properties": {
                "ThingName": {"Ref": "SerialNumber"},
                "AttributePayload": {
                    "hardwareVersion": "v1",
                    "serialNumber":  {"Ref": "SerialNumber"},
                    "tenant": {"Ref": "Tenant"}
                },
                "ThingTypeName": {"Ref": "DeviceType"}
            }
        },
        "certificate": {
            "Type": "AWS::IoT::Certificate",
            "Properties": {
                "CertificateSigningRequest": {"Ref": "CSR"},
                "Status": "ACTIVE"
            }
        },
        "policy": {
          "Properties": {
            "PolicyName": "ScopedPolicy"
          },
          "Type": "AWS::IoT::Policy"
        }
    }
}
