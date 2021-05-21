import os

from aws_cdk import (
    aws_dynamodb as dynamodb,
    core as cdk,
)
from aws_cdk.aws_iam import ManagedPolicy
from aws_cdk.aws_iot import CfnPolicy
from chalice.cdk import Chalice
from aws_cdk import aws_s3
from aws_cdk.aws_iam import Role, ServicePrincipal, PolicyStatement

RUNTIME_SOURCE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), os.pardir, 'runtime')


class ChaliceApp(cdk.Stack):

    def __init__(self, scope, id, **kwargs):
        super().__init__(scope, id, **kwargs)

        self.chalice = Chalice(
            self, 'ChaliceApp', source_dir=RUNTIME_SOURCE_DIR
        )

        # things_registration_policy = ManagedPolicy.from_aws_managed_policy_name('AWSIoTThingsRegistration')
        # self.chalice.get_role('DefaultRole').add_managed_policy(things_registration_policy)

        self.iot_policy = CfnPolicy(self, 'IoTPolicy', policy_document=iot_default_policy, policy_name='ScopedPolicy')

        self.dynamodb_table = self._create_ddb_table()

        self.s3_upload_bucket = self._create_s3_upload_bucket()

        self.credential_provider_role = self._create_credential_provider_role()

        self._attach_permissions()

    def _create_s3_upload_bucket(self):
        s3_bucket = aws_s3.Bucket(
            self,
            "iot-device-upload-bucket"
        )
        self.chalice.add_environment_variable(
            key='APP_UPLOAD_BUCKET',
            value=s3_bucket.bucket_name,
            function_name='APIHandler'
        )

        return s3_bucket

    def _create_ddb_table(self):

        dynamodb_table = dynamodb.Table(
            self, 'deviceRegTokens',
            partition_key=dynamodb.Attribute(
                name='regToken', type=dynamodb.AttributeType.STRING),
            removal_policy=cdk.RemovalPolicy.DESTROY)
        self.chalice.add_environment_variable(
            key='APP_TABLE_NAME',
            value=dynamodb_table.table_name,
            function_name='APIHandler'
        )

        cdk.CfnOutput(self, 'AppTableName',
                      value=dynamodb_table.table_name)
        return dynamodb_table

    def _attach_permissions(self):
        self.dynamodb_table.grant_read_write_data(
            self.chalice.get_role('DefaultRole')
        )
        self.s3_upload_bucket.grant_read_write(
            self.chalice.get_role('DefaultRole')
        )
        chalice_role = self.chalice.get_resource('DefaultRole')
        chalice_role.managed_policy_arns = ['arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration']

    def _create_credential_provider_role(self):

        credential_provider_role = Role(
            self,
            "AWSIoTCredentialProviderRole",
            assumed_by=ServicePrincipal("credentials.iot.amazonaws.com"),
        )
        rest_api_id = self.chalice.get_resource("RestAPI")
        credential_provider_role.add_to_policy(PolicyStatement(
            resources=["arn:aws:execute-api:*:*:{0}/api/*/*".format(rest_api_id.ref)],
            actions=["execute-api:Invoke"]
        ))
        credential_provider_role.add_to_policy(PolicyStatement(
            resources=[self.s3_upload_bucket.bucket_arn],
            actions=["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
        ))
        return credential_provider_role

iot_default_policy = {
    "Statement": [
        {
            "Action": "iot:Connect",
            "Condition": {
                "ForAllValues:StringEquals": {
                    "iot:Certificate.Subject.CommonName": "${iot:Connection.Thing.ThingName}"
                }
            },
            "Effect": "Allow",
            "Resource": {
                "Fn::Sub": "arn:aws:iot:${AWS::Region}:${AWS::AccountId}:client/${!iot:Connection.Thing.ThingName}"
            }
        },
        {
            "Action": "iot:Publish",
            "Effect": "Allow",
            "Resource": [
                {
                    "Fn::Sub": "arn:aws:iot:${AWS::Region}:${AWS::AccountId}:topic/demofleet/${!iot:Connection.Thing.ThingName}*"
                },
                {
                    "Fn::Sub": "arn:aws:iot:${AWS::Region}:${AWS::AccountId}:topic/$aws/things/${!iot:Connection.Thing.ThingName}*"
                }
            ]
        },
        {
            "Action": "iot:Subscribe",
            "Effect": "Allow",
            "Resource": [
                {
                    "Fn::Sub": "arn:aws:iot:${AWS::Region}:${AWS::AccountId}:topicfilter/demofleet/${!iot:Connection.Thing.ThingName}*"
                },
                {
                    "Fn::Sub": "arn:aws:iot:${AWS::Region}:${AWS::AccountId}:topicfilter/$aws/things/${!iot:Connection.Thing.ThingName}*"
                }
            ]
        },
        {
            "Action": "iot:Receive",
            "Effect": "Allow",
            "Resource": [
                {
                    "Fn::Sub": "arn:aws:iot:${AWS::Region}:${AWS::AccountId}:topic/demofleet/${!iot:Connection.Thing.ThingName}*"
                },
                {
                    "Fn::Sub": "arn:aws:iot:${AWS::Region}:${AWS::AccountId}:topic/$aws/things/${!iot:Connection.Thing.ThingName}*"
                }
            ]
        },
        {
            "Action": "iot:AssumeRoleWithCertificate",
            "Effect": "Allow",
            "Resource": [
                {
                    "Fn::Sub": "arn:aws:iot:${AWS::Region}:${AWS::AccountId}:rolealias/${!iot:Connection.Thing.Attributes[tenant]}"
                }
            ]
        }
    ],
    "Version": "2012-10-17"
}