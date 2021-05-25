from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTClient
from AWSIoTPythonSDK.core.protocol.connection.cores import ProgressiveBackOffCore
from AWSIoTPythonSDK.exception.AWSIoTExceptions import connectTimeoutException
import logging
import time
import uuid
import random
import json
import os
import tempfile
import requests
import boto3
import boto3.exceptions
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from flask import Flask, request
import threading
from aws_auth import RequestWithAWSAuth

# Configure logging
logger = logging.getLogger("AWSIoTPythonSDK.core")
logger.setLevel(logging.ERROR)
streamHandler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
streamHandler.setFormatter(formatter)
logger.addHandler(streamHandler)

per_thread_message_count = 1
fleet_provisioning_template_name = "FleetHubDemo"
fleet_provisioning_thing_prefix = "FleetHubDemo"

# Progressive back off core
backOffCore = ProgressiveBackOffCore()

flaskapp = Flask(__name__)

registration_code = None
reg_api_success = False


@flaskapp.route('/regToken', methods=['POST'])
def receive_reg_code():
    if reg_api_success:
        return "Device Provisioning Successful", 200
    else:

        json_data = request.json
        global registration_code
        registration_code = json_data['registrationCode']

        return 'Activation Pending', 201


class IoTThing(AWSIoTMQTTClient):
    def __init__(self):
        self.serial_number = str(uuid.uuid4())
        self.thing_name = self.serial_number
        self.iot_endpoint = "{0}-ats.iot.{1}.amazonaws.com".format(
            os.environ.get("IOT_ENDPOINT"),
            os.environ.get("AWS_DEFAULT_REGION")
        )
        print("Using endpoint: {0}".format(self.iot_endpoint))
        super().__init__(self.serial_number)
        self.private_key, self.private_key_pem = self.generate_private_key()
        self.certificate_pem = None
        self.csr = self.gen_csr(self.private_key)

        # AWSIoTMQTTClient connection configuration

        self.configureEndpoint(self.iot_endpoint, 8883)
        self.configureAutoReconnectBackoffTime(1, 32, 20)
        self.configureOfflinePublishQueueing(-1)  # Infinite offline Publish queueing
        self.configureDrainingFrequency(20)  # Draining: 2 Hz
        self.configureConnectDisconnectTimeout(10)  # 10 sec
        self.configureMQTTOperationTimeout(10)  # 5 sec

        # End MQTT client configuration
        self.initial_shadow = {
            "battery_state_of_charge": random.choice([1, 10, 30, 90]),
            "firmware_version": random.choice(["0.1", "1.0", "1.5", "2.0"]),
            "temperature": 15,
            "location": random.choice(['nyc', 'atl', 'chi', 'la', 'sf', 'bos'])
        }
        self.shadow = self.initial_shadow

        print("Initialized new thing with serial: {0}".format(self.serial_number))
        self.fp_mqtt_client = None
        self.certificate_ownership_token = None
        self.cert_id = None
        self.app_mqtt_client = None
        self.open_jobs = dict()
        self.boto_session = None
        self.send_heartbeats = True
        self.wan_connection = 1

    def init_thing_in_iot(self, provisioning_type="self", init_listeners=True):
        print("Using direct AWS IoT provisioning")
        if provisioning_type == "self":
            self.certificate_pem = self.init_thing_with_boto()
        elif provisioning_type == "REG_API":
            print("Using registration API flow for provisioning")
            global registration_code
            threading.Thread(target=flaskapp.run, kwargs={'host':'0.0.0.0'}).start()
            reg_response = self.init_thing_with_reg_api()
            self.certificate_pem = reg_response['certificate']
            self.shadow['tenant'] = reg_response['tenant']

        # print("Attempting registration with Fleet Provisioning")
        # self.certificate_pem = self.init_thing_with_fp()

        if not self.certificate_pem:
            print("No certificate returned, unable to initialize device")
            raise Exception
        else:
            print("Retrieved certificate:")
            print(self.certificate_pem)

        self.init_app_mqtt_client(init_listeners)

    @staticmethod
    def generate_private_key(key_size=2048):
        print("Generating private key")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        return private_key, pem

    def gen_csr(self, private_key):
        print("Generating CSR")
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Acme-Co"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"{0}".format(self.thing_name)),

        ])).sign(private_key, hashes.SHA256(), default_backend())
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        print("Generated CSR:")
        print(csr_pem)
        return csr_pem

    def init_thing_with_reg_api(self):
        """
        This provisioning flow runs a local web server that waits for a registration code and then uses that
        registration code to call a registration API that returns a certificate

        :return:
        Certificate
        """

        global registration_code

        while not self.certificate_pem:
            if registration_code and registration_code != "INVALID":
                print("Received registration code:")
                print(registration_code)

                post_body = {
                    "csr": self.csr.decode('utf-8'),
                    "regToken": registration_code,
                    "serialNumber": self.serial_number
                }

                headers = {
                    "Content-Type": "application/json"
                }
                cert_response = requests.post(os.environ['REG_API'] + "/api/certificate", data=json.dumps(post_body), headers=headers)
                registration_code = None
                if cert_response.status_code == 200 and 'certificate' in cert_response.json():
                    return cert_response.json()
                else:
                    print("Error getting certificate, clearing registration code")
                    print(cert_response.text)
                    registration_code = "INVALID"
                    continue
            else:
                print("Waiting for registration code")
                time.sleep(3)
                continue


    def init_thing_with_boto(self):
        """
        This provisioning flow can register a thing directly with IoT Core if the client already has AWS credentials.
        This is primarily for demo purposes

        :return:
        Certificate
        """

        boto_iot_client = boto3.client('iot')
        print("Retrieving certificate")
        certificate_data = boto_iot_client.create_certificate_from_csr(
            certificateSigningRequest=self.csr.decode('utf-8'),
            setAsActive=True
        )
        print(certificate_data['certificatePem'].splitlines())

        f = open("iot_provisioning_template.json", "r")
        provisioning_template_string = f.read()
        prov_template_object = json.loads(provisioning_template_string)
        prov_template_object['Resources']['policy']['Properties']['PolicyName'] = os.environ['IOT_POLICY_NAME']
        boto_iot_client.register_thing(
            templateBody=json.dumps(prov_template_object),
            parameters={
                "SerialNumber": self.serial_number,
                "AWS::IoT::Certificate::Id": certificate_data['certificateId']
            }
        )
        return certificate_data['certificatePem']

    def init_app_mqtt_client(self, init_listeners=True):
        """
        Initializes the MQTT client using credentials previously retrieved and store in the object

        :param init_listeners:
        Optionally disable the listeners for the MQTT client for debugging purposes

        :return:
        None
        """
        print("Connecting MQTT client")

        pk_pem = "\n".join(self.private_key_pem.decode('utf-8').splitlines())
        pk_file = tempfile.NamedTemporaryFile()
        pk_file.write(pk_pem.encode('utf-8'))
        pk_file.flush()

        cert_pem = "\n".join(self.certificate_pem.splitlines())
        cert_file = tempfile.NamedTemporaryFile()
        cert_file.write(cert_pem.encode('utf-8'))
        cert_file.flush()

        self.configureCredentials("AmazonRootCA1.pem", pk_file.name, cert_file.name)

        attempts = 0
        time.sleep(1)
        while attempts < 5:
            try:
                self.connect()
                print("MQTT client connected")
                break
            except connectTimeoutException:
                print("Connection timed out, trying again")
                attempts += 1
                continue
        else:
            print("Too many attempts")
            raise Exception

        if init_listeners:
            self.shadow_listener("default")
            print("Initialized shadow listener")

            self.init_jobs_client()
            print("IoT Client initialization completed")

        print("Reporting initial shadow")
        self.report_shadow(self.shadow, "default", False)



    # Handle communication with AWS IoT Shadow Service
    def shadow_listener(self, shadow_name):
        self.subscribe("$aws/things/{0}/shadow/name/{1}/update/accepted".format(self.thing_name, shadow_name), 1, self.shadow_callback)

    def report_shadow(self, shadow_value, shadow_name, clear_desired=False):
        new_shadow = {
            "state": {
                "reported": shadow_value
            }
        }
        shadow_topic = "$aws/things/{0}/shadow/name/{1}/update".format(self.thing_name, shadow_name)
        if clear_desired:
            new_shadow['state']['desired'] = None
        self.publish(shadow_topic, json.dumps(new_shadow), 0)
        print("Reported shadow of:")
        print(shadow_value)

    def shadow_callback(self, _0, _1, message):
        payload = json.loads(message.payload)['state']
        print("Received a shadow update: ")
        print(payload)
        print("from topic: ")
        print(message.topic)
        print("--------------\n\n")
        if "desired" in payload.keys():
            if payload["desired"]:
                self.update_device_configuration_from_shadow_update(payload)
            else:
                print("No changes requested")
        else:
            print("No changes requested")

    def update_device_configuration_from_shadow_update(self, updated_shadow):
        time.sleep(3)
        for key, value in updated_shadow['desired'].items():
            if key == "heartbeat":
                self.send_heartbeats = value
            self.shadow[key] = value
        self.report_shadow(self.shadow, "default", True)

    # Handle communication with AWS IoT Jobs Service
    def init_jobs_client(self):
        print("Checking for outstanding jobs")
        self.subscribe("$aws/things/{0}/jobs/get/accepted".format(self.thing_name), 0, self.init_jobs_response)

        print("Subscribing to jobs detail topic")
        self.subscribe(
            "$aws/things/{0}/jobs/+/get/accepted".format(self.thing_name),
            0,
            self.job_detail_callback
        )
        self.publish(
            "$aws/things/{0}/jobs/get".format(self.thing_name),
            json.dumps({"clientToken": str(uuid.uuid4())}),
            0
        )
        time.sleep(2)
        print("Initializing new jobs listener")
        self.subscribe("$aws/things/{0}/jobs/notify".format(self.thing_name), 0, self.jobs_notification_callback)

    def init_jobs_response(self, _0, _1, message):
        payload = json.loads(message.payload)
        if "queuedJobs" in payload.keys():
            if payload['queuedJobs']:
                print("Existing queued jobs:")
                print(payload['queuedJobs'])
                self.jobs_handler(payload['queuedJobs'])
        if "inProgressJobs" in payload.keys():
            if payload['inProgressJobs']:
                print("Existing In-Progress Jobs")
                print(payload['inProgressJobs'])
                self.jobs_handler(payload['inProgressJobs'])

    def jobs_notification_callback(self, _0, _1, message):
        payload = json.loads(message.payload)
        print("Received new Jobs: ")
        print(payload)
        print("--------------\n\n")
        if 'QUEUED' in payload['jobs'].keys():
            self.jobs_handler(payload['jobs']['QUEUED'])

    def jobs_handler(self, jobs):
        for j in jobs:
            print("Processing job: {0}".format(j['jobId']))
            get_job_payload = {
                "clientToken": str(uuid.uuid4()),
                "includeJobDocument": True
            }
            base_job_topic = "$aws/things/{0}/jobs/{1}/".format(self.thing_name, j['jobId'])
            self.publish(
                "{0}get".format(base_job_topic),
                json.dumps(get_job_payload),
                0
            )

    def job_detail_callback(self, _0, _1, message):
        job_detail = json.loads(message.payload)['execution']
        print("Received job details:")
        print(job_detail)
        self.open_jobs[job_detail['jobId']] = job_detail
        self.acknowledge_job(job_detail['jobId'])

        operation, success = self.execute_job(job_detail['jobId'])

        if success:
            status = "SUCCEEDED"
        elif operation and not success:
            status = "FAILED"
        else:
            status = "REJECTED"

        set_final_job_status = {
            "status": status
        }
        print("Notifying AWS IoT of status, {0}, of job: {1}".format(status, job_detail['jobId']))
        self.publish(
            "$aws/things/{0}/jobs/{1}/update".format(self.thing_name, job_detail['jobId']),
            json.dumps(set_final_job_status),
            0
        )
        print("Removing job from open jobs")
        del(self.open_jobs[job_detail['jobId']])

        # self.unsubscribe(message.topic)

    def acknowledge_job(self, job_id):
        print("Acknowledging job {0} as IN_PROGRESS to IoT Jobs".format(job_id))
        set_job_to_pending_payload = {
            "status": "IN_PROGRESS",
            "clientToken": str(uuid.uuid4())
        }
        self.publish(
            "$aws/things/{0}/jobs/{1}/update".format(self.thing_name, job_id),
            json.dumps(set_job_to_pending_payload),
            0
        )

    def execute_job(self, job_id):
        job_details = self.open_jobs[job_id]
        job_document = job_details['jobDocument']
        if 'operation' in job_document.keys():
            # Pretend to do something successfully
            if job_document['operation'] == "FIRMWARE_UPGRADE":
                self.firmware_upgrade(job_document)
            elif job_document['operation'] == "ORDER_66":
                self.demo_connectivity_issues()
            elif job_document['operation'] == "REBOOT":
                self.reboot()
            else:
                print("Successfully performed {0} on device".format(job_document['operation']))
            return job_document['operation'], True
        else:
            print("Missing operation to be performed in job")
            return None, False

    @staticmethod
    def subscribe_callback(_0, _1, message):
        payload = json.loads(message.payload)
        print("Received a message: ")
        print(payload)
        print("from topic: ")
        print(message.topic)
        print("--------------\n\n")

    def get_sts_credentials(self):

        pk_pem = "\n".join(self.private_key_pem.decode('utf-8').splitlines())
        pk_file = tempfile.NamedTemporaryFile()
        pk_file.write(pk_pem.encode('utf-8'))
        pk_file.flush()

        cert_pem = "\n".join(self.certificate_pem.splitlines())
        cert_file = tempfile.NamedTemporaryFile()
        cert_file.write(cert_pem.encode('utf-8'))
        cert_file.flush()

        iot_headers = {
            "x-amzn-iot-thingname": self.thing_name
        }
        r = requests.get(
            'https://{0}.credentials.iot.{1}.amazonaws.com/role-aliases/{2}/credentials'.format(
                os.environ['CREDENTIAL_ENDPOINT'], os.environ['AWS_DEFAULT_REGION'], self.shadow['tenant']), headers=iot_headers, cert=(cert_file.name, pk_file.name),
            verify="/tmp/AmazonRootCA1.pem")
        print(r.status_code)
        sts_credentials = r.json()['credentials']
        self.boto_session = boto3.Session(
            aws_access_key_id=sts_credentials['accessKeyId'],
            aws_secret_access_key=sts_credentials['secretAccessKey'],
            aws_session_token=sts_credentials['sessionToken']
        )

        print(sts_credentials)

    def upload_file_to_s3(self, body="Hello world"):
        files = {"file": body}
        s3_metadata_api_url = "{0}/api/upload".format(os.environ['REG_API'])
        # Instantiate API client with AWS SigV4 signed headers
        # And then send request to endpoint (API Gateway) to retrieve pre-signed URL
        api_client = RequestWithAWSAuth(request_url=s3_metadata_api_url, boto_session=self.boto_session)
        s3_data, status_code = api_client.get(s3_metadata_api_url)
        s3_presigned_url = json.loads(s3_data)['presignedUrl']
        print(s3_presigned_url)

        # Upload file to S3 with pre-signed URL
        presigned_s3_response = requests.put(s3_presigned_url, data=body)
        print(presigned_s3_response.text)
        print(presigned_s3_response.status_code)
        if presigned_s3_response.status_code == 200:
            print("Successfully uploaded data to S3 pre-signed URL")

        # Now we're going to upload data using the standard S3 client
        # using the permissions provided by the credentials provider
        upload_bucket = json.loads(s3_data)['uploadBucket']
        s3_client = self.boto_session.resource('s3')
        upload_bucket = s3_client.Bucket(upload_bucket)
        upload_bucket.put_object(
            Key="{0}/sampledata_{1}".format(self.thing_name, str(uuid.uuid4())[:5]),
            Body=b'Sample Data from Boto client'
        )
        print("Successfully uploaded object to S3 via Boto")

    def firmware_upgrade(self, job_document):
        self.shadow['firmware_version'] = job_document['firmware_version']
        self.report_shadow({"firmware_version": job_document['firmware_version']}, "default")

    def heartbeater(self):
        while True:
            if self.send_heartbeats:
                print("Sending heartbeat message")
                self.publish("demofleet/{0}/heartbeat".format(self.thing_name), "alive", 1)
                if self.shadow['temperature'] != 100:
                    new_shadow = {"desired": {"temperature": random.choice([10, 11, 12, 13, 14, 15, 16])}}
                    self.update_device_configuration_from_shadow_update(new_shadow)
                    print("Updated shadow with new temperature: {0}".format(new_shadow['desired']['temperature']))
            time.sleep(3)

    def demo_connectivity_issues(self):
        if self.shadow['battery_state_of_charge'] < 3:
            print("Battery low, shutting down")
            self.send_heartbeats = False
            time.sleep(2)
            self.disconnect()
            sys.exit(0)

        elif self.shadow['firmware_version'] == "0.1":
            print("Unhandled exception")
            sys.exit(1)

        elif self.shadow['location'] == 'atl':
            print("Temperature sensor stopped working, changing to 100")
            new_shadow = {"desired": {"temperature": 100}}
            self.update_device_configuration_from_shadow_update(new_shadow)

        elif self.shadow['firmware_version'] == "1.0":
            print("Minor bug in old firmware, can no longer update telemetry data")
            self.send_heartbeats = False

        # if self.shadow['location'] == 'chi':
        #     self.send_heartbeats = False
        #     time.sleep(2)
        #     self.disconnectAsync()
        #     time.sleep(15)
        #     while self.wan_connection == 1:
        #         self.connect(5)
        #         self.init_jobs_client()
        #         time.sleep(5)
        #         self.disconnectAsync()
        #         time.sleep(15)
        #     else:
        #         self.connect(5)
        #         self.init_jobs_client()
        #         self.init_shadow_client()
        #         self.send_heartbeats = True

    def reboot(self):
        print("Rebooting device")
        self.send_heartbeats = False
        time.sleep(3)
        print("Disconnecting MQTT")
        self.disconnectAsync()
        time.sleep(3)
        self.connect()
        self.shadow_listener("default")
        self.init_jobs_client()
        self.heartbeater()


if __name__ == "__main__":
    thing = IoTThing()
    thing.init_thing_in_iot(provisioning_type="REG_API")
    thing.get_sts_credentials()
    thing.upload_file_to_s3()
    # thing.heartbeater()

