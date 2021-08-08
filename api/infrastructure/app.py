#!/usr/bin/env python3
import os
from aws_cdk import core as cdk
from stacks.chaliceapp import ChaliceApp


app = cdk.App()
ChaliceApp(app, os.environ.get('STACK_NAME', 'device-registration-api')

app.synth()
