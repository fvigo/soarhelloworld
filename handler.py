import json
import boto3
import os
import datetime
import uuid
import logging
import re
import random
import whois
logger = logging.getLogger()
logger.setLevel(logging.INFO)

S3_BUCKET = os.environ.get('S3_BUCKET', None)
JSON_FILE = os.environ.get('JSON_FILE', None)
API_KEY = os.environ.get('API_KEY', None)

def unpack_exception(e):
    if not isinstance(e, BaseException):
        return None
    if not hasattr(e,'args'):
        return None
    if len(e.args) != 1:
        return None
    if not isinstance(e.args[0], dict):
        return None
    ex = e.args[0]
    if not ex.get('code', None):
        return None
    if not ex.get('err', None):
        return None
    return ex

def authenticate(event):
        # Check environment variables
        if not S3_BUCKET or not JSON_FILE or not API_KEY:
            raise RuntimeError({'code': 500,'err': 'Environment variables not set'})

        # Check Method
        # logger.info(f'event received and is: {dir(event)}')
        if 'httpMethod' not in event or event['httpMethod'] != 'GET':
            raise ValueError({'code': 400,'err': f'HTTP Method error'})
    
        # Check API KEY
        headers = event.get('headers', None)
        if not headers:
            raise ValueError({'code': 403, 'err': 'No Headers'})
        authorization = headers.get('Authorization', None)
        if not authorization:
            raise ValueError({'code': 403, 'err': 'No Authorization'})
        auth_reg = re.match('^Bearer (\w+)*$', authorization)
        # logger.info(f'Auth_Reg Groups is: {auth_reg.groups()}, len: {len(auth_reg.groups())}')
        if not auth_reg or len(auth_reg.groups()) != 1 or auth_reg.group(1) != API_KEY:
            raise ValueError({'code': 403, 'err': 'Invalid Authorization'})
        
        return

def get_domain(event, content):
    response = None
    try:
        # Check method and authenticate
        authenticate(event)

        # Check Domain
        severity = None
        query_string_parameters = event.get('queryStringParameters', None)
        if not query_string_parameters:
            raise ValueError({'code': 400, 'err': 'No domain provided'})

        domain = query_string_parameters.get('domain', None)
        if not domain:
            raise ValueError({'code': 400, 'err': 'No domain provided'})

        who = whois.query(domain)
        if who:
            response = {
                "statusCode": 200,
                "body": json.dumps(who)
            }
        else:
            response = {
                "statusCode": 404,
                "body": "Domain not found!"
            } 

    except Exception as e:
        ex_args = unpack_exception(e)
        if ex_args:
            response = {
                "statusCode": ex_args['code'],
                "body": ex_args['err']
            }
        else:
            response = {
                "statusCode": 500,
                "body": f"Input Error: {str(e)}"
            }    

    return response


def get_alerts(event, context):
    response = None
    try:
        # Check method and authenticate
        authenticate(event)

        # Check Severity filter
        severity = None
        query_string_parameters = event.get('queryStringParameters', None)
        if query_string_parameters:
            severity = int(query_string_parameters.get('severity', None))

        s3 = boto3.resource('s3')
        obj = s3.Object(S3_BUCKET, JSON_FILE)
        file_content = obj.get()['Body'].read().decode('utf-8')
        events = json.loads(file_content)

        now = int(datetime.datetime.utcnow().timestamp())

        alerts = []
        for e in events:
            # filter
            if severity:
                if 'severity' not in e:
                    continue
                if e['severity'] != severity:
                    continue
            e['created'] = now
            e['alert_id'] = str(uuid.uuid4())
            alerts.append(e)

        response = {
            "statusCode": 200,
            "body": json.dumps(alerts)
        }
    except Exception as e:
        ex_args = unpack_exception(e)
        if ex_args:
            response = {
                "statusCode": ex_args['code'],
                "body": ex_args['err']
            }
        else:
            response = {
                "statusCode": 500,
                "body": f"Input Error: {str(e)}"
            }    

    return response
