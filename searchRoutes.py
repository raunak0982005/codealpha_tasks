import boto3
import json
from boto3.dynamodb.conditions import Attr
from decimal import Decimal

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Routes')

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return int(obj)
        return super().default(obj)

def lambda_handler(event, context):

    print("EVENT:", json.dumps(event))
    
    params = event.get('queryStringParameters') or {}
    source = params.get('source', '')
    destination = params.get('destination', '')
    
    if not source or not destination:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'source and destination are required'})
        }
    
    response = table.scan(
        FilterExpression=Attr('source').eq(source) & Attr('destination').eq(destination)
    )
    
    routes = response.get('Items', [])
    
    if not routes:
        return {
            'statusCode': 404,
            'body': json.dumps({'error': 'No routes found'})
        }
    
    return {
        'statusCode': 200,
        'body': json.dumps(routes, cls=DecimalEncoder)
    }
