import boto3
import json
from boto3.dynamodb.conditions import Attr
from decimal import Decimal

dynamodb = boto3.resource('dynamodb')
tickets_table = dynamodb.Table('Tickets')

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return int(obj)
        return super().default(obj)

def lambda_handler(event, context):
    
    params = event.get('queryStringParameters') or {}
    user_id = params.get('user_id', '')
    
    if not user_id:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'user_id is required'})
        }
    
    response = tickets_table.scan(
        FilterExpression=Attr('user_id').eq(user_id)
    )
    
    tickets = response.get('Items', [])
    
    if not tickets:
        return {
            'statusCode': 404,
            'body': json.dumps({'error': 'No tickets found for this user'})
        }
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'user_id': user_id,
            'total_tickets': len(tickets),
            'tickets': tickets
        }, cls=DecimalEncoder)
    }
