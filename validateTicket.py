import boto3
import json
from decimal import Decimal
from datetime import datetime

dynamodb = boto3.resource('dynamodb')
tickets_table = dynamodb.Table('Tickets')

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return int(obj)
        return super().default(obj)

def lambda_handler(event, context):
    
    body = json.loads(event.get('body') or '{}')
    ticket_id = body.get('ticket_id', '')
    
    if not ticket_id:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'ticket_id is required'})
        }
    
    # Step 1 - Fetch ticket
    response = tickets_table.get_item(
        Key={'ticket_id': ticket_id}
    )
    
    ticket = response.get('Item', None)
    
    if not ticket:
        return {
            'statusCode': 404,
            'body': json.dumps({
                'valid': False,
                'error': 'Ticket not found. Possible fake ticket'
            })
        }
    
    # Step 2 - Check ticket status
    if ticket['status'] == 'USED':
        return {
            'statusCode': 409,
            'body': json.dumps({
                'valid': False,
                'error': 'Ticket already used. Possible duplicate scan'
            })
        }
    
    if ticket['status'] == 'CANCELLED':
        return {
            'statusCode': 409,
            'body': json.dumps({
                'valid': False,
                'error': 'Ticket has been cancelled'
            })
        }
    
    # Step 3 - Mark ticket as USED
    validated_at = datetime.utcnow().isoformat()
    
    tickets_table.update_item(
        Key={'ticket_id': ticket_id},
        UpdateExpression='SET #s = :used, validated_at = :time',
        ExpressionAttributeNames={'#s': 'status'},
        ExpressionAttributeValues={
            ':used': 'USED',
            ':time': validated_at
        }
    )
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'valid': True,
            'message': 'Ticket validated successfully. Passenger may board',
            'ticket_id': ticket['ticket_id'],
            'route_id': ticket['route_id'],
            'seat_number': ticket['seat_number'],
            'travel_date': ticket['travel_date'],
            'user_id': ticket['user_id'],
            'validated_at': validated_at
        }, cls=DecimalEncoder)
    }
