import boto3
import json
from boto3.dynamodb.conditions import Attr
from decimal import Decimal

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Schedules')

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return int(obj)
        return super().default(obj)

def lambda_handler(event, context):

    try:
        params = event.get('queryStringParameters') or {}
        route_id = params.get('route_id', '')
        date = params.get('date', '')
        
        if not route_id or not date:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'route_id and date are required'})
            }
        
        schedule_id = f"{route_id}#{date}"
        
        response = table.get_item(
            Key={'schedule_id': schedule_id}
        )
        
        schedule = response.get('Item', None)
        
        if not schedule:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'No schedule found'})
            }
        
        booked_seats = list(schedule.get('booked_seats', []))
        
        all_seats = [f"{row}{num}" for row in ['A','B','C','D','E'] for num in range(1, 9)]
        available_seats = [seat for seat in all_seats if seat not in booked_seats]
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'schedule_id': str(schedule['schedule_id']),
                'route_id': str(schedule['route_id']),
                'date': str(schedule['date']),
                'available_seats': available_seats,
                'booked_seats': booked_seats,
                'seats_remaining': int(schedule['available_seats'])
            })
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
