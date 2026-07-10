import boto3
import json
import uuid
from boto3.dynamodb.conditions import Attr
from decimal import Decimal
from datetime import datetime

dynamodb = boto3.resource('dynamodb')
schedules_table = dynamodb.Table('Schedules')
bookings_table = dynamodb.Table('Bookings')
tickets_table = dynamodb.Table('Tickets')

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return int(obj)
        return super().default(obj)

def lambda_handler(event, context):
    
    
    body = json.loads(event.get('body') or '{}')
    user_id = body.get('user_id', '')
    schedule_id = body.get('schedule_id', '')
    seat_number = body.get('seat_number', '')
    amount_paid = body.get('amount_paid', 0)
    
    
    if not user_id or not schedule_id or not seat_number:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'user_id, schedule_id and seat_number are required'})
        }
    
    
    schedule_response = schedules_table.get_item(
        Key={'schedule_id': schedule_id}
    )
    
    schedule = schedule_response.get('Item', None)
    
    if not schedule:
        return {
            'statusCode': 404,
            'body': json.dumps({'error': 'Schedule not found'})
        }
    
    booked_seats = schedule.get('booked_seats', [])
    
    if seat_number in booked_seats:
        return {
            'statusCode': 409,
            'body': json.dumps({'error': 'Seat already booked. Please select another seat'})
        }
    
    
    try:
        schedules_table.update_item(
            Key={'schedule_id': schedule_id},
            UpdateExpression='SET booked_seats = list_append(booked_seats, :seat), available_seats = available_seats - :one',
            ConditionExpression=Attr('available_seats').gt(0) & ~Attr('booked_seats').contains(seat_number),
            ExpressionAttributeValues={
                ':seat': [seat_number],
                ':one': Decimal('1')
            }
        )
    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        return {
            'statusCode': 409,
            'body': json.dumps({'error': 'Seat was just booked by someone else. Please select another seat'})
        }
    
   
    booking_id = str(uuid.uuid4())
    booked_at = datetime.utcnow().isoformat()
    
    bookings_table.put_item(
        Item={
            'booking_id': booking_id,
            'user_id': user_id,
            'schedule_id': schedule_id,
            'seat_number': seat_number,
            'status': 'CONFIRMED',
            'amount_paid': Decimal(str(amount_paid)),
            'booked_at': booked_at
        }
    )
    
    
    ticket_id = str(uuid.uuid4())
    route_id = schedule['route_id']
    travel_date = schedule['date']
    
    tickets_table.put_item(
        Item={
            'ticket_id': ticket_id,
            'booking_id': booking_id,
            'user_id': user_id,
            'route_id': route_id,
            'travel_date': travel_date,
            'seat_number': seat_number,
            'status': 'VALID',
            'qr_code': ticket_id,
            'issued_at': booked_at
        }
    )
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Booking confirmed!',
            'booking_id': booking_id,
            'ticket_id': ticket_id,
            'seat_number': seat_number,
            'travel_date': travel_date,
            'route_id': route_id,
            'qr_code': ticket_id
        }, cls=DecimalEncoder)
    }
