Task 3: Bus Pass Management System
Overview

A serverless Bus Pass Management System built using AWS services. The application provides APIs for passengers to search routes, book seats, validate tickets, and retrieve travel information through independent AWS Lambda functions.

Features
Search available bus routes
Book seats
Retrieve passenger tickets
View bus schedules
Validate booked tickets
Lambda Functions
File	Description
searchRoutes.py	Search available bus routes
bookSeat.py	Book a seat for a passenger
getMyTickets.py	Retrieve booked tickets
getSchedule.py	Get bus schedules
validateTicket.py	Validate passenger tickets
Technologies Used
AWS Lambda
Python
Amazon DynamoDB
API Gateway


Task 1: Data Redundancy Removal System (AWS)

Overview

This project implements a Data Redundancy Removal System using AWS serverless services. The system validates incoming records, detects duplicate entries using SHA-256 hashing, and stores only unique records in a DynamoDB table.

The objective is to improve database accuracy and prevent redundant data from being stored in the cloud.

------------------------------------------------------------------------------------

Features

- Validate incoming data
- Normalize input fields (trim spaces and convert text to lowercase)
- Generate a SHA-256 hash for each record
- Detect duplicate records efficiently
- Prevent duplicate insertion using DynamoDB Conditional Writes
- Store only unique and verified records
- Serverless architecture using AWS Lambda

---------------------------------------------------------------------------------------------

Tech Stack

- AWS Lambda – Serverless backend
- Amazon DynamoDB – NoSQL cloud database
- Python 3.x
- Boto3 – AWS SDK for Python
- SHA-256 (hashlib) – Duplicate detection


Database Schema

Table Name: "unique_records"

Partition Key: "hash" (String)

Example item:

{
  "hash": "a3f1b4c7...",
  "name": "John Doe",
  "email": "john@example.com",
  "phone": "1234567890",
  "created_at": "2026-07-10T10:30:00Z"
}

------------------------------------------------------------------------

How It Works

1. Receive a new record.
2. Validate the required fields.
3. Normalize the input data.
4. Generate a SHA-256 hash from the normalized fields.
5. Attempt to insert the record into DynamoDB.
6. If the hash already exists, reject the record as a duplicate.
7. Otherwise, store the record successfully.

---------------------------------------------------------------------

Example Request

{
  "name": "John Doe",
  "email": "john@example.com",
  "phone": "1234567890"
}

---------------------------------------------------------------------

Example Responses

New Record

{
  "message": "Record added successfully",
  "duplicate": false
}

Duplicate Record

{
  "message": "Duplicate record detected",
  "duplicate": true
}

---------------------------------------------------------

Future Improvements

- Fuzzy duplicate detection
- Email and phone format validation
- API Gateway integration
- CloudWatch logging and monitoring
- Unit tests
- Secondary indexes for advanced searching

------------------------------------------------

Learning Outcomes

Through this project, I learned:

- AWS Lambda fundamentals
- Amazon DynamoDB operations
- Serverless application development
- Data normalization techniques
- SHA-256 hashing
- Duplicate detection using conditional writes
- Basic cloud application architecture

---------------------------------------------------

License

This project is created for learning and educational purposes.
