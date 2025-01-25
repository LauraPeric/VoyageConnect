import boto3
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.users import User, hash_password, verify_password, create_access_token
from datetime import timedelta
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import jwt

# Povezivanje s DynamoDB Local
dynamodb = boto3.resource('dynamodb', 
                          region_name='us-west-2', 
                          endpoint_url='http://127.0.0.1:8000', 
                          aws_access_key_id='fakeMyKeyId',  # more biti fake ključ
                          aws_secret_access_key='fakeSecretAccessKey')  # more biti fake ključ

# overall tablica za korisnike u DynamoDB-u
users_table = dynamodb.Table('Users')

app = FastAPI()

# Omogućavanje CORS-a
origins = [
    "http://localhost:8080", 
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8081"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# endpoit+nt za registraciju korisnika
@app.post("/register")
async def register(user: User):
    # provjera jel korisnik postoji u DynamoDB
    response = users_table.get_item(Key={"email": user.email})
    if "Item" in response:
        raise HTTPException(status_code=400, detail="Email already registered")

    # hashiranje lozinke i pohranjivanje korisnika u DynamoDB
    hashed_password = hash_password(user.password)

    users_table.put_item(
        Item={
            "email": user.email,
            "username": user.username,
            "hashed_password": hashed_password,
        }
    )
    return {"message": "User successfully registered"}

# endpoint za prijavu korisnika
@app.post("/login")
async def login(user: User):
    # dohvati korisnika iz DynamoDB
    response = users_table.get_item(Key={"email": user.email})
    if "Item" not in response:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_in_db = response["Item"]

    # check lozinke
    if not verify_password(user.password, user_in_db["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # kreiranje JWT tokena
    access_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(minutes=30))

    return {"access_token": access_token, "token_type": "bearer"}

def create_users_table():
    try:
        table = dynamodb.create_table(
            TableName='Users',
            KeySchema=[
                {'AttributeName': 'email', 'KeyType': 'HASH'}  # Primarni ključ
            ],
            AttributeDefinitions=[
                {'AttributeName': 'email', 'AttributeType': 'S'}  # String tip
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        print("Table is being created...")
        table.wait_until_exists()
        print("Table created successfully!")
    except dynamodb.meta.client.exceptions.ResourceInUseException:
        print("Table already exists. Skipping creation.")


# pozuv funkcije za kreiranje tablice
create_users_table()
