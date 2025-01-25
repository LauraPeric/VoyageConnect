import boto3
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from jose import jwt
from botocore.exceptions import ClientError

# inicijalizacija DynamoDB klijenta
dynamodb = boto3.resource('dynamodb', region_name='us-west-2')
users_table = dynamodb.Table('Users')  # zamjena s imenom svoje tablice u DynamoDB-u

# hashing lozinki
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# konfiguracija tokena
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Pydantic modeli za validaciju podataka
class User(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserInDB(User):
    hashed_password: str

# funkcije za hashiranje lozinki
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# kreiranje JWT tokena
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# funkcija za dodavanje korisnika u DynamoDB
def add_user_to_db(user: User):
    try:
        hashed_password = hash_password(user.password)
        response = users_table.put_item(
            Item={
                'email': user.email,
                'username': user.username,
                'hashed_password': hashed_password,
            }
        )
        return {"message": "User successfully registered"}
    except ClientError as e:
        print(f"Error adding user to DynamoDB: {e.response['Error']['Message']}")
        raise Exception("Could not register user")

# funkcija za provjeru korisnika iz DynamoDB-a (prijava)
def get_user_from_db(email: str):
    try:
        response = users_table.get_item(
            Key={'email': email}
        )
        if 'Item' not in response:
            raise Exception("User not found")
        return response['Item']
    except ClientError as e:
        print(f"Error fetching user from DynamoDB: {e.response['Error']['Message']}")
        raise Exception("Error fetching user")

