from fastapi import FastAPI, HTTPException, Depends, status
#from fastapi.security import OAuth2PasswordBearer
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Security
from pydantic import BaseModel, EmailStr
from typing import Annotated
import logging
from datetime import datetime, timedelta

import model.user_model as models
from db.database import SessionLocal, engine
from sqlalchemy.orm import Session
import bcrypt

import os
from dotenv import load_dotenv
load_dotenv()

from fastapi_mail import FastMail, MessageSchema
from mail_config import conf
import jwt
from redis_client import RedisClient
from fastapi.middleware.cors import CORSMiddleware



# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# JWT Configuration
JWT_SECRET_KEY = "Vashu "  # Change this in production
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = 15

# Initialize Redis client
redis_client = RedisClient()

# OAuth2 scheme for extracting Bearer token from Authorization header (used for protected routes)
#oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Using HTTPBearer to manually accept Authorization: Bearer <token> in Swagger

token_auth_scheme = HTTPBearer()



# initialize the database
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # "*" means allow all; for security, you can later restrict it
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# create the database tables
models.Base.metadata.create_all(bind=engine)

# dependency for database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]


# Define the User model (Schema)
class UserBase(BaseModel):
    username: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str


# JWT Helper Functions
def create_reset_token(email: str) -> str:
    """Create JWT token for password reset"""
    payload = {
        'email': email,
        'exp': datetime.utcnow() + timedelta(minutes=JWT_EXPIRY_MINUTES),
        'iat': datetime.utcnow(),
        'purpose': 'password_reset'
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token

def verify_reset_token(token: str) -> str:
    """Verify JWT token and return email"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        email = payload.get('email')
        purpose = payload.get('purpose')
        
        if not email or purpose != 'password_reset':
            return None
        return email
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token has expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {str(e)}")
        return None
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def create_refresh_token(data: dict):
    expire = datetime.utcnow() + timedelta(days=7)
    to_encode = data.copy()
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

##def verify_access_token(token: str = Depends(oauth2_scheme)):
# Access token verification function
def verify_access_token(credentials: HTTPAuthorizationCredentials = Depends(token_auth_scheme)):
    """
    Verify JWT access token from Authorization header.
    Returns payload if token is valid, else raises error.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=403, detail="Invalid token type")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Access token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=403, detail=f"Invalid token: {str(e)}")



# Routes

@app.get("/")
def read_root():
    return {"message": "Welcome to the API!"}

# Create a new user
@app.post("/users/", status_code=status.HTTP_201_CREATED)
async def create_user(user: UserBase, db: db_dependency):
    try:
        # check if the user already exists
        existing_user = db.query(models.User).filter(
            (models.User.username == user.username) | (models.User.email == user.email)
        ).first()

        if existing_user:
            raise HTTPException(status_code=400, detail="User already exists")
        
        # hash the password
        hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
        # create a new user
        new_user = models.User(
            username=user.username,
            email=user.email,
            password=hashed_password.decode('utf-8'),
            is_verified=0
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return {"message": "User created successfully", "user": new_user.username}
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


# Login a user
@app.post("/login", status_code=status.HTTP_200_OK)
async def login(user: LoginRequest, db: db_dependency):
    try:
        # check if the user exists
        existing_user = db.query(models.User).filter(models.User.username == user.username).first()
        if not existing_user:
            raise HTTPException(status_code=400, detail="Invalid username or password")
        
        # check if the password is correct
        if not bcrypt.checkpw(user.password.encode('utf-8'), existing_user.password.encode('utf-8')):
            raise HTTPException(status_code=400, detail="Invalid username or password")
        
        payload = {
            "sub": existing_user.username,
            "user_id": existing_user.id,
            "username": existing_user.username,
        }

        access_token = create_access_token(payload)
        refresh_token = create_refresh_token(payload)

        # Store refresh token in Redis
        redis_client.setex(f"refresh_token:{existing_user.username}", 7 * 24 * 60 * 60, refresh_token)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Get user details by their ID
@app.get("/users/{user_id}", status_code=status.HTTP_200_OK)
async def read_user(user_id: int, db: db_dependency):
    try:
        #fetch user from database
        user = db.query(models.User).filter(models.User.id == user_id).first()
        # handle user not found
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_verified": user.is_verified,
            "full_name": user.user_details.full_name if user.user_details else None,
            "aadhar_card_no": user.user_details.aadhar_card_no if user.user_details else None,
            "pan_card_no": user.user_details.pan_card_no if user.user_details else None,
            "address": user.user_details.address if user.user_details else None,
            "phone_number": user.user_details.phone_number if user.user_details else None,
            "emergency_contact": user.user_details.emergency_contact if user.user_details else None,
            "nationality": user.user_details.nationality if user.user_details else None,
            "date_of_birth": user.user_details.date_of_birth if user.user_details else None,
            "created_at": user.user_details.created_at.isoformat() if user.user_details else None,
            "date_of_joining": user.user_details.date_of_joining.isoformat() if user.user_details and user.user_details.date_of_joining else None,
            "working_region_id": user.user_details.working_region_id if user.user_details else None,
            "home_region_id": user.user_details.home_region_id if user.user_details else None,
            "manager_name": user.user_details.manager_name if user.user_details else None,
            "current_department": user.user_details.current_Department if user.user_details else None,
            "current_role": user.user_details.current_role if user.user_details else None
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching user: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


# 1. Forgot password - generate JWT token and store in Redis
@app.post("/forgot-password")
async def forgot_password(request: PasswordResetRequest, db: Session = Depends(get_db)):
    try:
        logger.info(f"Processing forgot password for email: {request.email}")
        
        # Check if user exists
        user = db.query(models.User).filter(models.User.email == request.email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Email not registered")

        # Generate JWT token
        jwt_token = create_reset_token(request.email)
        logger.info(f"Generated JWT token for user: {user.username}")
        
        # Store JWT token in Redis with expiry (900 seconds = 15 minutes)
        try:
            redis_key = f"reset_token:{jwt_token}"
            redis_client.setex(redis_key, 900, request.email)
            logger.info(f"JWT token stored in Redis successfully")
        except Exception as redis_error:
            logger.error(f"Redis error: {str(redis_error)}")
            raise HTTPException(status_code=500, detail="Failed to store reset token")
        
        # Create reset link with JWT token
        reset_link = f"http://localhost:8000/reset-password-form?token={jwt_token}"
        
        # Prepare email message
        message = MessageSchema(
            subject="Password Reset Request",
            recipients=[request.email],
            body=f"""
            Hello {user.username},
            
            You have requested to reset your password. Please click the link below to reset your password:
            
            {reset_link}
            
            This link will expire in 15 minutes for security reasons.
            
            If you didn't request this password reset, please ignore this email.
            
            Best regards,
            Your App Team
            """,
            subtype="plain"
        )

        # Send email
        try:
            fm = FastMail(conf)
            await fm.send_message(message)
            logger.info("Password reset email sent successfully")
        except Exception as email_error:
            logger.error(f"Email sending error: {str(email_error)}")
            # Clean up the token from Redis if email fails
            redis_client.delete(f"reset_token:{jwt_token}")
            raise HTTPException(status_code=500, detail=f"Failed to send email: {str(email_error)}")

        return {"message": "Password reset link sent to your email.", "token_type": "JWT"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in forgot_password: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error occurred")


# 2. Reset password using JWT token
@app.post("/reset-password")
async def reset_password(request: PasswordResetConfirm, db: Session = Depends(get_db)):
    try:
        logger.info(f"Processing password reset with JWT token")
        
        # Validate input
        if not request.token or not request.new_password:
            raise HTTPException(status_code=400, detail="Token and new password are required")
        
        if len(request.new_password) < 6:
            raise HTTPException(status_code=400, detail="New password must be at least 6 characters long")
        
        # First verify JWT token structure and expiry
        email_from_jwt = verify_reset_token(request.token)
        if not email_from_jwt:
            raise HTTPException(status_code=400, detail="Invalid or expired JWT token")
        
        # Check if token exists in Redis (for additional security)
        try:
            redis_key = f"reset_token:{request.token}"
            email_from_redis = redis_client.get(redis_key)
            logger.info(f"Retrieved email from Redis: {email_from_redis}")
        except Exception as redis_error:
            logger.error(f"Redis error while retrieving token: {str(redis_error)}")
            raise HTTPException(status_code=500, detail="Failed to validate reset token")
        
        if not email_from_redis:
            raise HTTPException(status_code=400, detail="Token not found or already used")
        
        # Verify emails match (JWT vs Redis)
        if email_from_jwt != email_from_redis:
            logger.error(f"Email mismatch: JWT({email_from_jwt}) vs Redis({email_from_redis})")
            redis_client.delete(redis_key)
            raise HTTPException(status_code=400, detail="Token validation failed")
        
        # Find user by email
        user = db.query(models.User).filter(models.User.email == email_from_jwt).first()
        if not user:
            logger.error(f"User not found for email: {email_from_jwt}")
            # Clean up invalid token
            redis_client.delete(redis_key)
            raise HTTPException(status_code=400, detail="User not found")
        
        # Hash the new password
        try:
            hashed_password = bcrypt.hashpw(request.new_password.encode('utf-8'), bcrypt.gensalt())
            user.password = hashed_password.decode('utf-8')
        except Exception as hash_error:
            logger.error(f"Password hashing error: {str(hash_error)}")
            raise HTTPException(status_code=500, detail="Failed to process new password")
        
        # Update password in database
        try:
            db.commit()
            logger.info(f"Password updated successfully for user: {user.username}")
        except Exception as db_error:
            logger.error(f"Database error while updating password: {str(db_error)}")
            db.rollback()
            raise HTTPException(status_code=500, detail="Failed to update password")
        
        # Delete the used token from Redis
        try:
            redis_client.delete(redis_key)
            logger.info("JWT token deleted from Redis")
        except Exception as redis_error:
            logger.error(f"Error deleting token from Redis: {str(redis_error)}")
            # This is not critical, so we don't raise an exception
        
        return {"message": "Password reset successful", "user": user.username}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in reset_password: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal server error occurred")

        # Refresh token verify
@app.post("/refresh-token")
async def refresh_token(request: dict):
    try:
        refresh_token = request.get("refresh_token")
        payload = jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])

        if payload["type"] != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")

        username = payload.get("sub")
        stored_token = redis_client.get(f"refresh_token:{username}")
        if stored_token != refresh_token:
            raise HTTPException(status_code=403, detail="Refresh token expired or invalid")

        new_access_token = create_access_token({"sub": username})
        return {
            "access_token": new_access_token,
            "token_type": "bearer"
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except Exception as e:
        logger.error(f"Error refreshing token: {str(e)}")
        raise HTTPException(status_code=500, detail="Token refresh failed") 

# This is a protected route. Only users with a valid access token can access this.