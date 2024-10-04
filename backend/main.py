from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Response, Depends, Request 
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import os
import uuid
import json
import logging
from moviepy.editor import VideoFileClip, TextClip, CompositeVideoClip
import aiofiles
import requests
from pytube import YouTube
from moviepy.config import change_settings
from dotenv import load_dotenv
import jwt
from datetime import datetime, timedelta
from fastapi import Header
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from motor.motor_asyncio import AsyncIOMotorClient
import validators  # Ensure you have this package installed
import stripe
from passlib.context import CryptContext
import httpx
from urllib.parse import quote_plus
import moviepy.config as mpy_config
from moviepy.editor import TextClip

# Load the Stripe secret key
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# Replace with your actual username and password
username = "veeraallamsetti"  # Your MongoDB username
password = "veera@9676"     # Your MongoDB password, replace with the actual password

# URL-encode username and password
encoded_username = quote_plus(username)
encoded_password = quote_plus(password)

# Load environment variables from .env file
load_dotenv()

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Change to your frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# MongoDB configuration
MONGO_URI = f"mongodb+srv://{encoded_username}:{encoded_password}@cluster0.od1nd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = AsyncIOMotorClient(MONGO_URI)
db = client["your_database_name"]  # Change to your database name
users_collection = db["users"]

# GIFs and videos directory
GIFS_DIR = 'gifs'
VIDEOS_DIR = "downloads/"
os.makedirs(GIFS_DIR, exist_ok=True)
os.makedirs(VIDEOS_DIR, exist_ok=True)

# Specify the path to ImageMagick
change_settings({"IMAGEMAGICK_BINARY": "/usr/bin/magick"}) 
txt_clip = TextClip("Hello World", fontsize=70, color='white')

# JWT configuration
SECRET_KEY = "your_secret_key"  # Change this to a secure random key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # Token expiration time

# Pydantic User model
class User(BaseModel):
    username: str
    password: str

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Helper function to decode JWT
def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None

# Dependency to get the current user
async def get_current_user(token: str = Header(...)):
    username = decode_access_token(token)
    if username is None:
        raise HTTPException(status_code=401, detail="Unauthorized access")
    return username

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@app.post("/signup")
async def signup(user: User):
    existing_user = await users_collection.find_one({"username": user.username})
    if existing_user:
        logger.error("Signup failed: Username already registered")
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Hash the password
    hashed_password = pwd_context.hash(user.password)
    
    # Insert user with hashed password and subscription status
    await users_collection.insert_one({
        "username": user.username,
        "password": hashed_password,
        "gif_count": 0,  # Default gif count
        "subscription_status": "inactive"  # Default subscription status
    })
    logger.info(f"User {user.username} signed up successfully.")
    return {"message": "Signup successful"}


@app.post("/login")
async def login(user: User):
    existing_user = await users_collection.find_one({"username": user.username})
    if existing_user is None:
        logger.error("Login failed: Invalid credentials")
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Verify the password using the hash
    if not pwd_context.verify(user.password, existing_user["password"]):
        logger.error("Login failed: Invalid credentials")
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)

    logger.info(f"User {user.username} logged in successfully, JWT token generated.")
    return {"access_token": access_token, "token_type": "bearer"}

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


@app.get("/")
def read_root():
    return {"message": "Hello World"}

class TextCustomization(BaseModel):
    text: str
    font_size: int
    color: str
    font_type: str
    font_weight: str
    font_style: str
    position: str
    text_align: str
    text_shadow: str

@app.get("/check_gif_count")
async def check_gif_count(authorization: str = Header(...)):
    token = authorization.split(" ")[1]  # Extract token from the header
    username = await get_current_user(token)
    user_info = await users_collection.find_one({"username": username})
    if user_info:
        return {"gif_count": user_info.get("gif_count", 0)}
    raise HTTPException(status_code=404, detail="User not found")

@app.post("/upload_video")
async def upload_video(
    file: UploadFile = None,
    url: str = Form(None),
    token: str = Depends(oauth2_scheme)
):
    if not file and not url:
        raise HTTPException(status_code=400, detail="No file or URL provided")
    
    logger.info(f"Received upload request: file={file.filename if file else None}, url={url}")

    if url and not validators.url(url):
        logger.error("Invalid URL provided")
        raise HTTPException(status_code=400, detail="Invalid URL provided")

    video_id = str(uuid.uuid4())
    file_path = os.path.join(VIDEOS_DIR, f"{video_id}.mp4")

    if file:
        async with aiofiles.open(file_path, "wb") as buffer:
            content = await file.read()
            await buffer.write(content)
        logger.info(f"Uploaded video saved at {file_path}")
    
    elif url:
        if 'youtube.com' in url:
            try:
                yt = YouTube(url)
                video_stream = yt.streams.get_highest_resolution()
                video_stream.download(output_path=VIDEOS_DIR, filename=f"{video_id}.mp4")
                logger.info(f"Downloaded YouTube video saved at {file_path}")
            except Exception as e:
                logger.error(f"Failed to download YouTube video: {str(e)}")
                raise HTTPException(status_code=400, detail=f"Failed to download YouTube video: {str(e)}")
        else:
            response = requests.get(url)
            if response.status_code != 200:
                logger.error("Failed to download video from URL")
                raise HTTPException(status_code=400, detail="Failed to download video from URL")
            async with aiofiles.open(file_path, "wb") as buffer:
                await buffer.write(response.content)
            logger.info(f"Downloaded video from URL saved at {file_path}")

    return {"video_id": video_id, "file_path": file_path}

@app.post("/customize_and_generate_gif")
async def customize_and_generate_gif(
    token: str = Header(...),
    video_id: str = Form(...),
    start_time: float = Form(...),
    end_time: float = Form(...),
    text_customization: str = Form(...),
):
    video_path = os.path.join(VIDEOS_DIR, f"{video_id}.mp4")
    logger.info(f"Video path: {video_path}")

    if not os.path.exists(video_path):
        logger.error(f"Video file not found: {video_path}")
        raise HTTPException(status_code=404, detail="Video file not found")

    if start_time < 0 or end_time <= start_time:
        raise HTTPException(status_code=422, detail="Invalid time range")

    try:
        text_customization_data = json.loads(text_customization)
    except json.JSONDecodeError:
        raise HTTPException(status_code=422, detail="Invalid JSON format for text_customization")

    # Create the GIF
    gif_clip = VideoFileClip(video_path).subclip(start_time, end_time)

    color = text_customization_data.get('color', 'white')
    txt_clip = TextClip(
        text_customization_data['text'],
        fontsize=text_customization_data['font_size'],
        color=color,
        font=text_customization_data.get('font_type', 'Arial')
    ).set_pos(text_customization_data.get('position', 'bottom')).set_duration(gif_clip.duration)

    final_clip = CompositeVideoClip([gif_clip, txt_clip])
    gif_filename = f"{uuid.uuid4()}.gif"
    gif_path = os.path.join(GIFS_DIR, gif_filename)

    final_clip.write_gif(gif_path)

    logger.info(f"Generated GIF saved at: {gif_path}, exists: {os.path.exists(gif_path)}")

    # Update user's GIF count in MongoDB
    username = await get_current_user(token)
    await users_collection.update_one({"username": username}, {"$inc": {"gif_count": 1}})

    return {"gif_id": gif_filename}

@app.post("/logout")
async def logout(token: str = Depends(get_current_user)):
    # Handle logout logic if necessary
    return {"message": "Logged out successfully"}

@app.get("/download/{gif_id}")
async def download_gif(gif_id: str):
    file_path = os.path.join(GIFS_DIR, gif_id)
    logger.info(f"Attempting to download GIF with ID: {gif_id}, checking path: {file_path}")
    if os.path.exists(file_path):
        return FileResponse(file_path)
    else:
        raise HTTPException(status_code=404, detail="File not found")

# Set your secret key for Stripe
stripe.api_key = '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'  # Replace with your actual Stripe secret key

# Pydantic model for user
class User(BaseModel):
    username: str

@app.post("/create-checkout-session")
async def create_checkout_session(user: User):
    existing_user = await users_collection.find_one({"username": user.username})
    if not existing_user:
        raise HTTPException(status_code=400, detail="User not found")

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[
                {
                    "price": existing_user["price_id"],  # Use user's price ID from the database
                    "quantity": 1,
                }
            ],
            mode="subscription",
            success_url="http://localhost:3000/success",
            cancel_url="http://localhost:3000/cancel",
        )
        return {"id": session.id}
    except Exception as e:
        logger.error(f"Error creating checkout session: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("Stripe-Signature")
    endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET")  # Ensure this environment variable is set

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        logger.error("Invalid payload")
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        logger.error("Invalid signature")
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Handle the checkout session completed event
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        customer_email = session.get("customer_email")

        if customer_email:
            await users_collection.update_one(
                {"email": customer_email},  # Ensure the user document has an email field
                {"$set": {"subscription_status": "active"}}
            )
            logger.info(f"Subscription created for {customer_email}")

    return JSONResponse(content={"status": "success"})



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)