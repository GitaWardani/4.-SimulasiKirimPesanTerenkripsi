from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from utils import generate_key_pair, encrypt_message, decrypt_message
from pydantic import BaseModel

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Message(BaseModel):
    content: str

class User(BaseModel):
    username: str

def get_current_user(token: str = Depends(oauth2_scheme)):

    return User(username="fakeuser")

@app.on_event("startup")
def startup_event():
    generate_key_pair()

@app.post("/send-message")
async def send_message(message: Message, current_user: User = Depends(get_current_user)):

    target_user_public_key_path = 'public_key_psikolog.pem'
    ciphertext = encrypt_message(message.content, target_user_public_key_path)
    return {"message": "Pesan berhasil terkirim!", "encrypted_message": ciphertext.decode()}

@app.post("/receive-message")
async def receive_message(message: Message, current_user: User = Depends(get_current_user)):

    current_user_private_key_path = f'private_key_{current_user.username}.pem'
    decrypted_message = decrypt_message(message.content.encode(), current_user_private_key_path)
    return {"message": "Pesan berhasil diterima!", "decrypted_message": decrypted_message}
