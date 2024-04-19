from PIL import Image
import base64

def encrypt(image_path):
    with open(image_path, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read())
        return encoded_string

image_path = "./flag.png"
base64_string = encrypt(image_path)
with open('enc','wb') as f:
    f.write(base64_string)
