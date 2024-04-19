from PIL import Image
import base64
from io import BytesIO

def base64_to_image(base64_string, output_path):
    image_data = base64.b64decode(base64_string)
    image = Image.open(BytesIO(image_data))
    image.save(output_path)

with open('./enc','rb') as f:
    enc = f.read()
    
base64_string = enc.decode('utf-8')
output_path = "decoded_image.png"

base64_to_image(base64_string, output_path)
