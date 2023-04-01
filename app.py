
from flask import Flask,render_template,request,abort,redirect,url_for
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
import fernet
import base64
import os
from cryptosteganography import CryptoSteganography
import random,string


app = Flask(__name__)
app.secret_key = get_random_bytes(16)
app.config["MAX_CONTENT_LENGTH"] = 5096 * 5096
app.config["UPLOAD_PATH"] = 'static/encrypted/'
app.config["UPLOAD_EXTENSIONS"] = [".jpeg",".png",".pdf",".jpg",".doc",".docx",".csv",".xslx",".txt"]
#warning = " Store Key In A Safe Place"
error_filetype = ""
error_filetype2 = ""

@app.route("/")
def index():
    return render_template("index.html")
    
def verify():
    global verified
    global input_key
    with open("private.key") as private_key:
        key_file = str(private_key.read().strip("\n"))
    input_key = str(request.form["security_key"])
    if key_file in input_key:
        verified = "True"
    else:
        verified = "False"
    
@app.route("/upload")
def upload_file():
    return render_template("upload.html",filetype=error_filetype,filetype2=error_filetype2)
        
@app.route("/keygen", methods=["GET","POST"])
def get_key():
    global fernet,key
    key = Fernet.generate_key()
    fernet = Fernet(key)
    return render_template("upload.html",enc_key=key.decode())
    
@app.route("/stego_keygen", methods=["GET","POST"])
def get_key2():
    global fernet,key
    key = Fernet.generate_key()
    fernet = Fernet(key)
    return render_template("stego.html",enc_key=key.decode())
    
@app.route("/stego_file_keygen",methods=["GET","POST"])
def get_encrytion_key():
    global fernet,third_encryption_key
    third_encryption_key = Fernet.generate_key()
    fernet = Fernet(third_encryption_key)
    return render_template("stego.html",stego_file_key=third_encryption_key.decode())
    
@app.route("/encrypt_file", methods=["GET","POST"])
def encrypt_f():
    global error_filetype
    verify()
    if verified == "True":
        uploaded_file = request.files["file"]
        if uploaded_file.filename != '':
            file_ext = os.path.splitext(uploaded_file.filename)[1]
        if file_ext not in app.config["UPLOAD_EXTENSIONS"]:
            error_filetype = "File extension not allowed"
            abort(redirect(url_for('upload_file')))
            
        letters = string.ascii_lowercase
        random_filename = ''.join(random.choice(letters) for i in range(10))
        create_directory = os.mkdir('static/encrypted/' + random_filename) 
        uploaded_file.save('static/encrypted/' + random_filename + '/' + uploaded_file.filename)
        fn = 'static/encrypted/' + random_filename + '/' + uploaded_file.filename
        
        with open(fn, 'rb') as file:
            original = file.read()
        encrypted = fernet.encrypt(original)
        with open('static/encrypted/' + random_filename + '/' + random_filename + file_ext, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)
        os.remove(fn)
        message = 'File has been encrypted'
        download_link = 'Download Encrypted File'
        return render_template("upload.html",download=download_link,filename=random_filename + '/' + random_filename + file_ext,input_key=input_key,message=message,enc_key=key.decode())
    else:
        auth = "Not Authorized to upload files"
        return render_template("upload.html",filetype=auth)
@app.route("/decrypt_file", methods=["GET","POST"])
def decrypt_f():
    global error_filetype2
    verify()
    if verified == "True":
        get_key = request.form["decryption_key"]
        uploaded_file = request.files["encrypted_file"]
        if uploaded_file.filename != '':
            file_ext = os.path.splitext(uploaded_file.filename)[1]
            if file_ext not in app.config["UPLOAD_EXTENSIONS"]:
                error_filetype2 = "File extension not allowed"
                abort(redirect(url_for('upload_file')))
                
            letters = string.ascii_lowercase
            random_filename = ''.join(random.choice(letters) for i in range(10))
            create_directory = os.mkdir('decrypted/' + random_filename) 
            uploaded_file.save('decrypted/' + random_filename + '/' + uploaded_file.filename)
            fn = 'decrypted/' + random_filename + '/' +  uploaded_file.filename
            try:
                fernet = Fernet(get_key)
                with open(fn, 'rb') as enc_file:
                    encrypted = enc_file.read()
                    decrypted = fernet.decrypt(encrypted)
                with open(fn, 'wb') as dec_file:
                    dec_file.write(decrypted)
                    result = "File Has Been Decrypted"
                return render_template("upload.html",filename=uploaded_file.filename,result=result,file_n=uploaded_file.filename)
            except:
                pass
                result = "Failed to decrypt file"
                return render_template("upload.html",result=result,file_n=uploaded_file.filename)
    else:
        auth = "Not Authorized to upload files"
        return render_template("upload.html",filetype=auth)
@app.route("/decryptAES")
def dec():
    return render_template("decrypt.html")
    
@app.route("/keys", methods=["GET","POST"])
def key_gen():
    global cipher,key64,nonce64
    key_length = int(request.form['key-length'])
    if key_length == 128:
        key = get_random_bytes(16)
    if key_length == 192:
        key = get_random_bytes(24)
    if key_length == 256:
        key = get_random_bytes(32)
    key64 = base64.b64encode(key)   
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    nonce64 = base64.b64encode(nonce)
    return render_template("index.html",keygen=key64.decode('utf-8'),iv=nonce64.decode("utf-8"))
     
@app.route("/encrypt", methods=["POST","GET"])
def encrypt():
    text = bytes(request.form['ciphertext'],encoding='utf-8')
    cipher_text, tag = cipher.encrypt_and_digest(text)
    cipher64 = base64.b64encode(cipher_text)
    return render_template("index.html",key=key64.decode('utf-8'),ciphertext=cipher64.decode('utf-8'),iv4=nonce64.decode("utf-8"))
    
@app.route("/decrypt", methods=["POST","GET"])
def decrypt():
    try:
        decryption_status = 'Decryption Succesful'
        ciphertext = str(request.form['ciphertext'])
        IV = str(request.form['IV'])
        decryption_key = str(request.form['encryption_key'])
        decoded_ciphertext = base64.b64decode(ciphertext)
        decoded_IV = base64.b64decode(IV)
        decoded_key = base64.b64decode(decryption_key)
        
        cipher = AES.new(decoded_key, AES.MODE_GCM, decoded_IV)
        decrypted_message = cipher.decrypt(decoded_ciphertext).decode()
        return render_template("decrypt.html",result=decrypted_message,status=decryption_status)
    except:
        pass
        decryption_status = 'Decryption Failed'
        return render_template("decrypt.html",status=decryption_status)
        
@app.route("/stegohide")
def steg():
    return render_template("stego.html")

@app.route("/stego_hide", methods=["POST","GET"])
def stegohide():
    global error_filetype
    verify()
    if verified == "True":
        hidden_text = request.form["hidden_text"]
        uploaded_file = request.files["file"]
        if uploaded_file.filename != '':
            file_ext = os.path.splitext(uploaded_file.filename)[1]
            filename = os.path.splitext(uploaded_file.filename)[0]
        if file_ext not in app.config["UPLOAD_EXTENSIONS"]:
            error_filetype = "File extension not allowed"
            abort(redirect(url_for('upload_file')))
            
        letters = string.ascii_lowercase
        random_filename = ''.join(random.choice(letters) for i in range(10))
        create_directory = os.mkdir('static/stego/' + random_filename) 
        
        uploaded_file.save('static/stego/' + random_filename + '/' + uploaded_file.filename)
        os.rename('static/stego/' + random_filename + '/' + uploaded_file.filename,'static/stego/' + random_filename + '/' + random_filename + file_ext)
        fn = 'static/stego/' + random_filename + '/' + random_filename + file_ext
        crypto_steganography = CryptoSteganography(key.decode())
        crypto_steganography.hide(fn,'static/stego/' + random_filename + '/' + random_filename + '.png', hidden_text)
        os.remove(fn)
        message = 'Message has been hidden successfully'
        download_link = 'Download Encrypted File'
        return render_template("stego.html",download=download_link,image=random_filename + '/' + random_filename + '.png',input_key=input_key,message=message,enc_key=key.decode())
    else:
        auth = "Not Authorized to upload files"
        return render_template("stego.html",filetype=auth)
        
@app.route("/stego_hide_file",methods=["GET","POST"])
def stegohide_file():
    global error_filetype
    verify()
    if verified == "True":
        original_file = request.files["original_image"]
        secret_file = request.files["secret_file"]
        if original_file.filename != '' and original_file.filename != '':
            file_ext = os.path.splitext(original_file.filename)[1]
            file_ext = os.path.splitext(secret_file.filename)[1]
        if file_ext not in app.config["UPLOAD_EXTENSIONS"]:
            error_filetype = "File extension not allowed"
            abort(redirect(url_for('upload_file')))
            
        letters = string.ascii_lowercase
        random_filename = ''.join(random.choice(letters) for i in range(10))
        create_directory = os.mkdir('static/encrypted/' + random_filename) 
        
        original_file.save('static/encrypted/' + random_filename + '/' + original_file.filename)
        secret_file.save('static/encrypted/' + random_filename + '/' + secret_file.filename)
        secret_file_path = 'static/encrypted/' + random_filename + '/' + secret_file.filename
        op = 'static/encrypted/' + random_filename + '/' + original_file.filename
        crypto_steganography = CryptoSteganography(third_encryption_key.decode())
        message = None
        with open(secret_file_path, "rb") as f:
            message = f.read()
        crypto_steganography.hide(op , 'static/encrypted/' + random_filename + '/' + random_filename + '.png',message)
        os.remove(op)
        os.remove(secret_file_path)
        message = 'File has been hidden Successfully'
        download_link = 'Download Hidden File'
        return render_template("stego.html",stego_file_download=download_link,image_src=random_filename + '/' + random_filename + '.png',input_key=input_key,message=message,stego_file_key=third_encryption_key.decode())
    else:
        auth = "Not Authorized to upload files"
        return render_template("stego.html",filetype=auth)
        
@app.route("/stego_extract", methods=["POST","GET"])
def stego_extract():
    global error_filetype
    verify()
    if verified == "True":
        get_key = request.form["decryption_key"]
        uploaded_file = request.files["extract_file"]
        if uploaded_file.filename != '':
            file_ext = os.path.splitext(uploaded_file.filename)[1]
        if file_ext not in app.config["UPLOAD_EXTENSIONS"]:
            error_filetype = "File extension not allowed"
            abort(redirect(url_for('upload_file')))
            
        letters = string.ascii_lowercase
        random_filename = ''.join(random.choice(letters) for i in range(10))
        create_directory = os.mkdir('decrypted/Extracted/' + random_filename)
        
        uploaded_file.save('decrypted/Extracted/' + random_filename + '/' + uploaded_file.filename)
        os.rename('decrypted/Extracted/' + random_filename + '/' + uploaded_file.filename,'decrypted/Extracted/' + random_filename + '/' + random_filename + file_ext)
        uploaded_image = 'decrypted/Extracted/' + random_filename + '/' + random_filename + file_ext
        crypto_steganography = CryptoSteganography(get_key)
        secret = crypto_steganography.retrieve(uploaded_image)
        message = 'Secret Message has been Decrypted'
        heading = 'Extracted Message:'
        return render_template("stego.html",heading=heading,input_key=input_key,message=message,secret_message=secret,image='/decrypted/Extracted/' + random_filename + '/' + uploaded_file.filename)
    else:
        auth = "Not Authorized to upload files"
        return render_template("stego.html",filetype=auth)
        
@app.route("/stego_extract_file",methods=["GET","POST"])
def stegoextract_file():
    global error_filetype
    verify()
    if verified == "True":
        get_key = request.form["decryption_key"]
        get_format = request.form["format"]
        uploaded_file = request.files["extract_file"]
        if uploaded_file.filename != '':
            file_ext = os.path.splitext(uploaded_file.filename)[1]
            raw_file_name = os.path.splitext(uploaded_file.filename)[0]
        if file_ext not in app.config["UPLOAD_EXTENSIONS"]:
            error_filetype = "File extension not allowed"
            abort(redirect(url_for('upload_file')))
            
        letters = string.ascii_lowercase
        random_filename = ''.join(random.choice(letters) for i in range(10))
        create_directory = os.mkdir('decrypted/Extracted/' + random_filename) 
        
        uploaded_file.save('decrypted/Extracted/' + random_filename + '/' + uploaded_file.filename)
        uploaded_image = 'decrypted/Extracted/' + random_filename + '/' + uploaded_file.filename
        crypto_steganography = CryptoSteganography(get_key)
        try:
            secret = crypto_steganography.retrieve(uploaded_image)
            with open('decrypted/Extracted/' + random_filename + '/' + random_filename + '.' + get_format, 'wb') as f:
                f.write(secret)
            response = 'File has been Extracted'
        except:
            response = "Decryption Failed can't extract secret file"
            pass
        return render_template("stego.html",input_key=input_key,response=response,file_location='decrypted/Extracted/' + random_filename + '/' + random_filename + '.' + get_format)
    else:
        auth = "Not Authorized to upload files"
        return render_template("stego.html",filetype=auth)
        
#app.run('0.0.0.0',80,debug="True")           
