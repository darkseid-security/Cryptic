# Cryptic

<img src="https://github.com/darkseid-security/Cryptic/blob/main/screenshots/Cryptic3.png">

[CRYPTIC V1.3]

<img src="https://github.com/darkseid-security/Cryptic/blob/main/static/img/spider.png" height=400>

A Flask web application that allows you to encrypt/decrypt text with AES-GCM 128/192/256 bits.
Built in function allows you to upload files to the server and encrypt/decrypt them with AES-128-CBC.

Steganography feature built in aswell allow users to hide secret messages/files inside images.

Features
=================

- Users can generate a unique encryption key for each file or text they encrypt.
- Server does not log/store encryption keys.
- With text encryption users can select three diffrent key sizes 128,192 or 256.
- Modern UI/UX built with Bulma.
- Responsive mobile app
- Uses modern encryption cipher AES.
- Upload files to server and then Encrypt/Decrypt Files server side, set what file types you want to allow.
- Encrypt/Decrypt Text with AES-GCM Cipher.
- Server will check if security key matches, if it dosen't then upload will be aborted
- Uses self singed TLS certificate to encrypt data
- Hide and encrypt messages with AES-256 inside images
- Extract and decrypt secret messages hidden inside images 
- Generates random filenames after file has been uploaded
- [*New Feature] Embed files inside images
- [*New Feature] Extract embeded files
- [*New Feature] Generates a random folder name for each file uploaded so you can sort through them later
- [*Fixed] Path Transversal vulnerbility

TODO
========
- Create better mobile navigation

Run App
=========
- git clone https://github.com/computationalcore/cryptosteganography.git - don't install from pip issue with pillow
- Run command openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365 to generate TLS certificate
- To start app run gunicorn --certfile cert.pem --keyfile key.pem -b 0.0.0.0:80 app:app


Security Issues
=================
- If deploying on a VPS buy domain name and set up TLS cert with letsencrypt set port to port 80
- Directory static/encrypted is Public filenames could be bruteforced however filenames are 10 character long and encrypted with AES-128-CBC and uses a 128 bit key
- Directory static/stego is public however filenames are 10 character secret messages are encrypted with AES-256 with a 128 bit key 

