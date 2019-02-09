# url_share

Shares links across a local network and opens them in the default webbrowser. It uses UDP broadcast, encrypts/decrypts at client and server, and prompts you before sending a URL off.

## Usage:
    Just run it, thats it. If you want to change the default port (UDP 7443) edit the file.
    
    When you copy data into the clipboard, it checks if its a url (starts with "http"). If it detects a url, it will prompt you with a box asking to share.
    The file acts as both server and client.

## Requirements

    win10toast
    pynacl