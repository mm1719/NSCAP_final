import ftplib
import socks
import socket
import logging
from contextlib import closing

# Configure logging to stdout
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Configure the SOCKS5 proxy with remote DNS resolution
socks.setdefaultproxy(socks.SOCKS5, "127.0.0.1", 1080, username="user", password="password", rdns=True)
socket.socket = socks.socksocket

def ftp_download():
    logging.info("Running: FTP Large File Download")
    try:
        with closing(ftplib.FTP()) as ftp:
            ftp.connect('ftp.dlptest.com', 21)
            logging.info("Connected to FTP server")
            ftp.login('dlpuser', 'rNrKYTX9g7z3RgJRmxWuGHbeu')
            logging.info("Logged in to FTP server")
            ftp.set_pasv(True)  # Use passive mode
            logging.info("Set passive mode")
            
            with open('large_test_file.zip', 'wb') as f:
                def callback(data):
                    f.write(data)
                    logging.debug('.', end='', flush=True)  # Print progress dots
                
                ftp.retrbinary('RETR large_test_file.zip', callback)
        
        logging.info("Download completed.")
    except Exception as e:
        logging.error(f"FTP download failed: {e}")

ftp_download()
