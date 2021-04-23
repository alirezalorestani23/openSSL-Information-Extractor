from OpenSSL import crypto
import ssl
import datetime

from socket import socket
from collections import namedtuple


# https://www.pyopenssl.org/en/stable/api/crypto.html?highlight=X509#x509-objects

local_cert_directory = 'C:/Users/LENOVO/Desktop/uni/term8/amniat/hw/1/cert/alireza.lorestani.cert.pem'
cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(local_cert_directory).read())


webiste_cert = ssl.get_server_certificate(('anten.ir', 443))
cert2 = crypto.load_certificate(crypto.FILETYPE_PEM, webiste_cert)

def extract_information(cert):
    subject = cert.get_subject()
    cn = subject.CN
    issuer = cert.get_issuer().CN
    notAfter = cert.get_notAfter()
    notBefore = cert.get_notBefore()
    validTo = datetime.datetime.strptime(notAfter.decode("ascii"), '%Y%m%d%H%M%SZ').strftime('%b %d, %Y')
    validFrom = datetime.datetime.strptime(notBefore.decode("ascii"), '%Y%m%d%H%M%SZ').strftime('%b %d, %Y')
    print("Common Name: "+cn +"\nValid From: "+validFrom+"\nValid To: "+validTo+"\nIssuer: "+issuer)


extract_information(cert2)