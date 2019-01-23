# This is a demonstration of how to use RA-TLS without actually
# interfacing with the RA-TLS library directly. Instead, the RA-TLS
# key and certificate are generated at startup and exposed through the
# file system. The application accesses the key and certificate by
# reading from the file system.

import base64
import BaseHTTPServer, SimpleHTTPServer
import ssl

def rsa_key_der_to_pem(key_der):
    out = '-----BEGIN RSA PRIVATE KEY-----\n'
    i = 0
    for c in base64.b64encode(key_der):
        if (i == 64):
            out += '\n'
            i = 0
        out += c
        i += 1
    out += '\n'
    out += '-----END RSA PRIVATE KEY-----'
    return out

# The RA-TLS library currently only exposes the key and certificate as
# in DER format. The Python API expects them in PEM format. Hence, we
# convert them here.
crt_pem = ssl.DER_cert_to_PEM_cert(open('/tmp/crt').read())
f = open('/tmp/crt.pem', 'w')
f.write(crt_pem)
f.close()

with open('/tmp/key.pem', 'w') as f:
    print >> f, rsa_key_der_to_pem(open('/tmp/key').read())

# Start the HTTPS web server
ip = '10.0.1.1'
port = 4443

print "Server listening on %s:%d\n" % (ip, port)
httpd = BaseHTTPServer.HTTPServer((ip, port), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, keyfile='/tmp/key.pem', certfile='/tmp/crt.pem', server_side=True)
httpd.serve_forever()
