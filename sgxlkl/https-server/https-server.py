# This is a demonstration of how to use RA-TLS without actually
# interfacing with the RA-TLS library directly. Instead, the RA-TLS
# key and certificate are generated at startup and exposed through the
# file system. The application accesses the key and certificate by
# reading from the file system.

import base64
import BaseHTTPServer, SimpleHTTPServer
import ssl

# The RA-TLS library currently only exposes the key and certificate as
# in DER format. The Python API expects them in PEM format. Hence, we
# convert them here.
crt_pem = ssl.DER_cert_to_PEM_cert(open('/tmp/crt').read())
f = open('/tmp/crt.pem', 'w')
f.write(crt_pem)
f.close()

key_b64 = base64.b64encode(open('/tmp/key').read())
f = open('/tmp/key.pem', 'w')
print >> f, '-----BEGIN RSA PRIVATE KEY-----'
print >> f, key_b64
print >> f, '-----END RSA PRIVATE KEY-----'
f.close()

# Start the HTTPS web server
ip = '10.0.1.1'
port = 4443

print "Server listening on %s:%d\n" % (ip, port)
httpd = BaseHTTPServer.HTTPServer((ip, port), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, keyfile='/tmp/key.pem', certfile='/tmp/crt.pem', server_side=True)
httpd.serve_forever()
