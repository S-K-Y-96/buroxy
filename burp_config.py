import os
from pathlib import Path
import ssl
import certifi
# import urllib3

class BurpConfig:

    def __init__(self, burp_cer, proxy="http://127.0.0.1:8080", config_path="config/burp"):
        self.config_path = Path(config_path).absolute()
        self.config_path.mkdir(parents=True, exist_ok=True)
        self.certificate = self.create_custom_ca_bundle(burp_cer)
        self.status = "off"
        self.proxy = proxy
        
        # restoring point snapshot
        self.original_environ = dict(os.environ)
        self.original_ssl_context_function = ssl._create_default_https_context
    

    def on(self):
        if self.status == "off":
            self.set_proxy_env(self.proxy)
            self.set_ssl_env()
            self.patch_ssl_context()
        self.status = "on"

    def off(self):
        if self.status == "on":
            self.restore_env()
            self.unpatch_ssl_context()
        self.status = "off"

    def set_proxy_env(self, proxy):
        os.environ["ALL_PROXY"] = proxy
        os.environ["all_proxy"] = proxy
        os.environ["HTTP_PROXY"] = proxy
        os.environ["http_proxy"] = proxy
        os.environ["HTTPS_PROXY"] = proxy
        os.environ["https_proxy"] = proxy

    # Set custom CA bundle for SSL verification
    def set_ssl_env(self):
        os.environ['SSL_CERT_FILE'] = self.certificate
        os.environ['REQUESTS_CA_BUNDLE'] = self.certificate
        os.environ['CURL_CA_BUNDLE'] = self.certificate

    def restore_env(self):
        os.environ.clear()
        os.environ.update(self.original_environ)
    
    def patch_ssl_context(self):
        # Create a custom SSL context
        custom_context = ssl.create_default_context(cafile=self.certificate)
        # Replace the default SSL context
        ssl._create_default_https_context = lambda: custom_context
    
    def unpatch_ssl_context(self):
        ssl._create_default_https_context = self.original_ssl_context_function


    def create_custom_ca_bundle(self, burp_cer):
        burp_pem = str((self.config_path/"burp_certificate.pem"))
        all_pem  = str((self.config_path/"custom_ca_bundle.pem"))
        
        # Convert Burp certificate to PEM format
        os.system(f"openssl x509 -inform der -in {burp_cer} -out {burp_pem}")
        
        # Combine Burp certificate with system CA certificates
        with open(all_pem, 'wb') as outfile:
            with open(burp_pem, 'rb') as infile:
                outfile.write(infile.read())
            with open(certifi.where(), 'rb') as infile:
                outfile.write(infile.read())
        # $ cat {burp_pem} /etc/ssl/certs/ca-certificates.crt > {all_pem}
        
        return all_pem


    def __enter__(self):
        self.on()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.off()

    # def patch_urllib3(self):
    #     urllib3.util.ssl_.DEFAULT_CERTS = self.all_pem

    # def unpatch_urllib3(self):
    #     urllib3.util.ssl_.DEFAULT_CERTS = certifi.where()


# Usage:
# with BurpConfig("path/to/burp.cer") as burp:
#     # do

# burp = BurpConfig("path/to/burp.cer")
# burp.on()
# do

# burp.off()
# 