"""
Gera um certificado SSL auto-assinado para uso local com HTTPS.
Execute uma vez antes de rodar o app: python gerar_certificado.py
"""
import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

os.makedirs("certs", exist_ok=True)

# Gera chave privada RSA 2048 bits
chave = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Dados do certificado
nome = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME,             "BR"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,   "Sao Paulo"),
    x509.NameAttribute(NameOID.LOCALITY_NAME,            "Sao Paulo"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "Totem Concierge"),
    x509.NameAttribute(NameOID.COMMON_NAME,              "localhost"),
])

agora = datetime.now(timezone.utc)

cert = (
    x509.CertificateBuilder()
    .subject_name(nome)
    .issuer_name(nome)
    .public_key(chave.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(agora)
    .not_valid_after(agora + timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(__import__("ipaddress").IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    )
    .sign(chave, hashes.SHA256())
)

# Salva certificado
with open("certs/cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

# Salva chave privada
with open("certs/key.pem", "wb") as f:
    f.write(chave.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))

print("✅ Certificado gerado em certs/cert.pem e certs/key.pem")
print("   Válido por 365 dias para localhost / 127.0.0.1")
