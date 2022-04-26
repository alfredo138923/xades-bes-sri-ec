from cryptography.hazmat.primitives.serialization import pkcs12
from datetime import datetime
from cryptography.x509.extensions import KeyUsage
import re
import codecs
from datetime import datetime
from OpenSSL import crypto
from .cadenas import *
import subprocess
import xml.etree.ElementTree as ET
from .utils import *
import argparse
import uuid
import os


MAX_LINE_SIZE = 76


def get_certificados_validos(archivo, password):
    fecha_hora_actual = datetime.now()

    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(archivo, password)
    certificados_no_caducados = []
    certificados_validos = []

    if certificate.not_valid_after > datetime.now():
        certificados_no_caducados.append(certificate)

    for cert in additional_certificates:

        if cert.not_valid_after > fecha_hora_actual:
            certificados_no_caducados.append(cert)

    for cert in certificados_no_caducados:
        for ext in cert.extensions:

            if type(ext.value) == KeyUsage:

                if ext.value.digital_signature == True:
                    certificados_validos.append(cert)

    return certificados_validos, private_key


def get_clave_privada(ruta_p12, password):
    # https://github.com/pyca/pyopenssl/issues/770
    # No es posible recuperar con pyopenssl multiples claves_privadas
    # Se hace con una llamada directo a OPENSSL

    clave_privada_firma = None

    data = {
        'ruta': ruta_p12,
        'password': password.decode(),
    }

    CMD_OPENSSL = " openssl pkcs12  -in '{ruta}' -nocerts -passin pass:{password} -passout pass:{password} ".format(**data)

    salida_cmd = subprocess.check_output(CMD_OPENSSL, shell=True)

    salida_cmd = salida_cmd.decode()

    delimitador_inicio = '-----BEGIN ENCRYPTED PRIVATE KEY-----'
    delimitador_final = '-----END ENCRYPTED PRIVATE KEY-----'

    claves_privadas = separar_cadena(salida_cmd, delimitador_final, append_start=False)
    claves_validas = []

    for cp in claves_privadas:

        regex = '{}(.+?){}'.format(delimitador_inicio, delimitador_final)
        m = re.search(regex, cp, flags=re.DOTALL)

        if m:
            claves_validas.append(cp)

    if len(claves_validas) > 1:
        # Si la clave contiene mas de una clave privada,
        # buscar la que tenga el atributo 'Signing Key'

        for cp in claves_validas:

            if 'Signing Key' in cp:
                clave_privada_firma = cp

    elif len(claves_validas) == 1:
        clave_privada_firma = claves_validas[0]

    clave_privada_firma = separar_cadena(clave_privada_firma, delimitador_inicio, append_start=True)

    if len(clave_privada_firma) > 0:
        return clave_privada_firma[1]

    return clave_privada_firma


def get_c14n(cad):

    archivo_tmp = '/tmp/{}.xml'.format(uuid.uuid4())

    with open(archivo_tmp, 'w') as archivo:
        archivo.write(cad)

    CMD_XMLLINT = 'xmllint --c14n {}'.format(archivo_tmp)

    salida_cmd = subprocess.check_output(CMD_XMLLINT, shell=True)
    salida_cmd = salida_cmd.decode('utf-8')

    os.remove(archivo_tmp)

    return salida_cmd


def get_exponente(exp_int):

    exponent = '{:X}'.format(exp_int)
    exponent = exponent.zfill(6)
    exponent = codecs.encode(codecs.decode(exponent, 'HEX'), 'BASE64').decode()
    exponent = exponent.strip()

    return exponent


def get_modulo(mod_int):

    modulo = '{:X}'.format(mod_int)

    # dividir la cadena cada 2 caracteres
    modulo = re.findall(r'(\w{2})', modulo)

    modulo = map(lambda x: chr(int(x, 16)), modulo)
    modulo = ''.join(modulo)

    modulo = encode_base64(modulo, 'LATIN-1')

    modulo = split_string_every_n(modulo, MAX_LINE_SIZE)

    return modulo


def get_certificate_x509(cert):
    certificate_pem_tmp = str(cert)

    certX509 = re.findall(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
        certificate_pem_tmp, flags=re.DOTALL
    )

    certX509 = certX509[0].replace('\n', '').replace('\\n', '')

    certX509 = split_string_every_n(certX509, MAX_LINE_SIZE)

    return certX509


def procesar_firmar_comprobante(archivo_p12, ruta_p12, password, xml, ruta_xml_auth):
    certificados, _ = get_certificados_validos(archivo_p12, password)

    if len(certificados) == 0:
        raise Exception("No se han encontrado certificados válidos")

    cert = certificados[0]

    certificate_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

    certificateX509 = get_certificate_x509(certificate_pem)

    cert_pem = crypto.load_certificate(crypto.FILETYPE_PEM, certificate_pem)
    cert_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert_pem)

    certificateX509_der_hash = sha1_base64(cert_der)

    modulo = get_modulo(cert.public_key().public_numbers().n)
    exponente = get_exponente(cert.public_key().public_numbers().e)
    serial_number = cert_pem.get_serial_number()
    issuer_name = cert_pem.get_issuer()

    issuer_name = "".join(",{0:s}={1:s}".format(name.decode(), value.decode()) for name, value in issuer_name.get_components())

    issuer_name = issuer_name.replace(',', '', 1) if issuer_name.startswith(',') else issuer_name

    xml_element_tree = ET.ElementTree(ET.fromstring(xml))
    xml_no_header = get_c14n(xml)

    sha1_comprobante = sha1_base64(xml_no_header.encode())

    certificate_number = p_obtener_aleatorio(); # 1562780 en el ejemplo del SRI
    signature_number = p_obtener_aleatorio(); # 620397 en el ejemplo del SRI
    signed_properties_number = p_obtener_aleatorio(); # 24123 en el ejemplo del SRI

    # numeros fuera de los hash:

    signed_info_number = p_obtener_aleatorio(); # 814463 en el ejemplo del SRI
    signed_properties_id_number = p_obtener_aleatorio(); # 157683 en el ejemplo del SRI
    reference_id_number = p_obtener_aleatorio(); # 363558 en el ejemplo del SRI
    signature_value_number = p_obtener_aleatorio(); # 398963 en el ejemplo del SRI
    object_number = p_obtener_aleatorio(); # 231987 en el ejemplo del SRI

    signed_properties = get_signed_properties(
        signature_number, signed_properties_number, certificateX509_der_hash, serial_number,
        reference_id_number, issuer_name
    )

    signed_properties_para_hash = signed_properties.replace('<etsi:SignedProperties', '<etsi:SignedProperties ' + xmlns)

    signed_properties_para_hash = get_c14n(signed_properties_para_hash)

    sha1_signed_properties = sha1_base64(signed_properties_para_hash.encode())

    key_info = get_key_info(certificate_number, certificateX509, modulo, exponente)

    key_info_para_hash = key_info.replace('<ds:KeyInfo', '<ds:KeyInfo ' + xmlns)

    sha1_certificado = sha1_base64(key_info_para_hash.encode('UTF-8'))

    signed_info = get_signed_info(
        signed_info_number, signed_properties_id_number, sha1_signed_properties,
        certificate_number, sha1_certificado, reference_id_number, sha1_comprobante,
        signature_number, signed_properties_number
    )

    signed_info_para_firma = signed_info.replace('<ds:SignedInfo', '<ds:SignedInfo ' + xmlns)

    signed_info_para_firma = get_c14n(signed_info_para_firma)

    priv_key = get_clave_privada(ruta_p12, password)

    pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, priv_key, password)

    sign = crypto.sign(pkey, signed_info_para_firma.encode(), "SHA1")

    signature = encode_base64(sign)

    signature = split_string_every_n(signature, MAX_LINE_SIZE)

    xades_bes = get_xades_bes(xmlns, signature_number, signature_value_number, object_number, signed_info, signature, key_info, signed_properties)

    tail_tag = get_xml_nodo_final(xml_element_tree)

    comprobante = xml.replace(tail_tag, xades_bes + tail_tag)

    with open(ruta_xml_auth, 'w') as archivo:
        archivo.write(comprobante)


def firmar_comprobante(ruta_p12, password, ruta_xml, ruta_xml_auth):

    cert = leer_archivo(ruta_p12, 'rb')
    xml = leer_archivo(ruta_xml)
    password = password.encode()

    procesar_firmar_comprobante(cert, ruta_p12, password, xml, ruta_xml_auth)




