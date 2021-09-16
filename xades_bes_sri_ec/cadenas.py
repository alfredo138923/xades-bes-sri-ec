from datetime import datetime
import re

xmlns = 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:etsi="http://uri.etsi.org/01903/v1.3.2#"'


def format_xml_string(cad):
   cad = cad.replace('\n', '')

   cad = re.sub(' +', ' ', cad).replace('> ', '>').replace(' <', '<')

   return cad


def get_signed_properties(signature_number, signed_properties_number, certificateX509_der_hash, X509SerialNumber, reference_id_number, issuer_name):
   signed_properties = """
    <etsi:SignedProperties Id="Signature%(signature_number)s-SignedProperties%(signed_properties_number)s">
        <etsi:SignedSignatureProperties>
            <etsi:SigningTime>
                %(fecha_hora)s
            </etsi:SigningTime>
            <etsi:SigningCertificate>
                <etsi:Cert>
                    <etsi:CertDigest>
                        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                        <ds:DigestValue>
                        %(certificateX509_der_hash)s
                        </ds:DigestValue>
                    </etsi:CertDigest>
                    <etsi:IssuerSerial>
                        <ds:X509IssuerName>
                            %(issuer_name)s
                        </ds:X509IssuerName>
                        <ds:X509SerialNumber>
                            %(X509SerialNumber)s
                        </ds:X509SerialNumber>
                    </etsi:IssuerSerial>
                </etsi:Cert>
            </etsi:SigningCertificate>
        </etsi:SignedSignatureProperties>
    <etsi:SignedDataObjectProperties>
        <etsi:DataObjectFormat ObjectReference="#Reference-ID-%(reference_id_number)s">
            <etsi:Description>
                contenido comprobante
            </etsi:Description>
            <etsi:MimeType>
                text/xml
            </etsi:MimeType>
        </etsi:DataObjectFormat>
    </etsi:SignedDataObjectProperties>
    </etsi:SignedProperties>"""

   fecha_hora = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

   signed_properties = signed_properties % {
       'signature_number': signature_number,
       'signed_properties_number': signed_properties_number,
       'certificateX509_der_hash': certificateX509_der_hash,
       'X509SerialNumber': X509SerialNumber,
       'reference_id_number': reference_id_number,
       'fecha_hora': fecha_hora,
       'issuer_name': issuer_name
   }

   signed_properties = format_xml_string(signed_properties)

   return signed_properties


def get_key_info(certificate_number, certificateX509, modulus, exponent):
    key_info = """<ds:KeyInfo Id="Certificate%(certificate_number)s">
<ds:X509Data>
<ds:X509Certificate>
%(certificateX509)s
</ds:X509Certificate>
</ds:X509Data>
<ds:KeyValue>
<ds:RSAKeyValue>
<ds:Modulus>
%(modulus)s
</ds:Modulus>
<ds:Exponent>%(exponent)s</ds:Exponent>
</ds:RSAKeyValue>
</ds:KeyValue>
</ds:KeyInfo>"""

    key_info = key_info % {
        'certificate_number': certificate_number,
        'certificateX509': certificateX509,
        'modulus': modulus,
        'exponent': exponent
    }

    return key_info


def get_signed_info(signed_info_number, signed_properties_id_number, sha1_signed_properties, certificate_number, sha1_certificado,
    reference_id_number,
    sha1_comprobante, signature_number, signed_properties_number):

    signed_info = """<ds:SignedInfo Id="Signature-SignedInfo%(signed_info_number)s">
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<ds:Reference Id="SignedPropertiesID%(signed_properties_id_number)s" Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature%(signature_number)s-SignedProperties%(signed_properties_number)s">
<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<ds:DigestValue>%(sha1_signed_properties)s</ds:DigestValue>
</ds:Reference>
<ds:Reference URI="#Certificate%(certificate_number)s">
<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<ds:DigestValue>%(sha1_certificado)s</ds:DigestValue>
</ds:Reference>
<ds:Reference Id="Reference-ID-%(reference_id_number)s" URI="#comprobante">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<ds:DigestValue>%(sha1_comprobante)s</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>"""

    signed_info = signed_info % {
        'signed_info_number': signed_info_number,
        'signed_properties_id_number': signed_properties_id_number,
        'sha1_signed_properties': sha1_signed_properties,
        'certificate_number': certificate_number,
        'sha1_certificado': sha1_certificado,
        'reference_id_number': reference_id_number,
        'sha1_comprobante': sha1_comprobante,
        'signature_number': signature_number,
        'signed_properties_number': signed_properties_number

    }

    return signed_info


def get_xades_bes(xmls, signature_number, signature_value_number, object_number, signed_info, signature, key_info, signed_properties):
    xades_bes = """<ds:Signature %(xmls)s Id="Signature%(signature_number)s">
%(signed_info)s
<ds:SignatureValue>
%(signature)s
</ds:SignatureValue>
%(key_info)s
<ds:Object Id="Signature%(signature_number)s-Object%(object_number)s"><etsi:QualifyingProperties Target="#Signature%(signature_number)s">%(signed_properties)s</etsi:QualifyingProperties></ds:Object></ds:Signature>"""

    xades_bes = xades_bes % {
        'xmls': xmls,
        'signature_number': signature_number,
        'signature_value_number': signature_value_number,
        'object_number': object_number,
        'signed_info': signed_info,
        'signature': signature,
        'key_info': key_info,
        'signed_properties': signed_properties
    }

    return xades_bes