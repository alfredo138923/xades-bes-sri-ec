import base64
from random import random
import math
import hashlib
import binascii
import sys

PY3 = sys.version_info[0] >= 3


def sha1_base64(txt):
    m = hashlib.sha1()
    m.update(txt)

    sha1 = m.hexdigest()

    sha1_hex = binascii.unhexlify(sha1)

    b64 = encode_base64(sha1_hex)

    return b64


def sha1(txt):
    m = hashlib.sha1()
    m.update(txt)

    sha1 = m.hexdigest()

    return sha1


def split_string_every_n(cad, n):
    """
    Divide una cadena cada n caracteres. Separados por un
    salto de linea
    """

    res = [cad[i:i + n] for i in range(0, len(cad), n)]

    res = '\n'.join(res)

    return res


def p_obtener_aleatorio():
    return int(math.floor(random() * 999000) + 990)


def separar_cadena(cadena, delimitador, append_start=True):
    """
    Encuentra una cadena entre 2 delimitadores
    """

    cadena_separada = cadena.split(delimitador)

    result = []

    # agregar delimitador faltante
    for res in cadena_separada:

        if append_start:
            s = delimitador + res
        else:
            s = res + delimitador

        result.append(s)

    return result


def encode_base64(cad, encode='UTF-8'):

    if hasattr(cad, 'encode') and PY3:
        cad = base64.b64encode(cad.encode(encode))
    else:
        cad = base64.b64encode(cad)

    cad = cad.decode(encode)

    return cad


def leer_archivo(ruta, modo='r'):

    with open(ruta, modo) as archivo:
        return archivo.read()


def get_xml_nodo_final(xml_element_tree):

    cad = '</{}>'.format(xml_element_tree.getroot().tag)
    return cad
