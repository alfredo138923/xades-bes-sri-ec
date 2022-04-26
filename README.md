# xades-bes-sri-ec

Implementación en python del código para la firma de la facturación electrónica ecuatoriana usando el formato XAdES-BES sin librerias externas de python.

Requerimientos maquina:

```bash
apt-get install libxml2-utils
```

Requerimientos python:

```bash
cryptography==3.2.1
pyOpenSSL==20.0.1
lxml==4.6.3
```

Instalación:
```bash
pip install git+https://github.com/alfredo138923/xades-bes-sri-ec@0.1.2
```

## Ejemplo:
```python
from xades_bes_sri_ec import xades

ruta_p12 = '/ruta_absoluta_a_p12'
clave_p12 = 'clave_archivo_p12'
ruta_xml = '/ruta_absoluta_xml_a_firmar'
ruta_xml_auth = '/ruta_absoluta_xml_firmado'

ruta_xml_firmado = xades.firmar_comprobante(ruta_p12, clave_p12, ruta_xml, ruta_xml_auth)

```

## Créditos:
Implementación original en Nodejs por
[Jybaro](https://www.jybaro.com/blog/firma-electronica-de-factura-electronica/), con algunos cambios aplicados despues decompilar el JAR del firmador oficial del SRI para formar la misma salida del XML

## Contactos
alfredo138923@gmail.com

## Licencia
[AGPL V3](https://choosealicense.com/licenses/agpl-3.0/)
