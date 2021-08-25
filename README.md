# xades-bes-sri-ec

Implementación en python del código para la firma de la facturación electrónica ecuatoriana usando el formato XAdES-BES sin librerias externas.

Requerimientos:

```bash
cryptography==3.2
pyOpenSSL==20.0.1
```

Instalación:
```bash
pip install git+https://github.com/alfredo138923/xades-bes-sri-ec@0.1.0
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
[Jybaro](https://www.jybaro.com/blog/firma-electronica-de-factura-electronica/)

## Contactos
alfredo138923@pm.me

## Licencia
[AGPL V3](https://choosealicense.com/licenses/agpl-3.0/)