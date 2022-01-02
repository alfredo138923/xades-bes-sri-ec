from setuptools import setup

setup(
    name='xades-bes-sri-ec',
    version='0.1.1',
    description='Firma de la facturación electrónica ecuatoriana usando el formato XAdES-BES',
    url='https://github.com/alfredo138923/xades_bes_sri_ec',
    author='Alfredo Marcillo',
    author_email='alfredo138923@pm.me',
    license='AGPL V3',
    packages=['xades_bes_sri_ec'],
    install_requires=['cryptography==3.2.1', 'pyOpenSSL==20.0.1', 'lxml==4.6.3'],

    classifiers=[
        'Development Status :: Alpha',
        'Intended Audience :: Programming Language :: Python :: 3 :: 2',
        'License :: AGPL V3',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 2',
    ],
)
