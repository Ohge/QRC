# coding=utf-8
""" Quantum Resistant Cryptography Module Install """
from setuptools import setup
from codecs import open
from os import path

__author__ = 'Christopher Ohge'
__version__ = '1.0.0a1'

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='QRC',
    version='0.0.1',
    description='Quantum resistant cryptography suite with socket support',
    long_description=long_description,
    url='https://github.com/Ohge/QRC',
    author=__author__,
    author_email='chris.ohge@gmail.com',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Communications',
        'Topic :: Security :: Cryptography',
        'Topic :: Internet',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='quantum resistant elliptic curve ecc aes crypto cipher encrypt decrypt socket',
    packages=['QRC'],
    install_requires=['pyaes', 'ecc'],
)
