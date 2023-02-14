import io
from setuptools import setup

def read_file(filename): 
    with io.open(filename, mode='r', encoding='utf-8') as fd:
        return fd.read()


setup(
    name='FAME',
    version='0.1.0',
    use_scm_version=False,
    setup_requires=['setuptools_scm'],
    url='https://github.com/zRapha/FAME',
    license='MPL-2.0',
    author='Raphael Labaca Castro',
    author_email='Contact via GitHub',
    description='Framework for Adversarial Malware Evaluation', 
    long_description=read_file('README.md'), 
    long_description_content_type='text/markdown', 
    platforms=['Fedora 30, Ubuntu 16'], 
    entry_points={'console_scripts': ['fame = main:main',]}
)
