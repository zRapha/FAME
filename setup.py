import io
from setuptools import setup

def read_file(filename): 
    with io.open(filename, mode='r', encoding='utf-8') as fd:
        return fd.read()

setup(
    name='FAMEwork',
    version='0.1.5',
    use_scm_version=False,
    setup_requires=['setuptools_scm'],
    include_package_data=True,
    packages=['.'],
    install_requires=[
    'numpy==1.19.0',
    'pandas==0.25.0',
    'requests==2.28.2',
    'scikit-learn==0.21.2',
    'scipy== 1.5.1',
    'lief==0.10.1',
    'lightgbm==2.3.1',
    'joblib==1.2.0',
    'chainer==7.8.0',
    'chainerrl==0.8.0',
    'pytest==6.2.5',
    'coverage==6.0',
    'tqdm~=4.62.3',
    'sphinx==4.2.0',
    'gym~=0.19.0',
    'setuptools~=57.0.0'],
    url='https://github.com/zRapha/FAME',
    license='MPL-2.0',
    author='Raphael Labaca Castro',
    author_email='mail@rapha.ai',
    description='Framework for Adversarial Malware Evaluation', 
    long_description=read_file('PyPI.md'), 
    long_description_content_type='text/markdown', 
    platforms=['Fedora 30, Ubuntu 16'], 
    entry_points={'console_scripts': ['fame = main:main',]}
)
