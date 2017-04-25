from setuptools import setup, find_packages

setup(
    name="xcloud",
    version="0.0.1",
    install_requires=[
        'PyYaml',
        'jinja2',
        'glob2',
        'python-keystoneclient',
        'python-neutronclient',
        'python-novaclient',
        'requests==2.10.0',
        'babel==2.3.4'
    ],
    author="Dan Clayton",
    author_email="dan@azwebmaster.com",
    description="Used to provision servers in openstack.",
    license="MIT",
    keywords="cloud openstack",
    url="https://github.com/azweb76/x-cloud",
    packages=find_packages(exclude=('tests', 'docs')),
    entry_points={
        'console_scripts': [
            'xcloud=xcloud.cli:main',
        ],
    },
)
