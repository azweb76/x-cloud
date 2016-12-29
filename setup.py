from setuptools import setup

setup(
    name="xcloud",
    version="1.0.0",
    install_requires=[
        'PyYaml',
        'jinja2',
        'glob2',
        'python-keystoneclient',
        'python-neutronclient',
        'python-novaclient', 'keystoneclient',
    ],
    author = "Dan Clayton",
    author_email = "dan@azwebmaster.com",
    description = "Used to provision servers in openstack.",
    license = "MIT",
    keywords = "cloud openstack",
    url = "https://github.com/azweb76/x-cloud",
    packages=['xcloud'],
    entry_points={
        'console_scripts': [
            'xcloud=xcloud.xcloud:main',
        ],
    },
)
