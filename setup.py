from setuptools import setup, find_packages

setup(
    name="xcloud",
    version="1.0.1",
    install_requires=[
        'PyYaml',
        'jinja2',
        'glob2',
        'python-keystoneclient',
        'python-neutronclient',
        'python-novaclient',
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
            'xcloud=xcloud.xcloud:main',
        ],
    },
)
