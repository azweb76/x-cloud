from setuptools import setup, find_packages

setup(
    name="xcloud",
    version="0.0.4",
    install_requires=[
        'PyYaml',
        'jinja2',
        'glob2',
        'python-keystoneclient==3.10.0',
        'python-neutronclient==6.2.0',
        'python-novaclient==7.1.0',
        'requests>=2.19.1',
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
