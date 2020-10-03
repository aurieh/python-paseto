import sys
from os import path

from setuptools import find_packages, setup

PROJECT_ROOT = path.dirname(__file__)

# fmt:off
SRC_ROOT = path.join(PROJECT_ROOT, "src")
sys.path.insert(0, SRC_ROOT)

from paseto import __about__  # noqa isort:skip
# fmt:on

with open(path.join(PROJECT_ROOT, "README.rst"), "rt") as f:
    long_description = f.read()

install_requires = [
    "attrs==20.*",
    "cryptography==2.*",
    "PyNaCl==1.*",
]

tests_require = [
    "coverage==5.2",
    "flake8-bandit==2.1.1",
    "flake8-bugbear==19.8.0",
    "flake8-isort==2.7.0",
    "flake8==3.7.8",
    "hypothesis==5.10.5",
    "isort==4.3.21",
    "pep8-naming==0.8.2",
    "pytest==5.4.1",
]

dev_requires = ["black>=19.10b0"]

setup(
    name=__about__.__title__,
    version=__about__.__version__,
    description=__about__.__summary__,
    long_description=long_description,
    url=__about__.__uri__,
    author=__about__.__author__,
    author_email=__about__.__email__,
    license=__about__.__license__,
    package_dir={"": "src"},
    packages=find_packages(where=SRC_ROOT),
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require={"test": tests_require, "dev": dev_requires},
    test_suite="py.test",
    zip_safe=False,
    classifiers=[
        # TODO
    ],
)
