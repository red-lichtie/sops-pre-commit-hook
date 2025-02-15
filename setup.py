from setuptools import find_packages, setup

setup(
    name='sops-pre-commit-hook',
    url='https://github.com/onedr0p/sops-pre-commit',
    version='1.0.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'sops_pre_commit_hook = hooks.sops_pre_commit_hook:main',
        ],
    },
    install_requires=[
        "ruamel.yaml"
    ]
)