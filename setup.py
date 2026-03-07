from setuptools import setup, find_packages

setup(
    name="depradar",
    version="2.0.0",
    description="Python dependency risk scanner CLI",
    packages=find_packages(),
    py_modules=["cli.depradar"],
    install_requires=[
        "typer>=0.12.0",
        "rich>=13.0.0",
        "httpx>=0.27.0",
    ],
    entry_points={
        "console_scripts": [
            "depradar=cli.depradar:app",
        ],
    },
    python_requires=">=3.11",
)
