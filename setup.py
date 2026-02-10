from setuptools import setup,find_packages
setup(name="nullsec-spoof",version="2.0.0",author="bad-antics",description="Network address spoofing and identity manipulation toolkit",packages=find_packages(where="src"),package_dir={"":"src"},python_requires=">=3.8")
