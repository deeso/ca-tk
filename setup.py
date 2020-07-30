#!/usr/bin/env python
from setuptools import setup, find_packages
import os


data_files = [(d, [os.path.join(d, f) for f in files])
              for d, folders, files in os.walk(os.path.join('src', 'config'))]


setup(name='core-analysis-tk',
      version='.01',
      description='perform memory analysis on core analysis',
      author='Adam Pridgen',
      author_email='adam.pridgen@cisco.com',
      install_requires=['wheel', 'pyelftools'],
      packages=find_packages('src'),
      package_dir={'': 'src'},
)
