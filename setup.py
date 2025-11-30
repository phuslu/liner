"""Build a Python wheel for the liner Go shared library."""
# pylint: disable=too-many-statements, line-too-long, C0103

import os
import platform
import setuptools


def system(cmd):
    """os.system with echo"""
    print(cmd)
    assert os.system(cmd) == 0

os.system('rm -rf wheel && mkdir -p wheel/liner')
os.chdir('wheel')

os.environ['CGO_ENABLED'] = '1'

revsion = os.getenv('REVSION', '1984')
is_darwin = platform.system() == 'Darwin'
go = 'garble -literals -tiny -seed=o9WDTZ4CN4w' if os.getenv('GOGARBLE') else 'go'

go_ldflags = f'-s -w -X main.version={revsion}'
go_ldflags = go_ldflags + " -linkmode external -extldflags '-Wl,-install_name,@rpath/libliner.so'" if is_darwin else go_ldflags

system('rm -rf build dist liner liner.egg-info')
system(f'{go} build -v -trimpath -ldflags="{go_ldflags}" -buildmode=c-shared -o liner/libliner.so ..')
system('ln -sf ../../start.c.in liner/start.c')
system('ln -sf ../../README.md liner/README.md')
system('ln -sf ../../LICENSE liner/LICENSE')
with open('liner/__init__.py', 'wb') as file:
    file.write(b'from .liner import start')
with open('liner/__main__.py', 'wb') as file:
    file.write(b'from .liner import start\nstart()')

liner_extension = setuptools.Extension(
    'liner.liner',
    define_macros=[('Py_LIMITED_API', '0x03090000')],
    sources=['liner/start.c'],
    include_dirs=['./liner'],
    library_dirs=['./liner'],
    libraries=['liner'],
    extra_link_args= ['-Wl,-rpath,@loader_path' if is_darwin else '-Wl,-rpath,$ORIGIN'],
    py_limited_api=True,
)

setuptools.setup(
    name='liner-py',
    version=revsion,
    description='python bindings for liner',
    long_description='python bindings for liner.',
    long_description_content_type='text/markdown',
    url='https://github.com/phuslu/liner',
    author='Phus Lu',
    author_email='phus.lu@gmail.com',
    license='AGPL-3.0',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
    ],
    python_requires='>=3.9',
    packages=['liner'],
    ext_modules=[liner_extension],
    options={
        'bdist_wheel': {
            'py_limited_api': 'cp39',
            'plat_name': 'macosx_11_0_'+platform.machine() if is_darwin else None,
        }
    },
    include_package_data=True,
    package_data={
        'liner':[
            'libliner.so',
            'README.md',
            'LICENSE',
        ],
    },
)
