"""Build a Python wheel for the liner Go shared library."""
# pylint: disable=too-many-statements, line-too-long, C0103, W0105

import base64
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

revsion = '1.0.' + os.getenv('REVSION', '1984')
is_darwin = platform.system() == 'Darwin'
go = 'garble -literals -tiny -seed=o9WDTZ4CN4w' if os.getenv('GOGARBLE') else 'go'

go_ldflags = f'-s -w -X main.version={revsion}'
go_ldflags = go_ldflags + " -linkmode external -extldflags '-Wl,-install_name,@rpath/libliner.cp39.so'" if is_darwin else go_ldflags

system('rm -rf build dist liner liner.egg-info')
system(f'{go} build -v -trimpath -ldflags="{go_ldflags}" -buildmode=c-shared -o liner/libliner.cp39.so ..')
system('ln -sf ../../start.c.in liner/start.c')
system('ln -sf ../../README.md liner/README.md')
system('ln -sf ../../LICENSE liner/LICENSE')
with open('liner/__main__.py', 'wb') as file:
    file.write(b'from .liner import start\nstart()')
if is_darwin:
    '''
    def rot():
        import os, mmap
        with open(os.path.dirname(__file__) + '/libliner.cp39.so', "r+b") as file:
            m = mmap.mmap(file.fileno(), 0)
            m[:] = m[:].translate(bytes.maketrans(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
    try:
        from .liner import start
        rot()
    except ImportError:
        rot()
        from .liner import start
        rot()
    '''
    with open('liner/__init__.pyc', 'wb') as file:
        file.write(base64.b64decode('YQ0NCgAAAADMyKJpsQEAAOMAAAAAAAAAAAAAAAAAAAAACAAAAEAAAABzTgAAAGQAZAGEAFoAehZkAmQDbAFtAloCAQBlAIMAAQBXAG4qBABlA3lIAQABAAEAZQCDAAEAZAJkA2wBbQJaAgEAZQCDAAEAWQBuAjAAZARTACkFYwAAAAAAAAAAAAAAAAQAAAAIAAAAQwAAAHN8AAAAZAFkAGwAfQBkAWQAbAF9AXQCfABqA6AEdAWhAWQCFwBkA4MCj0J9AnwBoAF8AqAGoQBkAaECfQN8A2QAZASFAhkAoAd0CKAJZAVkBqECoQF8A2QAZASFAjwAVwBkAAQABACDAwEAbhAxAHNuMAABAAEAAQBZAAEAZABTACkHTukAAAAAehEvbGlibGluZXIuY3AzOS5zb3oDcitiaQAQAABzNAAAAEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpzNAAAAE5PUFFSU1RVVldYWVpBQkNERUZHSElKS0xNbm9wcXJzdHV2d3h5emFiY2RlZmdoaWprbG0pCtoCb3PaBG1tYXDaBG9wZW7aBHBhdGjaB2Rpcm5hbWXaCF9fZmlsZV9f2gZmaWxlbm/aCXRyYW5zbGF0ZdoFYnl0ZXPaCW1ha2V0cmFucykEcgIAAAByAwAAANoEZmlsZdoBbakAcg4AAAD6C19faW5pdF9fLnB52gNyb3QBAAAAcwgAAAAAARABGAEQAXIQAAAA6QEAAAApAdoFc3RhcnROKQRyEAAAAFoFbGluZXJyEgAAANoLSW1wb3J0RXJyb3JyDgAAAHIOAAAAcg4AAAByDwAAANoIPG1vZHVsZT4BAAAAcw4AAAAIBgIBDAEKAQwBBgEMAQ=='))
else:
    with open('liner/__init__.py', 'wb') as file:
        file.write(b'from .liner import start')


liner_extension = setuptools.Extension(
    'liner.liner',
    define_macros=[('Py_LIMITED_API', '0x03090000')],
    sources=['liner/start.c'],
    include_dirs=['./liner'],
    library_dirs=['./liner'],
    libraries=['liner.cp39'],
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
            'libliner.cp39.so',
            'README.md',
            'LICENSE',
        ],
    },
)
