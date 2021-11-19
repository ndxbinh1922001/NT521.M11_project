assert True
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 31137))
s.bind(('192.168.0.1', 8080))
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers.modes import ECB


# Insecure mode
mode = ECB(iv)

# Secure cipher and mode
cipher = AES.new(key, blockalgo.MODE_CTR, iv)

# Secure mode
mode = CBC(iv)
from Crypto.Cipher import ARC2 as pycrypto_arc2
from Crypto.Cipher import ARC4 as pycrypto_arc4
from Crypto.Cipher import Blowfish as pycrypto_blowfish
from Crypto.Cipher import DES as pycrypto_des
from Crypto.Cipher import XOR as pycrypto_xor
from Cryptodome.Cipher import ARC2 as pycryptodomex_arc2
from Cryptodome.Cipher import ARC4 as pycryptodomex_arc4
from Cryptodome.Cipher import Blowfish as pycryptodomex_blowfish
from Cryptodome.Cipher import DES as pycryptodomex_des
from Cryptodome.Cipher import XOR as pycryptodomex_xor
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.Util import Counter
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.backends import default_backend
from struct import pack

key = b'Sixteen byte key'
iv = Random.new().read(pycrypto_arc2.block_size)
cipher = pycrypto_arc2.new(key, pycrypto_arc2.MODE_CFB, iv)
msg = iv + cipher.encrypt(b'Attack at dawn')
cipher = pycryptodomex_arc2.new(key, pycryptodomex_arc2.MODE_CFB, iv)
msg = iv + cipher.encrypt(b'Attack at dawn')

key = b'Very long and confidential key'
nonce = Random.new().read(16)
tempkey = SHA.new(key+nonce).digest()
cipher = pycrypto_arc4.new(tempkey)
msg = nonce + cipher.encrypt(b'Open the pod bay doors, HAL')
cipher = pycryptodomex_arc4.new(tempkey)
msg = nonce + cipher.encrypt(b'Open the pod bay doors, HAL')

iv = Random.new().read(bs)
key = b'An arbitrarily long key'
plaintext = b'docendo discimus '
plen = bs - divmod(len(plaintext),bs)[1]
padding = [plen]*plen
padding = pack('b'*plen, *padding)
bs = pycrypto_blowfish.block_size
cipher = pycrypto_blowfish.new(key, pycrypto_blowfish.MODE_CBC, iv)
msg = iv + cipher.encrypt(plaintext + padding)
bs = pycryptodomex_blowfish.block_size
cipher = pycryptodomex_blowfish.new(key, pycryptodomex_blowfish.MODE_CBC, iv)
msg = iv + cipher.encrypt(plaintext + padding)

key = b'-8B key-'
plaintext = b'We are no longer the knights who say ni!'
nonce = Random.new().read(pycrypto_des.block_size/2)
ctr = Counter.new(pycrypto_des.block_size*8/2, prefix=nonce)
cipher = pycrypto_des.new(key, pycrypto_des.MODE_CTR, counter=ctr)
msg = nonce + cipher.encrypt(plaintext)
nonce = Random.new().read(pycryptodomex_des.block_size/2)
ctr = Counter.new(pycryptodomex_des.block_size*8/2, prefix=nonce)
cipher = pycryptodomex_des.new(key, pycryptodomex_des.MODE_CTR, counter=ctr)
msg = nonce + cipher.encrypt(plaintext)

key = b'Super secret key'
plaintext = b'Encrypt me'
cipher = pycrypto_xor.new(key)
msg = cipher.encrypt(plaintext)
cipher = pycryptodomex_xor.new(key)
msg = cipher.encrypt(plaintext)

cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message")

cipher = Cipher(algorithms.Blowfish(key), mode=None, backend=default_backend())
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message")

cipher = Cipher(algorithms.IDEA(key), mode=None, backend=default_backend())
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message")
from cryptography.hazmat.primitives import hashes
from Crypto.Hash import MD2 as pycrypto_md2
from Crypto.Hash import MD4 as pycrypto_md4
from Crypto.Hash import MD5 as pycrypto_md5
from Crypto.Hash import SHA as pycrypto_sha
from Cryptodome.Hash import MD2 as pycryptodomex_md2
from Cryptodome.Hash import MD4 as pycryptodomex_md4
from Cryptodome.Hash import MD5 as pycryptodomex_md5
from Cryptodome.Hash import SHA as pycryptodomex_sha
import hashlib

hashlib.md5(1)
hashlib.md5(1).hexdigest()

abc = str.replace(hashlib.md5("1"), "###")

print(hashlib.md5("1"))

hashlib.sha1(1)

pycrypto_md2.new()
pycrypto_md4.new()
pycrypto_md5.new()
pycrypto_sha.new()

pycryptodomex_md2.new()
pycryptodomex_md4.new()
pycryptodomex_md5.new()
pycryptodomex_sha.new()

hashes.MD5()
hashes.SHA1()
import dill
import StringIO

# dill
pick = dill.dumps({'a': 'b', 'c': 'd'})
print(dill.loads(pick))

file_obj = StringIO.StringIO()
dill.dump([1, 2, '3'], file_obj)
file_obj.seek(0)
print(dill.load(file_obj))

file_obj.seek(0)
print(dill.Undillr(file_obj).load())
from django.contrib.auth.models import User

User.objects.filter(username='admin').extra(
    select={'test': 'secure'},
    where=['secure'],
    tables=['secure']
)
User.objects.filter(username='admin').extra({'test': 'secure'})
User.objects.filter(username='admin').extra(select={'test': 'secure'})
User.objects.filter(username='admin').extra(where=['secure'])

User.objects.filter(username='admin').extra(dict(could_be='insecure'))
User.objects.filter(username='admin').extra(select=dict(could_be='insecure'))
query = '"username") AS "username", * FROM "auth_user" WHERE 1=1 OR "username"=? --'
User.objects.filter(username='admin').extra(select={'test': query})
User.objects.filter(username='admin').extra(select={'test': '%secure' % 'nos'})
User.objects.filter(username='admin').extra(select={'test': '{}secure'.format('nos')})

where_var = ['1=1) OR 1=1 AND (1=1']
User.objects.filter(username='admin').extra(where=where_var)
where_str = '1=1) OR 1=1 AND (1=1'
User.objects.filter(username='admin').extra(where=[where_str])
User.objects.filter(username='admin').extra(where=['%secure' % 'nos'])
User.objects.filter(username='admin').extra(where=['{}secure'.format('no')])

tables_var = ['django_content_type" WHERE "auth_user"."username"="admin']
User.objects.all().extra(tables=tables_var).distinct()
tables_str = 'django_content_type" WHERE "auth_user"."username"="admin'
User.objects.all().extra(tables=[tables_str]).distinct()
from django.db.models.expressions import RawSQL
from django.contrib.auth.models import User

User.objects.annotate(val=RawSQL('secure', []))
User.objects.annotate(val=RawSQL('%secure' % 'nos', []))
User.objects.annotate(val=RawSQL('{}secure'.format('no'), []))
raw = '"username") AS "val" FROM "auth_user" WHERE "username"="admin" --'
User.objects.annotate(val=RawSQL(raw, []))
raw = '"username") AS "val" FROM "auth_user"' \
      ' WHERE "username"="admin" OR 1=%s --'
User.objects.annotate(val=RawSQL(raw, [0]))
import os

print(eval("1+1"))
print(eval("os.getcwd()"))
print(eval("os.chmod('%s', 0777)" % 'test.txt'))


# A user-defined method named "eval" should not get flagged.
class Test(object):
    def eval(self):
        print("hi")
    def foo(self):
        self.eval()

Test().eval()
exec("do evil")
from flask import Flask

app = Flask(__name__)

@app.route('/')
def main():
    raise

#bad
app.run(debug=True)

#okay
app.run()
app.run(debug=False)

#unrelated
run()
run(debug=True)
run(debug)
from ftplib import FTP

ftp = FTP('ftp.debian.org')
ftp.login()

ftp.cwd('debian')
ftp.retrlines('LIST')

ftp.quit()# Possible hardcoded password: 'Admin'
# Severity: Low   Confidence: Medium
def someFunction(user, password="Admin"):
    print("Hi " + user)

def someFunction2(password):
    # Possible hardcoded password: 'root'
    # Severity: Low   Confidence: Medium
    if password == "root":
        print("OK, logged in")

def noMatch(password):
    # Possible hardcoded password: ''
    # Severity: Low   Confidence: Medium
    if password == '':
        print("No password!")

def NoMatch2(password):
    # Possible hardcoded password: 'ajklawejrkl42348swfgkg'
    # Severity: Low   Confidence: Medium
    if password == "ajklawejrkl42348swfgkg":
        print("Nice password!")

# Possible hardcoded password: 'blerg'
# Severity: Low   Confidence: Medium
def doLogin(password="blerg"):
    pass

def NoMatch3(a, b):
    pass

# Possible hardcoded password: 'blerg'
# Severity: Low   Confidence: Medium
doLogin(password="blerg")

# Possible hardcoded password: 'blerg'
# Severity: Low   Confidence: Medium
password = "blerg"

# Possible hardcoded password: 'blerg'
# Severity: Low   Confidence: Medium
d["password"] = "blerg"

# Possible hardcoded password: 'secret'
# Severity: Low   Confidence: Medium
EMAIL_PASSWORD = "secret"

# Possible hardcoded password: 'emails_secret'
# Severity: Low   Confidence: Medium
email_pwd = 'emails_secret'

# Possible hardcoded password: 'd6s$f9g!j8mg7hw?n&2'
# Severity: Low   Confidence: Medium
my_secret_password_for_email = 'd6s$f9g!j8mg7hw?n&2'

# Possible hardcoded password: '1234'
# Severity: Low   Confidence: Medium
passphrase='1234'
with open('/tmp/abc', 'w') as f:
    f.write('def')

# ok
with open('/abc/tmp', 'w') as f:
    f.write('def')

with open('/var/tmp/123', 'w') as f:
    f.write('def')

with open('/dev/shm/unit/test', 'w') as f:
    f.write('def')

# Negative test
with open('/foo/bar', 'w') as f:
    f.write('def')
import hashlib

hashlib.new('md5')

hashlib.new('md4', 'test')

hashlib.new(name='md5', string='test')

hashlib.new('MD4', string='test')

hashlib.new(string='test', name='MD5')

hashlib.new('sha1')

hashlib.new(string='test', name='SHA1')

hashlib.new('sha', string='test')

hashlib.new(name='SHA', string='test')

# Test that plugin does not flag valid hash functions.
hashlib.new('sha256')

hashlib.new('SHA512')
import httplib
c = httplib.HTTPSConnection("example.com")

import http.client
c = http.client.HTTPSConnection("example.com")

import six
six.moves.http_client.HTTPSConnection("example.com")
import requests
import wsgiref.handlers

def application(environ, start_response):
    r = requests.get('https://192.168.0.42/private/api/foobar')
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [r.content]

if __name__ == '__main__':
    wsgiref.handlers.CGIHandler().run(application)
from twisted.internet import reactor
from twisted.web import static, server, twcgi

root = static.File("/root")
root.putChild("cgi-bin", twcgi.CGIDirectory("/var/www/cgi-bin"))
reactor.listenTCP(80, server.Site(root))
reactor.run()
from twisted.internet import reactor
from twisted.web import static, server, twcgi

root = static.File("/root")
root.putChild("login.cgi", twcgi.CGIScript("/var/www/cgi-bin/login.py"))
reactor.listenTCP(80, server.Site(root))
reactor.run()
from subprocess import Popen as pop
import hashlib as h
import hashlib as hh
import hashlib as hhh
import hashlib as hhhh
from pickle import loads as lp
import pickle as p

pop('/bin/gcc --version', shell=True)

h.md5('1')
hh.md5('2')
hhh.md5('3').hexdigest()
hhhh.md5('4')
lp({'key': 'value'})
from subprocess import Popen

from ..foo import sys
from . import sys
from .. import sys
from .. import subprocess
from ..subprocess import Popen
os = __import__("os")
pickle = __import__("pickle")
sys = __import__("sys")
subprocess = __import__("subprocess")

# this has been reported in the wild, though it's invalid python
# see bug https://bugs.launchpad.net/bandit/+bug/1396333
__import__()

# TODO(??): bandit can not find this one unfortunately (no symbol tab)
a = 'subprocess'
__import__(a)
import importlib
a = importlib.import_module('os')
b = importlib.import_module('pickle')
c = importlib.__import__('sys')
d = importlib.__import__('subprocess')

# Do not crash when target is an expression
e = importlib.import_module(MODULE_MAP[key])
f = importlib.__import__(MODULE_MAP[key])

# Do not crash when target is a named argument
g = importlib.import_module(name='sys')
h = importlib.__import__(name='subprocess')
i = importlib.import_module(name='subprocess', package='bar.baz')
j = importlib.__import__(name='sys', package='bar.baz')
import os
import pickle
import sys
import subprocess
import jinja2
from jinja2 import Environment, select_autoescape
templateLoader = jinja2.FileSystemLoader( searchpath="/" )
something = ''

Environment(loader=templateLoader, load=templateLoader, autoescape=True)
templateEnv = jinja2.Environment(autoescape=True,
        loader=templateLoader )
Environment(loader=templateLoader, load=templateLoader, autoescape=something)
templateEnv = jinja2.Environment(autoescape=False, loader=templateLoader )
Environment(loader=templateLoader,
            load=templateLoader,
            autoescape=False)

Environment(loader=templateLoader,
            load=templateLoader)

Environment(loader=templateLoader, autoescape=select_autoescape())

Environment(loader=templateLoader,
            autoescape=select_autoescape(['html', 'htm', 'xml']))


def fake_func():
    return 'foobar'
Environment(loader=templateLoader, autoescape=fake_func())
from mako.template import Template
import mako

from mako import template

Template("hello")

# XXX(fletcher): for some reason, bandit is missing the one below. keeping it
# in for now so that if it gets fixed inadvertitently we know.
mako.template.Template("hern")
template.Template("hern")
from django.utils import safestring

mystr = '<b>Hello World</b>'
mystr = safestring.mark_safe(mystr)
import os
from django.utils import safestring


def insecure_function(text, cls=''):
    return '<h1 class="{cls}">{text}</h1>'.format(text=text, cls=cls)


my_insecure_str = insecure_function('insecure', cls='" onload="alert(\'xss\')')
safestring.mark_safe(my_insecure_str)
safestring.SafeText(my_insecure_str)
safestring.SafeUnicode(my_insecure_str)
safestring.SafeString(my_insecure_str)
safestring.SafeBytes(my_insecure_str)


def try_insecure(cls='" onload="alert(\'xss\')'):
    try:
        my_insecure_str = insecure_function('insecure', cls=cls)
    except Exception:
        my_insecure_str = 'Secure'
    safestring.mark_safe(my_insecure_str)


def except_insecure(cls='" onload="alert(\'xss\')'):
    try:
        my_insecure_str = 'Secure'
    except Exception:
        my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe(my_insecure_str)


def try_else_insecure(cls='" onload="alert(\'xss\')'):
    try:
        if 1 == random.randint(0, 1):  # nosec
            raise Exception
    except Exception:
        my_insecure_str = 'Secure'
    else:
        my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe(my_insecure_str)


def finally_insecure(cls='" onload="alert(\'xss\')'):
    try:
        if 1 == random.randint(0, 1):  # nosec
            raise Exception
    except Exception:
        print("Exception")
    else:
        print("No Exception")
    finally:
        my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe(my_insecure_str)


def format_arg_insecure(cls='" onload="alert(\'xss\')'):
    my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe('<b>{} {}</b>'.format(my_insecure_str, 'STR'))


def format_startarg_insecure(cls='" onload="alert(\'xss\')'):
    my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe('<b>{}</b>'.format(*[my_insecure_str]))


def format_keywords_insecure(cls='" onload="alert(\'xss\')'):
    my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe('<b>{b}</b>'.format(b=my_insecure_str))


def format_kwargs_insecure(cls='" onload="alert(\'xss\')'):
    my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe('<b>{b}</b>'.format(**{'b': my_insecure_str}))


def percent_insecure(cls='" onload="alert(\'xss\')'):
    my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe('<b>%s</b>' % my_insecure_str)


def percent_list_insecure(cls='" onload="alert(\'xss\')'):
    my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe('<b>%s %s</b>' % (my_insecure_str, 'b'))


def percent_dict_insecure(cls='" onload="alert(\'xss\')'):
    my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe('<b>%(b)s</b>' % {'b': my_insecure_str})


def import_insecure():
    import sre_constants
    safestring.mark_safe(sre_constants.ANY)


def import_as_insecure():
    import sre_constants.ANY as any_str
    safestring.mark_safe(any_str)


def from_import_insecure():
    from sre_constants import ANY
    safestring.mark_safe(ANY)


def from_import_as_insecure():
    from sre_constants import ANY as any_str
    safestring.mark_safe(any_str)


def with_insecure(path):
    with open(path) as f:
        safestring.mark_safe(f.read())


def also_with_insecure(path):
    with open(path) as f:
        safestring.mark_safe(f)


def for_insecure():
    my_secure_str = ''
    for i in range(random.randint(0, 1)):  # nosec
        my_secure_str += insecure_function('insecure', cls='" onload="alert(\'xss\')')
    safestring.mark_safe(my_secure_str)


def while_insecure():
    my_secure_str = ''
    while ord(os.urandom(1)) % 2 == 0:
        my_secure_str += insecure_function('insecure', cls='" onload="alert(\'xss\')')
    safestring.mark_safe(my_secure_str)


def some_insecure_case():
    if ord(os.urandom(1)) % 2 == 0:
        my_secure_str = insecure_function('insecure', cls='" onload="alert(\'xss\')')
    elif ord(os.urandom(1)) % 2 == 0:
        my_secure_str = 'Secure'
    else:
        my_secure_str = 'Secure'
    safestring.mark_safe(my_secure_str)

mystr = 'insecure'


def test_insecure_shadow():  # var assigned out of scope
    safestring.mark_safe(mystr)


def test_insecure(str_arg):
    safestring.mark_safe(str_arg)


def test_insecure_with_assign(str_arg=None):
    if not str_arg:
        str_arg = 'could be insecure'
    safestring.mark_safe(str_arg)
import os
from django.utils import safestring

safestring.mark_safe('<b>secure</b>')
safestring.SafeText('<b>secure</b>')
safestring.SafeUnicode('<b>secure</b>')
safestring.SafeString('<b>secure</b>')
safestring.SafeBytes('<b>secure</b>')

my_secure_str = '<b>Hello World</b>'
safestring.mark_safe(my_secure_str)

my_secure_str, _ = ('<b>Hello World</b>', '')
safestring.mark_safe(my_secure_str)

also_secure_str = my_secure_str
safestring.mark_safe(also_secure_str)


def try_secure():
    try:
        my_secure_str = 'Secure'
    except Exception:
        my_secure_str = 'Secure'
    else:
        my_secure_str = 'Secure'
    finally:
        my_secure_str = 'Secure'
    safestring.mark_safe(my_secure_str)


def format_secure():
    safestring.mark_safe('<b>{}</b>'.format('secure'))
    my_secure_str = 'secure'
    safestring.mark_safe('<b>{}</b>'.format(my_secure_str))
    safestring.mark_safe('<b>{} {}</b>'.format(my_secure_str, 'a'))
    safestring.mark_safe('<b>{} {}</b>'.format(*[my_secure_str, 'a']))
    safestring.mark_safe('<b>{b}</b>'.format(b=my_secure_str))  # nosec TODO
    safestring.mark_safe('<b>{b}</b>'.format(**{'b': my_secure_str}))  # nosec TODO
    my_secure_str = '<b>{}</b>'.format(my_secure_str)
    safestring.mark_safe(my_secure_str)


def percent_secure():
    safestring.mark_safe('<b>%s</b>' % 'secure')
    my_secure_str = 'secure'
    safestring.mark_safe('<b>%s</b>' % my_secure_str)
    safestring.mark_safe('<b>%s %s</b>' % (my_secure_str, 'a'))
    safestring.mark_safe('<b>%(b)s</b>' % {'b': my_secure_str})  # nosec TODO


def with_secure(path):
    with open(path) as f:
        safestring.mark_safe('Secure')


def loop_secure():
    my_secure_str = ''

    for i in range(ord(os.urandom(1))):
        my_secure_str += ' Secure'
    safestring.mark_safe(my_secure_str)
    while ord(os.urandom(1)) % 2 == 0:
        my_secure_str += ' Secure'
    safestring.mark_safe(my_secure_str)


def all_secure_case():
    if ord(os.urandom(1)) % 2 == 0:
        my_secure_str = 'Secure'
    elif ord(os.urandom(1)) % 2 == 0:
        my_secure_str = 'Secure'
    else:
        my_secure_str = 'Secure'
    safestring.mark_safe(my_secure_str)
import marshal
import tempfile


serialized = marshal.dumps({'a': 1})
print(marshal.loads(serialized))

file_obj = tempfile.TemporaryFile()
marshal.dump(range(5), file_obj)
file_obj.seek(0)
print(marshal.load(file_obj))
file_obj.close()
from tempfile import mktemp
import tempfile.mktemp as mt
import tempfile as tmp

foo = 'hi'

mktemp(foo)
tempfile.mktemp('foo')
mt(foo)
tmp.mktemp(foo)
import subprocess

subprocess.check_output("/some_command",
                        "args",
                        shell=True,
                        universal_newlines=True)
import xml
import yaml

def subprocess_shell_cmd():
    # sample function with known subprocess shell cmd candidates
    # candidate #1
    subprocess.Popen('/bin/ls *', shell=True)
    # candidate #2
    subprocess.Popen('/bin/ls *', shell=True) # nosec

def yaml_load():
    # sample function with known yaml.load candidates
    temp_str = yaml.dump({'a': '1', 'b': '2'})
    # candidate #3
    y = yaml.load(temp_str)
    # candidate #4
    y = yaml.load(temp_str) # nosec

def xml_sax_make_parser():
    # sample function with known xml.sax.make_parser candidates
    # candidate #5
    xml.sax.make_parser()
    # candidate #6
    xml.sax.make_parser() # nosec
def subprocess_shell_cmd():
    # sample function with known subprocess shell cmd candidates

def yaml_load():
    # sample function with known yaml.load candidates

def xml_sax_make_parser():
    # sample function with known xml.sax.make_parser candidates
import xml
import yaml

def subprocess_shell_cmd():
    # sample function with known subprocess shell cmd candidates
    # candidate #2
    subprocess.Popen('/bin/ls *', shell=True) # nosec

def yaml_load():
    # sample function with known yaml.load candidates
    temp_str = yaml.dump({'a': '1', 'b': '2'})
    # candidate #4
    y = yaml.load(temp_str) # nosec

def xml_sax_make_parser():
    # sample function with known xml.sax.make_parser candidates
    # candidate #6
    xml.sax.make_parser() # nosec
import xml
import yaml

def subprocess_shell_cmd():
    # sample function with known subprocess shell cmd candidates
    # candidate #1
    subprocess.Popen('/bin/ls *', shell=True)
    # candidate #2
    subprocess.Popen('/bin/ls *', shell=True) # nosec

def yaml_load():
    # sample function with known yaml.load candidates
    temp_str = yaml.dump({'a': '1', 'b': '2'})
    # candidate #4
    y = yaml.load(temp_str) # nosec

def xml_sax_make_parser():
    # sample function with known xml.sax.make_parser candidates
    # candidate #6
    xml.sax.make_parser() # nosec
test(hi
�(�W nonsense.py +I-.���� �>�b   subprocess.Popen('/bin/ls *', shell=True) #nosec (on the line)
subprocess.Popen('/bin/ls *', #nosec (at the start of function call)
                 shell=True)
subprocess.Popen('/bin/ls *',
                 shell=True)  #nosec (on the specific kwarg line)
subprocess.Popen('#nosec', shell=True)
subprocess.Popen('/bin/ls *', shell=True) # type: … # nosec # noqa: E501 ; pylint: disable=line-too-long
from paramiko import client

ssh_client = client.SSHClient()
ssh_client.set_missing_host_key_policy(client.AutoAddPolicy)
ssh_client.set_missing_host_key_policy(client.WarningPolicy)
print('hopefully no vulnerabilities here')
import os
import stat

keyfile = 'foo'

os.chmod('/etc/passwd', 0o227)
os.chmod('/etc/passwd', 0o7)
os.chmod('/etc/passwd', 0o664)
os.chmod('/etc/passwd', 0o777)
os.chmod('/etc/passwd', 0o770)
os.chmod('/etc/passwd', 0o776)
os.chmod('/etc/passwd', 0o760)
os.chmod('~/.bashrc', 511)
os.chmod('/etc/hosts', 0o777)
os.chmod('/tmp/oh_hai', 0x1ff)
os.chmod('/etc/passwd', stat.S_IRWXU)
os.chmod(key_file, 0o777)
import os

os.execl(path, arg0, arg1)
os.execle(path, arg0, arg1, env)
os.execlp(file, arg0, arg1)
os.execlpe(file, arg0, arg1, env)
os.execv(path, args)
os.execve(path, args, env)
os.execvp(file, args)
os.execvpe(file, args, env)

import os
from os import popen
import os as o
from os import popen as pos

os.popen('/bin/uname -av')
popen('/bin/uname -av')
o.popen('/bin/uname -av')
pos('/bin/uname -av')
os.popen2('/bin/uname -av')
os.popen3('/bin/uname -av')
os.popen4('/bin/uname -av')

os.popen4('/bin/uname -av; rm -rf /')
os.popen4(some_var)
import os

os.spawnl(mode, path)
os.spawnle(mode, path, env)
os.spawnlp(mode, file)
os.spawnlpe(mode, file, env)
os.spawnv(mode, path, args)
os.spawnve(mode, path, args, env)
os.spawnvp(mode, file, args)
os.spawnvpe(mode, file, args, env)
import os

os.startfile('/bin/foo.docx')
os.startfile('/bin/bad.exe')
os.startfile('/bin/text.txt')
import os

os.system('/bin/echo hi')
import paramiko


client = paramiko.client.SSHClient()

# this is not safe
client.exec_command('something; really; unsafe')

# this is safe
client.connect('somehost')
from subprocess import Popen as pop

pop('gcc --version', shell=False)
pop('/bin/gcc --version', shell=False)
pop(var, shell=False)

pop(['ls', '-l'], shell=False)
pop(['/bin/ls', '-l'], shell=False)

pop('../ls -l', shell=False)

pop('c:\\hello\\something', shell=False)
pop('c:/hello/something_else', shell=False)
import cPickle
import pickle
import StringIO


# pickle
pick = pickle.dumps({'a': 'b', 'c': 'd'})
print(pickle.loads(pick))

file_obj = StringIO.StringIO()
pickle.dump([1, 2, '3'], file_obj)
file_obj.seek(0)
print(pickle.load(file_obj))

file_obj.seek(0)
print(pickle.Unpickler(file_obj).load())

# cPickle
serialized = cPickle.dumps({(): []})
print(cPickle.loads(serialized))

file_obj = StringIO.StringIO()
cPickle.dump((1,), file_obj)
file_obj.seek(0)
print(cPickle.load(file_obj))

file_obj.seek(0)
print(cPickle.Unpickler(file_obj).load())

import commands
import popen2


print(commands.getstatusoutput('/bin/echo / | xargs ls'))
print(commands.getoutput('/bin/echo / | xargs ls'))

# This one is safe.
print(commands.getstatus('/bin/echo / | xargs ls'))

print(popen2.popen2('/bin/echo / | xargs ls')[0].read())
print(popen2.popen3('/bin/echo / | xargs ls')[0].read())
print(popen2.popen4('/bin/echo / | xargs ls')[0].read())
print(popen2.Popen3('/bin/echo / | xargs ls').fromchild.read())
print(popen2.Popen4('/bin/echo / | xargs ls').fromchild.read())
from Crypto.Cipher import AES
from Crypto import Random

from . import CryptoMaterialsCacheEntry


def test_pycrypto():
    key = b'Sixteen byte key'
    iv = Random.new().read(AES.block_size)
    cipher = pycrypto_arc2.new(key, AES.MODE_CFB, iv)
    factory = CryptoMaterialsCacheEntry()
from Cryptodome.Cipher import AES
from Cryptodome import Random

from . import CryptoMaterialsCacheEntry


def test_pycrypto():
    key = b'Sixteen byte key'
    iv = Random.new().read(AES.block_size)
    cipher = pycrypto_arc2.new(key, AES.MODE_CFB, iv)
    factory = CryptoMaterialsCacheEntry()
import random
import os
import somelib

bad = random.random()
bad = random.randrange()
bad = random.randint()
bad = random.choice()
bad = random.choices()
bad = random.uniform()
bad = random.triangular()

good = os.urandom()
good = random.SystemRandom()

unknown = random()
unknown = somelib.a.random()
import requests

requests.get('https://gmail.com', verify=True)
requests.get('https://gmail.com', verify=False)
requests.post('https://gmail.com', verify=True)
requests.post('https://gmail.com', verify=False)
requests.put('https://gmail.com', verify=True)
requests.put('https://gmail.com', verify=False)
requests.delete('https://gmail.com', verify=True)
requests.delete('https://gmail.com', verify=False)
requests.patch('https://gmail.com', verify=True)
requests.patch('https://gmail.com', verify=False)
requests.options('https://gmail.com', verify=True)
requests.options('https://gmail.com', verify=False)
requests.head('https://gmail.com', verify=True)
requests.head('https://gmail.com', verify=False)
import os
import shelve
import tempfile

with tempfile.TemporaryDirectory() as d:
    filename = os.path.join(d, 'shelf')

    with shelve.open(filename) as db:
        db['spam'] = {'eggs': 'ham'}

    with shelve.open(filename) as db:
        print(db['spam'])
subprocess.call(["/bin/ls", "-l"])
subprocess.call(["/bin/ls", "-l"]) #noqa
subprocess.call(["/bin/ls", "-l"]) # noqa
subprocess.call(["/bin/ls", "-l"]) # nosec
subprocess.call(["/bin/ls", "-l"])
subprocess.call(["/bin/ls", "-l"]) #nosec
subprocess.call(["/bin/ls", "-l"])
import sqlalchemy

# bad
query = "SELECT * FROM foo WHERE id = '%s'" % identifier
query = "INSERT INTO foo VALUES ('a', 'b', '%s')" % value
query = "DELETE FROM foo WHERE id = '%s'" % identifier
query = "UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier
query = """WITH cte AS (SELECT x FROM foo)
SELECT x FROM cte WHERE x = '%s'""" % identifier
# bad alternate forms
query = "SELECT * FROM foo WHERE id = '" + identifier + "'"
query = "SELECT * FROM foo WHERE id = '{}'".format(identifier)
query = f"SELECT * FROM foo WHERE id = {tmp}"

# bad
cur.execute("SELECT * FROM foo WHERE id = '%s'" % identifier)
cur.execute("INSERT INTO foo VALUES ('a', 'b', '%s')" % value)
cur.execute("DELETE FROM foo WHERE id = '%s'" % identifier)
cur.execute("UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier)
# bad alternate forms
cur.execute("SELECT * FROM foo WHERE id = '" + identifier + "'")
cur.execute("SELECT * FROM foo WHERE id = '{}'".format(identifier))
cur.execute(f"SELECT * FROM foo WHERE id {tmp}")

# good
cur.execute("SELECT * FROM foo WHERE id = '%s'", identifier)
cur.execute("INSERT INTO foo VALUES ('a', 'b', '%s')", value)
cur.execute("DELETE FROM foo WHERE id = '%s'", identifier)
cur.execute("UPDATE foo SET value = 'b' WHERE id = '%s'", identifier)

# bug: https://bugs.launchpad.net/bandit/+bug/1479625
def a():
    def b():
        pass
    return b

a()("SELECT %s FROM foo" % val)

# real world false positives
choices=[('server_list', _("Select from active instances"))]
print("delete from the cache as the first argument")
import sqlalchemy

# bad
query = "SELECT * FROM foo WHERE id = '%s'" % identifier
query = "INSERT INTO foo VALUES ('a', 'b', '%s')" % value
query = "DELETE FROM foo WHERE id = '%s'" % identifier
query = "UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier
query = """WITH cte AS (SELECT x FROM foo)
SELECT x FROM cte WHERE x = '%s'""" % identifier
# bad alternate forms
query = "SELECT * FROM foo WHERE id = '" + identifier + "'"
query = "SELECT * FROM foo WHERE id = '{}'".format(identifier)

# bad
cur.execute("SELECT * FROM foo WHERE id = '%s'" % identifier)
cur.execute("INSERT INTO foo VALUES ('a', 'b', '%s')" % value)
cur.execute("DELETE FROM foo WHERE id = '%s'" % identifier)
cur.execute("UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier)
# bad alternate forms
cur.execute("SELECT * FROM foo WHERE id = '" + identifier + "'")
cur.execute("SELECT * FROM foo WHERE id = '{}'".format(identifier))

# good
cur.execute("SELECT * FROM foo WHERE id = '%s'", identifier)
cur.execute("INSERT INTO foo VALUES ('a', 'b', '%s')", value)
cur.execute("DELETE FROM foo WHERE id = '%s'", identifier)
cur.execute("UPDATE foo SET value = 'b' WHERE id = '%s'", identifier)

# bug: https://bugs.launchpad.net/bandit/+bug/1479625
def a():
    def b():
        pass
    return b

a()("SELECT %s FROM foo" % val)

# real world false positives
choices=[('server_list', _("Select from active instances"))]
print("delete from the cache as the first argument")
import ssl
from pyOpenSSL import SSL

ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv2)
SSL.Context(method=SSL.SSLv2_METHOD)
SSL.Context(method=SSL.SSLv23_METHOD)

herp_derp(ssl_version=ssl.PROTOCOL_SSLv2)
herp_derp(method=SSL.SSLv2_METHOD)
herp_derp(method=SSL.SSLv23_METHOD)

# strict tests
ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv3)
ssl.wrap_socket(ssl_version=ssl.PROTOCOL_TLSv1)
SSL.Context(method=SSL.SSLv3_METHOD)
SSL.Context(method=SSL.TLSv1_METHOD)

herp_derp(ssl_version=ssl.PROTOCOL_SSLv3)
herp_derp(ssl_version=ssl.PROTOCOL_TLSv1)
herp_derp(method=SSL.SSLv3_METHOD)
herp_derp(method=SSL.TLSv1_METHOD)

ssl.wrap_socket()

def open_ssl_socket(version=ssl.PROTOCOL_SSLv2):
    pass

def open_ssl_socket(version=SSL.SSLv2_METHOD):
    pass

def open_ssl_socket(version=SSL.SSLv23_METHOD):
    pass

# this one will pass ok
def open_ssl_socket(version=SSL.TLSv1_1_METHOD):
    pass
import subprocess
from subprocess import Popen as pop


def Popen(*args, **kwargs):
    print('hi')

    def __len__(self):
        return 0

pop('/bin/gcc --version', shell=True)
Popen('/bin/gcc --version', shell=True)

subprocess.Popen('/bin/gcc --version', shell=True)
subprocess.Popen(['/bin/gcc', '--version'], shell=False)
subprocess.Popen(['/bin/gcc', '--version'])

subprocess.call(["/bin/ls",
                 "-l"
                 ])
subprocess.call('/bin/ls -l', shell=True)

subprocess.check_call(['/bin/ls', '-l'], shell=False)
subprocess.check_call('/bin/ls -l', shell=True)

subprocess.check_output(['/bin/ls', '-l'])
subprocess.check_output('/bin/ls -l', shell=True)

subprocess.run(['/bin/ls', '-l'])
subprocess.run('/bin/ls -l', shell=True)

subprocess.Popen('/bin/ls *', shell=True)
subprocess.Popen('/bin/ls %s' % ('something',), shell=True)
subprocess.Popen('/bin/ls {}'.format('something'), shell=True)

command = "/bin/ls" + unknown_function()
subprocess.Popen(command, shell=True)

subprocess.Popen('/bin/ls && cat /etc/passwd', shell=True)

command = 'pwd'
subprocess.call(command, shell='True')
subprocess.call(command, shell='False')
subprocess.call(command, shell='None')
subprocess.call(command, shell=1)

subprocess.call(command, shell=Popen())
subprocess.call(command, shell=[True])
subprocess.call(command, shell={'IS': 'True'})
subprocess.call(command, shell=command)

subprocess.call(command, shell=False)
subprocess.call(command, shell=0)
subprocess.call(command, shell=[])
subprocess.call(command, shell={})
subprocess.call(command, shell=None)
import telnetlib
import getpass

host = sys.argv[1]

username = raw_input('Username:')
password = getpass.getpass()
tn = telnetlib.Telnet(host)

tn.read_until("login: ")
tn.write(username + "\n")
if password:
    tn.read_until("Password: ")
    tn.write(password + "\n")

tn.write("ls\n")
tn.write("exit\n")

print(tn.read_all())
from os import tempnam
from os import tmpnam
import os

os.tmpnam()

tmpnam()

os.tempnam('dir1')
os.tempnam('dir1', 'prefix1')

tempnam('dir1')
tempnam('dir1', 'prefix1')
# bad
for i in {0,1}:
    try:
        a = i
    except:
        continue


# bad
while keep_trying:
    try:
        a = 1
    except Exception:
        continue


# bad
for i in {0,2}:
    try:
        a = i
    except ZeroDivisionError:
        continue
    except:
        a = 2


# good
while keep_trying:
    try:
        a = 1
    except:
        a = 2
# bad
try:
    a = 1
except:
    pass


# bad
try:
    a = 1
except Exception:
    pass


# bad
try:
    a = 1
except ZeroDivisionError:
    pass
except:
    a = 2


# good
try:
    a = 1
except:
    a = 2


# silly, but ok
try:
    a = 1
except:
    pass
    a = 2
import ssl

# Correct
context = ssl.create_default_context()

# Incorrect: unverified context
context = ssl._create_unverified_context()
''' Example dangerous usage of urllib[2] opener functions

The urllib and urllib2 opener functions and object can open http, ftp,
and file urls. Often, the ability to open file urls is overlooked leading
to code that can unexpectedly open files on the local server. This
could be used by an attacker to leak information about the server.
'''


import urllib
import urllib2

# Python 3
import urllib.request

# Six
import six

def test_urlopen():
    # urllib
    url = urllib.quote('file:///bin/ls')
    urllib.urlopen(url, 'blah', 32)
    urllib.urlretrieve('file:///bin/ls', '/bin/ls2')
    opener = urllib.URLopener()
    opener.open('file:///bin/ls')
    opener.retrieve('file:///bin/ls')
    opener = urllib.FancyURLopener()
    opener.open('file:///bin/ls')
    opener.retrieve('file:///bin/ls')

    # urllib2
    handler = urllib2.HTTPBasicAuthHandler()
    handler.add_password(realm='test',
                         uri='http://mysite.com',
                         user='bob')
    opener = urllib2.build_opener(handler)
    urllib2.install_opener(opener)
    urllib2.urlopen('file:///bin/ls')
    urllib2.Request('file:///bin/ls')

    # Python 3
    urllib.request.urlopen('file:///bin/ls')
    urllib.request.urlretrieve('file:///bin/ls', '/bin/ls2')
    opener = urllib.request.URLopener()
    opener.open('file:///bin/ls')
    opener.retrieve('file:///bin/ls')
    opener = urllib.request.FancyURLopener()
    opener.open('file:///bin/ls')
    opener.retrieve('file:///bin/ls')

    # Six
    six.moves.urllib.request.urlopen('file:///bin/ls')
    six.moves.urllib.request.urlretrieve('file:///bin/ls', '/bin/ls2')
    opener = six.moves.urllib.request.URLopener()
    opener.open('file:///bin/ls')
    opener.retrieve('file:///bin/ls')
    opener = six.moves.urllib.request.FancyURLopener()
    opener.open('file:///bin/ls')
    opener.retrieve('file:///bin/ls')
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.PublicKey import DSA as pycrypto_dsa
from Crypto.PublicKey import RSA as pycrypto_rsa
from Cryptodome.PublicKey import DSA as pycryptodomex_dsa
from Cryptodome.PublicKey import RSA as pycryptodomex_rsa


# Correct
dsa.generate_private_key(key_size=2048,
                         backend=backends.default_backend())
ec.generate_private_key(curve=ec.SECP384R1,
                        backend=backends.default_backend())
rsa.generate_private_key(public_exponent=65537,
                         key_size=2048,
                         backend=backends.default_backend())
pycrypto_dsa.generate(bits=2048)
pycrypto_rsa.generate(bits=2048)
pycryptodomex_dsa.generate(bits=2048)
pycryptodomex_rsa.generate(bits=2048)

# Also correct: without keyword args
dsa.generate_private_key(4096,
                         backends.default_backend())
ec.generate_private_key(ec.SECP256K1,
                        backends.default_backend())
rsa.generate_private_key(3,
                         4096,
                         backends.default_backend())
pycrypto_dsa.generate(4096)
pycrypto_rsa.generate(4096)
pycryptodomex_dsa.generate(4096)
pycryptodomex_rsa.generate(4096)

# Incorrect: weak key sizes
dsa.generate_private_key(key_size=1024,
                         backend=backends.default_backend())
ec.generate_private_key(curve=ec.SECT163R2,
                        backend=backends.default_backend())
rsa.generate_private_key(public_exponent=65537,
                         key_size=1024,
                         backend=backends.default_backend())
pycrypto_dsa.generate(bits=1024)
pycrypto_rsa.generate(bits=1024)
pycryptodomex_dsa.generate(bits=1024)
pycryptodomex_rsa.generate(bits=1024)

# Also incorrect: without keyword args
dsa.generate_private_key(512,
                         backends.default_backend())
ec.generate_private_key(ec.SECT163R2,
                        backends.default_backend())
rsa.generate_private_key(3,
                         512,
                         backends.default_backend())
pycrypto_dsa.generate(512)
pycrypto_rsa.generate(512)
pycryptodomex_dsa.generate(512)
pycryptodomex_rsa.generate(512)

# Don't crash when the size is variable
rsa.generate_private_key(public_exponent=65537,
                         key_size=some_key_size,
                         backend=backends.default_backend())
import os as o
import subprocess as subp

# Vulnerable to wildcard injection
o.system("/bin/tar xvzf *")
o.system('/bin/chown *')
o.popen2('/bin/chmod *')
subp.Popen('/bin/chown *', shell=True)

# Not vulnerable to wildcard injection
subp.Popen('/bin/rsync *')
subp.Popen("/bin/chmod *")
subp.Popen(['/bin/chown', '*'])
subp.Popen(["/bin/chmod", sys.argv[1], "*"],
                 stdin=subprocess.PIPE, stdout=subprocess.PIPE)
o.spawnvp(os.P_WAIT, 'tar', ['tar', 'xvzf', '*'])
import xml.etree.cElementTree as badET
import defusedxml.cElementTree as goodET

xmlString = "<note>\n<to>Tove</to>\n<from>Jani</from>\n<heading>Reminder</heading>\n<body>Don't forget me this weekend!</body>\n</note>"

# unsafe
tree = badET.fromstring(xmlString)
print(tree)
badET.parse('filethatdoesntexist.xml')
badET.iterparse('filethatdoesntexist.xml')
a = badET.XMLParser()

# safe
tree = goodET.fromstring(xmlString)
print(tree)
goodET.parse('filethatdoesntexist.xml')
goodET.iterparse('filethatdoesntexist.xml')
a = goodET.XMLParser()
import xml.etree.ElementTree as badET
import defusedxml.ElementTree as goodET

xmlString = "<note>\n<to>Tove</to>\n<from>Jani</from>\n<heading>Reminder</heading>\n<body>Don't forget me this weekend!</body>\n</note>"

# unsafe
tree = badET.fromstring(xmlString)
print(tree)
badET.parse('filethatdoesntexist.xml')
badET.iterparse('filethatdoesntexist.xml')
a = badET.XMLParser()

# safe
tree = goodET.fromstring(xmlString)
print(tree)
goodET.parse('filethatdoesntexist.xml')
goodET.iterparse('filethatdoesntexist.xml')
a = goodET.XMLParser()
import xml.dom.expatbuilder as bad
import defusedxml.expatbuilder as good

bad.parse('filethatdoesntexist.xml')
good.parse('filethatdoesntexist.xml')

xmlString = "<note>\n<to>Tove</to>\n<from>Jani</from>\n<heading>Reminder</heading>\n<body>Don't forget me this weekend!</body>\n</note>"

bad.parseString(xmlString)
good.parseString(xmlString)
import xml.sax.expatreader as bad
import defusedxml.expatreader as good

p = bad.create_parser()
b = good.create_parser()
import lxml.etree
import lxml
from lxml import etree
from defusedxml.lxml import fromstring
from defuxedxml import lxml as potatoe

xmlString = "<note>\n<to>Tove</to>\n<from>Jani</from>\n<heading>Reminder</heading>\n<body>Don't forget me this weekend!</body>\n</note>"
root = lxml.etree.fromstring(xmlString)
root = fromstring(xmlString)
from xml.dom.minidom import parseString as badParseString
from defusedxml.minidom import parseString as goodParseString
a = badParseString("<myxml>Some data some more data</myxml>")
print(a)
b = goodParseString("<myxml>Some data some more data</myxml>")
print(b)


from xml.dom.minidom import parse as badParse
from defusedxml.minidom import parse as goodParse
a = badParse("somfilethatdoesntexist.xml")
print(a)
b = goodParse("somefilethatdoesntexist.xml")
print(b)
from xml.dom.pulldom import parseString as badParseString
from defusedxml.pulldom import parseString as goodParseString
a = badParseString("<myxml>Some data some more data</myxml>")
print(a)
b = goodParseString("<myxml>Some data some more data</myxml>")
print(b)


from xml.dom.pulldom import parse as badParse
from defusedxml.pulldom import parse as goodParse
a = badParse("somfilethatdoesntexist.xml")
print(a)
b = goodParse("somefilethatdoesntexist.xml")
print(b)
import xml.sax
from xml import sax
import defusedxml.sax

class ExampleContentHandler(xml.sax.ContentHandler):
    def __init__(self):
        xml.sax.ContentHandler.__init__(self)

    def startElement(self, name, attrs):
        print('start:', name)

    def endElement(self, name):
        print('end:', name)

    def characters(self, content):
        print('chars:', content)

def main():
    xmlString = "<note>\n<to>Tove</to>\n<from>Jani</from>\n<heading>Reminder</heading>\n<body>Don't forget me this weekend!</body>\n</note>"
    # bad
    xml.sax.parseString(xmlString, ExampleContentHandler())
    xml.sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler())
    sax.parseString(xmlString, ExampleContentHandler())
    sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler)

    # good
    defusedxml.sax.parseString(xmlString, ExampleContentHandler())

    # bad
    xml.sax.make_parser()
    sax.make_parser()
    print('nothing')
    # good
    defusedxml.sax.make_parser()

if __name__ == "__main__":
    main()
import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer

def is_even(n):
    return n%2 == 0

server = SimpleXMLRPCServer(("localhost", 8000))
print("Listening on port 8000...")
server.register_function(is_even, "is_even")
server.serve_forever()
import json
import yaml


def test_yaml_load():
    ystr = yaml.dump({'a': 1, 'b': 2, 'c': 3})
    y = yaml.load(ystr)
    yaml.dump(y)
    try:
        y = yaml.load(ystr, Loader=yaml.CSafeLoader)
    except AttributeError:
        # CSafeLoader only exists if you build yaml with LibYAML
        y = yaml.load(ystr, Loader=yaml.SafeLoader)


def test_json_load():
    # no issue should be found
    j = json.load("{}")
assert True