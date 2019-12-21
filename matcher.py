import sys
import re
from collections.abc import MutableMapping as DictMixin

__author__ = 'Alfonso Villalobos'
__version__ = '0.1'
__license__ = 'MIT'


def makelist(data): # This is just to handy
    if isinstance(data, (tuple, list, set, dict)): return list(data)
    elif data: return [data]
    else: return []


def yieldroutes(func):
    """ Return a generator for routes that match the signature (name, args)
    of the func parameter. This may yield more than one route if the function
    takes optional keyword arguments. The output is best described by example::

        a()         -> '/a'
        b(x, y)     -> '/b/<x>/<y>'
        c(x, y=5)   -> '/c/<x>' and '/c/<x>/<y>'
        d(x=5, y=6) -> '/d' and '/d/<x>' and '/d/<x>/<y>'
    """
    path = '/' + func.__name__.replace('__','/').lstrip('/')
    spec = getargspec(func)
    argc = len(spec[0]) - len(spec[3] or [])
    path += ('/<%s>' * argc) % tuple(spec[0][:argc])
    yield path
    for arg in spec[0][argc:]:
        path += '/<%s>' % arg
        yield path


def _re_flatten(p):
    ''' Turn all capturing groups in a regular expression pattern into
        non-capturing groups. '''
    if '(' not in p: return p
    return re.sub(r'(\\*)(\(\?P<[^>]+>|\((?!\?))',
        lambda m: m.group(0) if len(m.group(1)) % 2 else m.group(1) + '(?:', p)


class Router(object):

    default_pattern = '[^/]+'
    default_filter  = 're'

    #: The current CPython regexp implementation does not allow more
    #: than 99 matching groups per regular expression.
    _MAX_GROUPS_PER_PATTERN = 99

    def __init__(self, strict=False):
        '''
        Constructor function
        '''
        self.static = {}
        self.dyna_routes = {}
        self.dyna_regexes = {}
        self.builder  = {}
        self._groups  = {}
        self.strict_order = strict
        self.routes = []
        self.filters = {
            're':    lambda conf:
                (_re_flatten(conf or self.default_pattern), None, None),
            'int':   lambda conf: (r'-?\d+', int, lambda x: str(int(x))),
            'float': lambda conf: (r'-?[\d.]+', float, lambda x: str(float(x))),
            'path':  lambda conf: (r'.+?', None, None)}

    def route(self, path, callback=None, name=None, apply=None,
        skip=None, **config):
        plugins = makelist(apply)
        skiplist = makelist(skip)
        def decorator(callback):
            if isinstance(callback, str): callback = load(callback)
            for rule in makelist(path) or yieldroutes(callback):
                route = Route(self, rule, callback, name=name,
                              plugins=plugins, skiplist=skiplist, **config)
                self.add_route(route)
            return callback
        return decorator(callback) if callback else decorator

    def get(self, path=None, **options):
        return self.route(path, **options)

    def add_route(self, route):
        self.routes.append(route)
        self.add(route.rule, 'GET', route, name=route.name)

    rule_syntax = re.compile('(\\\\*)'\
        '(?:(?::([a-zA-Z_][a-zA-Z_0-9]*)?()(?:#(.*?)#)?)'\
          '|(?:<([a-zA-Z_][a-zA-Z_0-9]*)?(?::([a-zA-Z_]*)'\
            '(?::((?:\\\\.|[^\\\\>]+)+)?)?)?>))')

    def _itertokens(self, rule):
        offset, prefix = 0, ''
        for match in self.rule_syntax.finditer(rule):
            prefix += rule[offset:match.start()]
            g = match.groups()
            if len(g[0])%2: # Escaped wildcard
                prefix += match.group(0)[len(g[0]):]
                offset = match.end()
                continue
            if prefix:
                yield prefix, None, None
            name, filtr, conf = g[4:7] if g[2] is None else g[1:4]
            yield name, filtr or 'default', conf or None
            offset, prefix = match.end(), ''
        if offset <= len(rule) or prefix:
            yield prefix+rule[offset:], None, None

    def _compile(self, method):
        all_rules = self.dyna_routes[method]
        comborules = self.dyna_regexes[method] = []
        maxgroups = self._MAX_GROUPS_PER_PATTERN
        for x in range(0, len(all_rules), maxgroups):
            some = all_rules[x:x+maxgroups]
            combined = (flatpat for (_, flatpat, _, _) in some)
            combined = '|'.join('(^%s$)' % flatpat for flatpat in combined)
            combined = re.compile(combined).match
            rules = [(target, getargs) for (_, _, target, getargs) in some]
            comborules.append((combined, rules))

    def add(self, rule, method, target, name=None):
        ''' Add a new rule or replace the target for an existing rule. '''
        anons     = 0    # Number of anonymous wildcards found
        keys      = []   # Names of keys
        pattern   = ''   # Regular expression pattern with named groups
        filters   = []   # Lists of wildcard input filters
        builder   = []   # Data structure for the URL builder
        is_static = True

        for key, mode, conf in self._itertokens(rule):
            if mode:
                is_static = False
                if mode == 'default': mode = self.default_filter
                mask, in_filter, out_filter = self.filters[mode](conf)
                if not key:
                    pattern += '(?:%s)' % mask
                    key = 'anon%d' % anons
                    anons += 1
                else:
                    pattern += '(?P<%s>%s)' % (key, mask)
                    keys.append(key)
                if in_filter: filters.append((key, in_filter))
                builder.append((key, out_filter or str))
            elif key:
                pattern += re.escape(key)
                builder.append((None, key))

        self.builder[rule] = builder
        if name: self.builder[name] = builder

        if is_static and not self.strict_order:
            self.static.setdefault(method, {})
            self.static[method][self.build(rule)] = (target, None)
            return

        try:
            re_pattern = re.compile('^(%s)$' % pattern)
            re_match = re_pattern.match
        except re.error:
            raise RouteSyntaxError("Could not add Route: %s (%s)" % (rule, _e()))

        if filters:
            def getargs(path):
                url_args = re_match(path).groupdict()
                for name, wildcard_filter in filters:
                    try:
                        url_args[name] = wildcard_filter(url_args[name])
                    except ValueError:
                        raise HTTPError(400, 'Path has wrong format.')
                return url_args
        elif re_pattern.groupindex:
            def getargs(path):
                return re_match(path).groupdict()
        else:
            getargs = None

        flatpat = _re_flatten(pattern)
        whole_rule = (rule, flatpat, target, getargs)

        if (flatpat, method) in self._groups:
            if DEBUG:
                msg = 'Route <%s %s> overwrites a previously defined route'
                warnings.warn(msg % (method, rule), RuntimeWarning)
            self.dyna_routes[method][self._groups[flatpat, method]] = whole_rule
        else:
            self.dyna_routes.setdefault(method, []).append(whole_rule)
            self._groups[flatpat, method] = len(self.dyna_routes[method]) - 1

        self._compile(method)

    def build(self, _name, *anons, **query):
        ''' Build an URL by filling the wildcards in a rule. '''
        builder = self.builder.get(_name)
        if not builder: raise RouteBuildError("No route with that name.", _name)
        try:
            for i, value in enumerate(anons): query['anon%d'%i] = value
            url = ''.join([f(query.pop(n)) if n else f for (n,f) in builder])
            return url if not query else url+'?'+urlencode(query)
        except KeyError:
            raise RouteBuildError('Missing URL argument: %r' % _e().args[0])

    def match(self, path):
        ''' Return a (target, url_agrs) tuple or raise HTTPError(400/404/405). '''
        # verb = environ['REQUEST_METHOD'].upper()
        # path = environ['PATH_INFO'] or '/'
        target = None
        methods = ['PROXY', 'GET']
        for method in methods:
            if method in self.static and path in self.static[method]:
                target, getargs = self.static[method][path]
                return target, getargs(path) if getargs else {}
            elif method in self.dyna_regexes:
                for combined, rules in self.dyna_regexes[method]:
                    match = combined(path)
                    if match:
                        target, getargs = rules[match.lastindex - 1]
                        return target, getargs(path) if getargs else {}

        # No matching route found. Collect alternative methods for 405 response
        allowed = set([])
        nocheck = set(methods)
        for method in set(self.static) - nocheck:
            if path in self.static[method]:
                allowed.add(verb)
        for method in set(self.dyna_regexes) - allowed - nocheck:
            for combined, rules in self.dyna_regexes[method]:
                match = combined(path)
                if match:
                    allowed.add(method)
        if allowed:
            allow_header = ",".join(sorted(allowed))
            print(405, "Method not allowed.", Allow=allow_header)

        # No matching route and no alternative method found. We give up
        print('Error not found')


class ConfigDict(dict):
    ''' A dict-like configuration storage with additional support for
        namespaces, validators, meta-data, on_change listeners and more.

        This storage is optimized for fast read access. Retrieving a key
        or using non-altering dict methods (e.g. `dict.get()`) has no overhead
        compared to a native dict.
    '''
    __slots__ = ('_meta', '_on_change')

    class Namespace(DictMixin):

        def __init__(self, config, namespace):
            self._config = config
            self._prefix = namespace

        def __getitem__(self, key):
            depr('Accessing namespaces as dicts is discouraged. '
                 'Only use flat item access: '
                 'cfg["names"]["pace"]["key"] -> cfg["name.space.key"]') #0.12
            return self._config[self._prefix + '.' + key]

        def __setitem__(self, key, value):
            self._config[self._prefix + '.' + key] = value

        def __delitem__(self, key):
            del self._config[self._prefix + '.' + key]

        def __iter__(self):
            ns_prefix = self._prefix + '.'
            for key in self._config:
                ns, dot, name = key.rpartition('.')
                if ns == self._prefix and name:
                    yield name

        def keys(self): return [x for x in self]
        def __len__(self): return len(self.keys())
        def __contains__(self, key): return self._prefix + '.' + key in self._config
        def __repr__(self): return '<Config.Namespace %s.*>' % self._prefix
        def __str__(self): return '<Config.Namespace %s.*>' % self._prefix

        # Deprecated ConfigDict features
        def __getattr__(self, key):
            depr('Attribute access is deprecated.') #0.12
            if key not in self and key[0].isupper():
                self[key] = ConfigDict.Namespace(self._config, self._prefix + '.' + key)
            if key not in self and key.startswith('__'):
                raise AttributeError(key)
            return self.get(key)

        def __setattr__(self, key, value):
            if key in ('_config', '_prefix'):
                self.__dict__[key] = value
                return
            depr('Attribute assignment is deprecated.') #0.12
            if hasattr(DictMixin, key):
                raise AttributeError('Read-only attribute.')
            if key in self and self[key] and isinstance(self[key], self.__class__):
                raise AttributeError('Non-empty namespace attribute.')
            self[key] = value

        def __delattr__(self, key):
            if key in self:
                val = self.pop(key)
                if isinstance(val, self.__class__):
                    prefix = key + '.'
                    for key in self:
                        if key.startswith(prefix):
                            del self[prefix+key]

        def __call__(self, *a, **ka):
            depr('Calling ConfDict is deprecated. Use the update() method.') #0.12
            self.update(*a, **ka)
            return self

    def __init__(self, *a, **ka):
        self._meta = {}
        self._on_change = lambda name, value: None
        if a or ka:
            depr('Constructor does no longer accept parameters.') #0.12
            self.update(*a, **ka)

    def load_config(self, filename):
        ''' Load values from an *.ini style config file.

            If the config file contains sections, their names are used as
            namespaces for the values within. The two special sections
            ``DEFAULT`` and ``bottle`` refer to the root namespace (no prefix).
        '''
        conf = ConfigParser()
        conf.read(filename)
        for section in conf.sections():
            for key, value in conf.items(section):
                if section not in ('DEFAULT', 'bottle'):
                    key = section + '.' + key
                self[key] = value
        return self

    def load_dict(self, source, namespace='', make_namespaces=False):
        ''' Import values from a dictionary structure. Nesting can be used to
            represent namespaces.

            >>> ConfigDict().load_dict({'name': {'space': {'key': 'value'}}})
            {'name.space.key': 'value'}
        '''
        stack = [(namespace, source)]
        while stack:
            prefix, source = stack.pop()
            if not isinstance(source, dict):
                raise TypeError('Source is not a dict (r)' % type(key))
            for key, value in source.items():
                if not isinstance(key, basestring):
                    raise TypeError('Key is not a string (%r)' % type(key))
                full_key = prefix + '.' + key if prefix else key
                if isinstance(value, dict):
                    stack.append((full_key, value))
                    if make_namespaces:
                        self[full_key] = self.Namespace(self, full_key)
                else:
                    self[full_key] = value
        return self

    def update(self, *a, **ka):
        ''' If the first parameter is a string, all keys are prefixed with this
            namespace. Apart from that it works just as the usual dict.update().
            Example: ``update('some.namespace', key='value')`` '''
        prefix = ''
        if a and isinstance(a[0], basestring):
            prefix = a[0].strip('.') + '.'
            a = a[1:]
        for key, value in dict(*a, **ka).items():
            self[prefix+key] = value

    def setdefault(self, key, value):
        if key not in self:
            self[key] = value
        return self[key]

    def __setitem__(self, key, value):
        if not isinstance(key, basestring):
            raise TypeError('Key has type %r (not a string)' % type(key))

        value = self.meta_get(key, 'filter', lambda x: x)(value)
        if key in self and self[key] is value:
            return
        self._on_change(key, value)
        dict.__setitem__(self, key, value)

    def __delitem__(self, key):
        dict.__delitem__(self, key)

    def clear(self):
        for key in self:
            del self[key]

    def meta_get(self, key, metafield, default=None):
        ''' Return the value of a meta field for a key. '''
        return self._meta.get(key, {}).get(metafield, default)

    def meta_set(self, key, metafield, value):
        ''' Set the meta field for a key to a new value. This triggers the
            on-change handler for existing keys. '''
        self._meta.setdefault(key, {})[metafield] = value
        if key in self:
            self[key] = self[key]

    def meta_list(self, key):
        ''' Return an iterable of meta field names defined for a key. '''
        return self._meta.get(key, {}).keys()

    # Deprecated ConfigDict features
    def __getattr__(self, key):
        depr('Attribute access is deprecated.') #0.12
        if key not in self and key[0].isupper():
            self[key] = self.Namespace(self, key)
        if key not in self and key.startswith('__'):
            raise AttributeError(key)
        return self.get(key)

    def __setattr__(self, key, value):
        if key in self.__slots__:
            return dict.__setattr__(self, key, value)
        depr('Attribute assignment is deprecated.') #0.12
        if hasattr(dict, key):
            raise AttributeError('Read-only attribute.')
        if key in self and self[key] and isinstance(self[key], self.Namespace):
            raise AttributeError('Non-empty namespace attribute.')
        self[key] = value

    def __delattr__(self, key):
        if key in self:
            val = self.pop(key)
            if isinstance(val, self.Namespace):
                prefix = key + '.'
                for key in self:
                    if key.startswith(prefix):
                        del self[prefix+key]

    def __call__(self, *a, **ka):
        depr('Calling ConfDict is deprecated. Use the update() method.') #0.12
        self.update(*a, **ka)
        return self


class Route(object):
    ''' This class wraps a route callback along with route specific metadata and
        configuration and applies Plugins on demand. It is also responsible for
        turing an URL path rule into a regular expression usable by the Router.
    '''

    def __init__(self, app, rule, callback, name=None,
                 plugins=None, skiplist=None, **config):
        #: The application this route is installed to.
        self.app = app
        #: The path-rule string (e.g. ``/wiki/:page``).
        self.rule = rule
        #: The original callback with no plugins applied. Useful for introspection.
        self.callback = callback
        #: The name of the route (if specified) or ``None``.
        self.name = name or None
        #: A list of route-specific plugins (see :meth:`Bottle.route`).
        self.plugins = plugins or []
        #: A list of plugins to not apply to this route (see :meth:`Bottle.route`).
        self.skiplist = skiplist or []
        #: Additional keyword arguments passed to the :meth:`Bottle.route`
        #: decorator are stored in this dictionary. Used for route-specific
        #: plugin configuration and meta-data.
        self.config = ConfigDict().load_dict(config, make_namespaces=True)

    def __call__(self, *a, **ka):
        depr("Some APIs changed to return Route() instances instead of"\
             " callables. Make sure to use the Route.call method and not to"\
             " call Route instances directly.") #0.12
        return self.call(*a, **ka)

    def _make_callback(self):
        callback = self.callback
        for plugin in self.all_plugins():
            try:
                if hasattr(plugin, 'apply'):
                    api = getattr(plugin, 'api', 1)
                    context = self if api > 1 else self._context
                    callback = plugin.apply(callback, context)
                else:
                    callback = plugin(callback)
            except RouteReset: # Try again with changed configuration.
                return self._make_callback()
            if not callback is self.callback:
                update_wrapper(callback, self.callback)
        return callback

    def get_undecorated_callback(self):
        ''' Return the callback. If the callback is a decorated function, try to
            recover the original function. '''
        func = self.callback
        func = getattr(func, '__func__' if py3k else 'im_func', func)
        closure_attr = '__closure__' if py3k else 'func_closure'
        while hasattr(func, closure_attr) and getattr(func, closure_attr):
            func = getattr(func, closure_attr)[0].cell_contents
        return func

    def get_callback_args(self):
        ''' Return a list of argument names the callback (most likely) accepts
            as keyword arguments. If the callback is a decorated function, try
            to recover the original function before inspection. '''
        return getargspec(self.get_undecorated_callback())[0]

    def get_config(self, key, default=None):
        ''' Lookup a config field and return its value, first checking the
            route.config, then route.app.config.'''
        for conf in (self.config, self.app.conifg):
            if key in conf: return conf[key]
        return default


class Matcher(Router):

    def __init__():
        '''
        Constructor function
        '''
        self.router = Router()

    def excect_route(self, websockets, path):
        '''
        Function dedicated to return the function that the path wants binding
        the websockets for fourther use of it
        '''
        self.socket = websockets
        route_tuple = self.match(path)
        route_tuple[0].callback(route_tuple[1])
