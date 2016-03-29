import os
import textwrap
import subprocess
import re
try:
    import cPickle as pickle
except ImportError:
    import pickle

log = '/isafw_deplog'
temp_file = '/isafw_dep_tmp'
report_file = '/dep_report'
DEPChecker = None

DEPENDENCIES_BLACKLIST = ['.*-dbg$', '.*-locale$', '.*-doc$']


class Dependency(object):
    def __init__(self, pkg_name, details):
        self.pkg_name = pkg_name
        self.details = details

    def __str__(self):
        return '{0} ({1})'.format(self.pkg_name, self.details)

    def __repr__(self):
        return self.__str__()


class ISA_DEPChecker:
    initialized = False

    def __init__(self, ISA_config):
        self.b_depgraph = {}  # build-time dependency graph
        self.r_depgraph = {}  # run-time dependency graph
        self.logdir = ISA_config.logdir
        self.reportdir = ISA_config.reportdir
        self.timestamp = ISA_config.timestamp

        self.initialized = True
        with open(self.logdir + log, 'a') as flog:
            flog.write("\nPlugin ISA_DEPChecker initialized!\n")

    def _filter_deps(self, deps):
        is_valid = lambda dep: not any(
            re.match(regex, dep.pkg_name) for regex in DEPENDENCIES_BLACKLIST
        )
        return filter(is_valid, deps)

    def _parse_rdeps(self, rdeps):
        if ':' not in rdeps:
            return rdeps, []

        pkg, dependencies = rdeps.split(':', 1)

        if not dependencies.strip():
            return pkg, []

        regex = r'((?P<name>[^\(/)\s]+)\s*(\((?P<details>[^)]*)\))?)'

        return pkg, [
            Dependency(dep.group('name'), dep.group('details'))
            for dep in re.finditer(regex, dependencies)
            if dep.group('name').strip().lower() != 'none'
            ]

    def process_package(self, ISA_pkg):
        b_deps = [Dependency(pkg, '') for pkg in ISA_pkg.b_deps]

        r_deps = dict()
        for deps in ISA_pkg.r_deps:
            pkg, dependencies = self._parse_rdeps(deps)
            r_deps.setdefault(pkg, set()).update(dependencies)

        b_filtered = self._filter_deps(b_deps)
        r_filtered = {}
        for pkg in r_deps:
            r_filtered[pkg] = self._filter_deps(r_deps[pkg])

        with open(self.reportdir + temp_file, 'a+b') as tmp:
            b_obj = ('b', ISA_pkg.name, b_filtered)
            pickle.dump(b_obj, tmp)

            for pkg in r_filtered:
                r_obj = ('r', pkg, r_filtered[pkg])
                pickle.dump(r_obj, tmp)

    def load_dep_graphs(self, remove_temp=False):
        """ Fill self.b_depgraph and self.r_depgraph """
        tmp = open(self.reportdir + temp_file, 'rb')

        while True:
            try:
                dep_type, pkg, deps = pickle.load(tmp)

                # update dependencies if node already exists in depgraph,
                # add new empty node otherwise
                depgraph = self.b_depgraph if dep_type == 'b' else self.r_depgraph
                node = depgraph.setdefault(pkg, set())
                node.update(deps)

            except EOFError:
                break

        tmp.close()

        if remove_temp:
            try:
                os.remove(self.reportdir + temp_file)
            except OSError:
                pass

    def process_report(self):
        self.load_dep_graphs()

        self._generate_graph(self.b_depgraph, 'build_time')
        self._generate_graph(self.r_depgraph, 'run_time')

    def generate_dot(self, digraph, vulnerable_packages, vuln_dependent_packages=set()):
        """ Generate a digraph definition in the DOT language """

        def _edge(a, b=None, label=None):
            """ Generate the DOT definition of a edge from `a` to `b`.
            If only `a` is provided, a standalone node with no links will be added to the graph.
            Vulnerable packages are red, while packages that depend on vuln. packages are yellow.
            """
            edge_template = '\t"{a}" -> "{b}" {opts};'
            standalone_node_template = '\t"{node}" {opts};'  # node with no dependencies

            if not b:
                if a in vulnerable_packages:
                    opts = ' [style=filled,fillcolor=red]'
                elif a in vuln_dependent_packages:
                    opts = ' [style=filled,fillcolor=yellow]'
                else:
                    opts = ''

                return standalone_node_template.format(node=a, opts=opts)

            opts = []
            if b in vuln_dependent_packages or b in vulnerable_packages:
                opts.append('color=red')
            if label:
                opts.append('label="' + label + '"')

            return edge_template.format(
                a=a, b=b,
                opts='[' + ','.join(opts) + ']' if opts else ''
            )

        graph_template = textwrap.dedent('''\
        digraph dependency_graph {{
        \tranksep=3;
        {edges}
        }}
        ''')

        edges = []
        for node in vuln_dependent_packages:
            edges.append(_edge(node))
        for node in vulnerable_packages:
            edges.append(_edge(node))

        for node, deps in digraph.iteritems():
            for dep in deps:
                edges.append(_edge(a=node, b=dep.pkg_name, label=dep.details))
            if not deps:
                edges.append(_edge(node))

        return graph_template.format(edges='\n'.join(edges))

    def invert_graph(self, depgraph):
        """ Build the inverse dependency graph.
        Dependencies details are not kept; only package names are considered.
        """
        inv_depgraph = {}
        for pkg, deps in depgraph.iteritems():
            for dep in deps:
                node = inv_depgraph.setdefault(dep.pkg_name, list())
                node.append(pkg)
            if pkg not in inv_depgraph:
                inv_depgraph[pkg] = []
        return inv_depgraph

    def get_dependent_pkgs(self, packages_name, depgraph):
        """ Given a package, return a list of the packages that depend on it. """
        if type(packages_name) not in (list, tuple):
            packages_name = [packages_name]

        dependent_packages = set()
        visited = set()

        inv_depgraph = self.invert_graph(depgraph)

        def dfs(node):
            visited.add(node)
            dependent_packages.update(inv_depgraph[node])
            for n in inv_depgraph[node]:
                if n not in visited:
                    dfs(n)

        for pkg_name in packages_name:
            dfs(pkg_name)

        return dependent_packages

    def _generate_graph(self, dep_graph, name, vulnerable_packages=tuple(), vuln_dependent_packages=set()):
        """ Draw and save a dependency graph """
        report_path = self.reportdir + report_file + '_' + name + '_' + self.timestamp + '.dot'

        dot_graph = self.generate_dot(dep_graph, vulnerable_packages, vuln_dependent_packages)
        with open(report_path, 'w') as f:
            f.write(dot_graph)

        # render the graph
        rc = subprocess.call(['which', 'dot'])
        if rc == 0:
            # remove transient redundancy from graph before rendering
            ps = subprocess.Popen(('tred', report_path), stdout=subprocess.PIPE)
            subprocess.call(
                ('dot', '-Tsvg', '-o', report_path[:-3] + 'svg'),
                stdin=ps.stdout
            )
            ps.wait()
        else:
            with open(self.logdir + log, 'a') as flog:
                flog.write('Graphviz is missing, the graphs will not be rendered.\n')

    def generate_complete_graph(self, dep_graph, vulnerable_packages, name):
        """ Draw and save the full dependency graph """
        vuln_dependent_packages = self.get_dependent_pkgs(vulnerable_packages, dep_graph)

        return self._generate_graph(dep_graph, name, vulnerable_packages, vuln_dependent_packages)

    def generate_vulnerability_graph(self, dep_graph, root_packages, vulnerable_packages, name):
        """ Draw and save a partial dependency graph """
        inv_depgraph = self.invert_graph(dep_graph)
        partial_graph = {}

        visited = set()

        def dfs(node):
            visited.add(node)
            for n in inv_depgraph[node]:
                partial_graph.setdefault(n, set()).add(Dependency(node, ''))

                if n not in visited:
                    dfs(n)

        for pkg in root_packages:
            dfs(pkg)

        vuln_dependent_packages = self.get_dependent_pkgs(vulnerable_packages, dep_graph)

        # todo: avoid tred-ing partial graphs?
        return self._generate_graph(partial_graph, name, vulnerable_packages, vuln_dependent_packages)

    def cleanup(self):
        try:  # remove temp file
            os.remove(self.reportdir + temp_file)
        except OSError:
            pass


# ======== supported callbacks from ISA ============= #

def init(ISA_config):
    global DEPChecker
    DEPChecker = ISA_DEPChecker(ISA_config)


def getPluginName():
    return "ISA_DEPChecker"


def process_package(ISA_pkg):
    global DEPChecker
    return DEPChecker.process_package(ISA_pkg)


def process_report():
    global DEPChecker
    return DEPChecker.process_report()


def runtime_vulnerability_graph(vuln_pkgs, name):
    global DEPChecker
    DEPChecker.load_dep_graphs()
    DEPChecker.generate_complete_graph(DEPChecker.r_depgraph, vuln_pkgs, name)


def runtime_vulnerability_graph_partial(root_pkgs, vuln_pkgs, name):
    global DEPChecker
    DEPChecker.load_dep_graphs()
    DEPChecker.generate_vulnerability_graph(DEPChecker.r_depgraph, root_pkgs, vuln_pkgs, name)


def buildtime_vulnerability_graph(vuln_pkgs, name):
    global DEPChecker
    DEPChecker.load_dep_graphs()
    DEPChecker.generate_complete_graph(DEPChecker.b_depgraph, vuln_pkgs, name)


def buildtime_vulnerability_graph_partial(root_pkgs, vuln_pkgs, name):
    global DEPChecker
    DEPChecker.load_dep_graphs()
    DEPChecker.generate_vulnerability_graph(DEPChecker.b_depgraph, root_pkgs, vuln_pkgs, name)


def cleanup():
    global DEPChecker
    DEPChecker.cleanup()

# ==================================================== #
