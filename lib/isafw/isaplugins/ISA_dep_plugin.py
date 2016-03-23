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

        self.generate_graph(self.b_depgraph, 'build_time')
        self.generate_graph(self.r_depgraph, 'run_time')

    def generate_graph(self, dep_graph, deps_type):
        report_path = self.reportdir + report_file + '_' + deps_type + '_' + self.timestamp + '.dot'

        dot_graph = self.generate_dot(dep_graph)
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

    def generate_dot(self, digraph):
        """ Generate a digraph definition in the DOT language """
        graph_template = textwrap.dedent('''\
        digraph dependency_graph {{
        \tranksep=3;
        {edges}
        }}
        ''')
        edge_template = '\t"{a}" -> "{b}";'

        edges = []
        for node, deps in digraph.iteritems():
            for dep in deps:
                edges.append(edge_template.format(a=node, b=dep.pkg_name))

        return graph_template.format(edges='\n'.join(edges))


# ======== supported callbacks from ISA ============= #

def init(ISA_config):
    global DEPChecker
    DEPChecker = DEPChecker or ISA_DEPChecker(ISA_config)


def getPluginName():
    return "ISA_DEPChecker"


def process_package(ISA_pkg):
    global DEPChecker
    return DEPChecker.process_package(ISA_pkg)


def process_report():
    global DEPChecker
    return DEPChecker.process_report()

# ==================================================== #
