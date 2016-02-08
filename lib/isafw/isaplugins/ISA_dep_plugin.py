import os
import textwrap
import subprocess

try:
    import cPickle as pickle
except ImportError:
    import pickle

log = '/isafw_deplog'
temp_file = '/isafw_dep_tmp'
report_file = '/dep_report'
DEPChecker = None


class ISA_DEPChecker:
    initialized = False

    def __init__(self, ISA_config):
        self.depgraph = {}
        self.logdir = ISA_config.logdir
        self.reportdir = ISA_config.reportdir
        self.timestamp = ISA_config.timestamp

        self.initialized = True
        with open(self.logdir + log, 'a') as flog:
            flog.write("\nPlugin ISA_DEPChecker initialized!\n")

    def process_package(self, ISA_pkg):
        b_deps = ISA_pkg.b_deps

        with open(self.reportdir + temp_file, 'a+b') as tmp:
            obj = (ISA_pkg.name, b_deps)
            pickle.dump(obj, tmp)

    def process_report(self):
        tmp = open(self.reportdir + temp_file, 'rb')

        while True:
            try:
                pkg, deps = pickle.load(tmp)

                # update dependencies if node already exists in depgraph,
                # add new empty node otherwise
                node = self.depgraph.setdefault(pkg, set())
                node.update(deps)

            except EOFError:
                break

        tmp.close()

        try:  # remove temp file
            os.remove(self.reportdir + temp_file)
        except OSError:
            pass

        dot_graph = self.generate_dot()
        report_path = self.reportdir + report_file + '_' + self.timestamp + '.dot'
        with open(report_path, 'w') as f:
            f.write(dot_graph)

        # render the graph
        rc = subprocess.call(['which', 'dot'])
        if rc == 0:
            # remove transient redundancy from graph before rendering
            ps = subprocess.Popen(('tred', report_path), stdout=subprocess.PIPE)
            subprocess.call(
                    ('dot', '-Tpng', '-o', report_path[:-3] + 'png'),
                    stdin=ps.stdout
            )
            ps.wait()
        else:
            with open(self.logdir + log, 'a') as flog:
                flog.write('Graphviz is missing, the graph will not be rendered.\n')

        # put dependency graph in log file. todo: remove me
        with open(self.logdir + log, 'a') as flog:
            flog.write(str(self.depgraph))

    def generate_dot(self):
        """ Generate a digraph definition in the DOT language """
        graph_template = textwrap.dedent('''\
        digraph dependency_graph {{
        \tranksep=3;
        {edges}
        }}
        ''')
        edge_template = '\t"{a}" -> "{b}";'

        edges = []
        for node, deps in self.depgraph.iteritems():
            for dep in deps:
                edges.append(edge_template.format(a=node, b=dep))

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
