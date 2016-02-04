import os
try:
    import cPickle as pickle
except ImportError:
    import pickle

log = '/isafw_deplog'
temp_file = '/isafw_dep_tmp'
DEPChecker = None


class ISA_DEPChecker:
    initialized = False

    def __init__(self, ISA_config):
        self.logdir = ISA_config.logdir
        self.reportdir = ISA_config.reportdir
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

        depgraph = {}
        while True:
            try:
                pkg, deps = pickle.load(tmp)

                # update dependencies if node already exists in depgraph,
                # add new empty node otherwise
                node = depgraph.setdefault(pkg, set())
                node.update(deps)

            except EOFError:
                break

        tmp.close()

        try:  # remove temp file
            os.remove(self.reportdir + temp_file)
        except OSError:
            pass

        # put dependency graph in log file. todo: remove me
        with open(self.logdir + log, 'a') as flog:
            flog.write(str(depgraph))


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
