import sys
from dataclasses import dataclass, field

def vuln_search_recursive(path, target, project, proj_libs):
    lib = project[target]
    lib.is_visited = True
    if lib.lib_name in proj_libs:
        if '[' not in path or ']' not in path:
            print(path)
    for parent in lib.parents:
        if project[parent].is_visited:
            continue
        vuln_search_recursive(parent + ' ' + path, parent, project, proj_libs)
    lib.is_visited = False

@dataclass
class Lib:
    lib_name: str
    is_visited: bool = False
    dependencies: set = field(default_factory=set)
    parents: set = field(default_factory=set)

    def add_lib_parent(self, parent):
        self.parents.add(parent)

    def add_lib_dependency(self, dependency):
        self.dependencies = self.dependencies.union(dependency)


if __name__ == '__main__':
    project = dict()
    vuln_libs = set(input().split())
    proj_libs = set(input().split())
    for lib_name in proj_libs.union(vuln_libs):
        if project.get(lib_name) is None:
            project[lib_name] = Lib(lib_name=lib_name)
    array = []
    for line in sys.stdin.readlines():
        if len(line.rstrip()) != 0:
            array.append(line.rstrip())
    try:
        for line in array:
            libs_list = str(line).split()
            for lib_name in libs_list:
                if project.get(lib_name) is None:
                    project[lib_name] = Lib(lib_name=lib_name)
            parent = libs_list[0]
            dependencies = libs_list[1:]
            project[parent].add_lib_dependency(dependency=dependencies)
            for dependency in dependencies:
                project[dependency].add_lib_parent(parent=parent)

        for vuln_lib in vuln_libs:
            vuln_search_recursive(path=vuln_lib, target=vuln_lib, project=project, proj_libs=proj_libs)
    except:
        print("", end='')
