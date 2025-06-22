import os
import ast
import json
import subprocess
import chardet
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Union
import re

class UniversalRepoAnalyzer:
    def __init__(self, repo_url: str):
        self.repo_url = repo_url
        self.repo_name = repo_url.split("/")[-1].replace(".git", "")
        self.local_path = f"./temp_{self.repo_name}"
        self.dependency_graph = defaultdict(set)
        self.cyclic_dependencies = []
        self.file_types = defaultdict(int)
        self.binary_files = []

    def clone_repo(self) -> None:
        """Клонирует репозиторий."""
        if not os.path.exists(self.local_path):
            subprocess.run(["git", "clone", self.repo_url, self.local_path], check=True)

    def scan_files(self) -> None:
        """Сканирует все файлы в репозитории."""
        for root, _, files in os.walk(self.local_path):
            for file in files:
                file_path = os.path.join(root, file)
                self._analyze_file(file_path)

    def _analyze_file(self, file_path: str) -> None:
        """Анализирует файл в зависимости от его типа."""
        file_ext = os.path.splitext(file_path)[1].lower()
        self.file_types[file_ext] += 1

        if self._is_binary(file_path):
            self.binary_files.append(file_path)
            return

        try:
            with open(file_path, "rb") as f:
                raw_data = f.read()
                encoding = chardet.detect(raw_data)["encoding"] or "utf-8"
                content = raw_data.decode(encoding)
        except UnicodeDecodeError:
            return

        relative_path = os.path.relpath(file_path, self.local_path)

        if file_ext == ".py":
            self._analyze_python(relative_path, content)
        elif file_ext == ".js":
            self._analyze_javascript(relative_path, content)
        elif file_ext == ".go":
            self._analyze_go(relative_path, content)
        elif file_ext == ".rs":
            self._analyze_rust(relative_path, content)
        elif file_ext in (".java", ".kt"):
            self._analyze_java(relative_path, content)
        elif file_ext == ".cpp":
            self._analyze_cpp(relative_path, content)

    def _is_binary(self, file_path: str) -> bool:
        """Проверяет, является ли файл бинарным."""
        try:
            with open(file_path, "rb") as f:
                return b"\x00" in f.read(1024)
        except:
            return True

    def _analyze_python(self, file_path: str, content: str) -> None:
        """Анализирует Python-файл."""
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    for alias in node.names:
                        module = alias.name.split(".")[0]
                        if not module.startswith((".", "_")) and module not in ("sys", "os"):
                            self.dependency_graph[file_path].add(module)
        except SyntaxError:
            pass

    def _analyze_javascript(self, file_path: str, content: str) -> None:
        """Анализирует JavaScript-файл."""
        imports = re.findall(r"import\s+(?:.*?\s+from\s+)?[\"']([^\"']+)", content)
        for imp in imports:
            if not imp.startswith((".", "/")):
                self.dependency_graph[file_path].add(imp.split("/")[0])

    def _analyze_go(self, file_path: str, content: str) -> None:
        """Анализирует Go-файл."""
        imports = re.findall(r"import\s+\(([^)]+)\)", content, re.DOTALL)
        for imp_group in imports:
            for imp in imp_group.split("\n"):
                imp = imp.strip().strip('"')
                if imp and not imp.startswith((".", "_")):
                    self.dependency_graph[file_path].add(imp.split("/")[-1])

    def _analyze_rust(self, file_path: str, content: str) -> None:
        """Анализирует Rust-файл."""
        imports = re.findall(r"use\s+([^;]+);", content)
        for imp in imports:
            imp = imp.strip().split("::")[0]
            if imp and not imp.startswith((".", "crate", "self")):
                self.dependency_graph[file_path].add(imp)

    def detect_cycles(self) -> None:
        """Находит циклы в графе зависимостей."""
        visited = set()
        recursion_stack = set()

        def dfs(node: str, path: List[str]) -> None:
            if node in recursion_stack:
                cycle_start_index = path.index(node)
                cycle = path[cycle_start_index:]
                if len(cycle) > 1:
                    self.cyclic_dependencies.append(tuple(cycle))
                return
            if node in visited:
                return

            visited.add(node)
            recursion_stack.add(node)
            path.append(node)

            for neighbor in self.dependency_graph.get(node, set()):
                dfs(neighbor, path.copy())

            recursion_stack.remove(node)
            path.pop()

        for node in self.dependency_graph:
            dfs(node, [])

    def export_to_dot(self, output_file: str = "dependencies.dot") -> None:
        """Экспортирует граф в формат DOT."""
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("digraph Dependencies {\n")
            f.write('    rankdir="LR";\n')
            for src, deps in self.dependency_graph.items():
                for dst in deps:
                    f.write(f'    "{src}" -> "{dst}";\n')
            f.write("}\n")

    def export_to_json(self, output_file: str = "dependencies.json") -> None:
        """Экспортирует граф в JSON."""
        # Собираем все уникальные узлы
        all_nodes = set(self.dependency_graph.keys())
        for deps in self.dependency_graph.values():
            all_nodes.update(deps)

        graph_data = {
            "nodes": [{"id": node} for node in all_nodes],
            "links": [
                {"source": src, "target": dst}
                for src, deps in self.dependency_graph.items()
                for dst in deps
            ],
            "cycles": [list(cycle) for cycle in self.cyclic_dependencies],
            "metadata": {
                "file_types": dict(self.file_types),
                "binary_files_count": len(self.binary_files)
            }
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(graph_data, f, indent=2)

    def clean_up(self) -> None:
        """Удаляет временную папку."""
        subprocess.run(["rm", "-rf", self.local_path], shell=True)

if __name__ == "__main__":
    repo_url = input("Введите URL репозитория: ").strip()
    analyzer = UniversalRepoAnalyzer(repo_url)
    
    print("🔄 Клонирую репозиторий...")
    analyzer.clone_repo()
    
    print("🔍 Анализирую файлы...")
    analyzer.scan_files()
    
    print("🔄 Ищу циклы зависимостей...")
    analyzer.detect_cycles()
    
    print("📤 Экспортирую результаты...")
    analyzer.export_to_dot()
    analyzer.export_to_json()
    
    analyzer.clean_up()
    print("✅ Готово!")
    print(f"- Граф зависимостей (DOT): dependencies.dot")
    print(f"- Граф зависимостей (JSON): dependencies.json")
    if analyzer.cyclic_dependencies:
        print("⚠ Найдены цикличные зависимости:")
        for cycle in analyzer.cyclic_dependencies:
            print(" → ".join(cycle))