from rich.console import Console
from rich.table import Table

table = Table(title="Reference")

table.add_column("Language", justify="center", no_wrap=True)
table.add_column("Official", justify="center", no_wrap=True)
table.add_column("Type", justify="center", no_wrap=True)
table.add_column("URL", justify="center", no_wrap=True)

table.add_row("C", "yes", "all", "https://github.com/sphincs/sphincsplus")
table.add_row("Go", "yes", "256", "https://github.com/Yawning/sphincs256")
table.add_row("Assembly", "yes", "256",
              "https://github.com/sphincs/sphincs-256")
table.add_row("C++", "yes", "all + parallel",
              "https://github.com/sphincs/parallel-sphincsplus")
table.add_row("Go", "no", "256", "https://github.com/Yawning/sphincs256")
table.add_row("Python", "no", "256",
              "https://github.com/joostrijneveld/SPHINCS-256-py")
table.add_row("C", "no", "256", "https://github.com/ahf/sphincs")
table.add_row("Assembly", "no", "many", "https://github.com/kste/sphincs")
table.add_row("Rust", "no", "all",
              "https://github.com/Argyle-Software/sphincsplus")
table.add_row("Rust", "no", "all", "https://github.com/AtropineTears/Selenite")
table.add_row("Python", "no", "all",
              "https://github.com/tottifi/sphincs-python")

console = Console()
console.print(table)
