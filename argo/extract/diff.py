from argo.extract.archive import PackageFiles
from argo.schema import FileChange


def _by_size(c: FileChange) -> tuple[int, str]:
    return (-c.size, c.path)


def diff_files(new: PackageFiles, old: PackageFiles | None) -> list[FileChange]:
    old_files = old.files if old is not None else {}
    added = [
        FileChange(path=p, status="added", size=len(b))
        for p, b in new.files.items()
        if p not in old_files
    ]
    modified = [
        FileChange(path=p, status="modified", size=len(b))
        for p, b in new.files.items()
        if p in old_files and old_files[p] != b
    ]
    removed = [
        FileChange(path=p, status="removed", size=len(b))
        for p, b in old_files.items()
        if p not in new.files
    ]
    return (
        sorted(added, key=_by_size) + sorted(modified, key=_by_size) + sorted(removed, key=_by_size)
    )
