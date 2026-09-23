from __future__ import annotations
from pathlib import Path
import hashlib,json,sqlite3
from src.models import CaptureStatus,Transaction
class Database:
    def __init__(self,path:Path):
        self.path=path; path.parent.mkdir(parents=True,exist_ok=True); self.connection=sqlite3.connect(path); self.connection.row_factory=sqlite3.Row; self.connection.execute("PRAGMA foreign_keys=ON")
        schema=Path(__file__).parents[1]/"sql"/"schema.sql"; self.connection.executescript(schema.read_text(encoding="utf-8"))
    @staticmethod
    def sha256(path:Path)->str:
        digest=hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda:stream.read(1024*1024),b""): digest.update(block)
        return digest.hexdigest()
    def register_capture(self,path:Path,force:bool=False)->tuple[int,bool]:
        digest=self.sha256(path); row=self.connection.execute("SELECT id,status FROM capture_file WHERE sha256=?",(digest,)).fetchone()
        if row and not force:return int(row["id"]),False
        if row:
            self.connection.execute("UPDATE capture_file SET path=?,status=?,error=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?",(str(path),CaptureStatus.DISCOVERED,int(row["id"]))); self.connection.commit(); return int(row["id"]),True
        cur=self.connection.execute("INSERT INTO capture_file(path,sha256,status) VALUES(?,?,?)",(str(path),digest,CaptureStatus.DISCOVERED)); self.connection.commit(); return int(cur.lastrowid),True
    def set_capture_status(self,id_:int,status:CaptureStatus,error:str|None=None,stats:dict|None=None)->None:
        self.connection.execute("UPDATE capture_file SET status=?,error=?,protocol_stats=COALESCE(?,protocol_stats),updated_at=CURRENT_TIMESTAMP WHERE id=?",(status,error,json.dumps(stats) if stats else None,id_)); self.connection.commit()
    def save_transaction(self,capture_id:int,tx:Transaction)->None:
        self.connection.execute("INSERT OR IGNORE INTO transaction(id,capture_file_id,payload) VALUES(?,?,?)",(tx.id,capture_id,tx.model_dump_json())); self.connection.commit()
    def statuses(self)->list[dict]: return [dict(x) for x in self.connection.execute("SELECT status,COUNT(*) count FROM capture_file GROUP BY status")]
    def recover_interrupted(self)->int:
        cur=self.connection.execute("UPDATE capture_file SET status='STABLE',error='recovered after interrupted run' WHERE status IN ('PROBING','PARSING','ANALYZING')"); self.connection.commit(); return cur.rowcount
