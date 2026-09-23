from src.config import load_config
from src.database import Database
config=load_config(); paths=config.create_directories(); Database(paths["state"] / "agent.db")
print("ok")
