from __future__ import annotations
import argparse,json
from pathlib import Path
from src.agent import analyze_file,watch
from src.config import load_config
from src.database import Database
from src.output.openapi import generate_openapi,load_interfaces
from src.platform import get_platform_adapter
def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(prog="api-survey"); parser.add_argument("--config",type=Path); sub=parser.add_subparsers(dest="command",required=True)
    analyze=sub.add_parser("analyze"); analyze.add_argument("pcap",type=Path); analyze.add_argument("--force",action="store_true")
    sub.add_parser("watch"); sub.add_parser("status"); sub.add_parser("list-endpoints")
    show=sub.add_parser("show-endpoint"); show.add_argument("method"); show.add_argument("path")
    sub.add_parser("generate-openapi"); sub.add_parser("list-interfaces")
    args=parser.parse_args(argv); config=load_config(args.config); paths=config.create_directories()
    if args.command=="analyze": analyze_file(args.pcap,config,args.force)
    elif args.command=="watch": watch(config)
    elif args.command=="status":
        db=Database(Path(config.database.url) if config.database.url else paths["state"]/"agent.db"); print(json.dumps(db.statuses(),indent=2))
    elif args.command=="list-interfaces": print(json.dumps(get_platform_adapter().list_interfaces(),indent=2))
    elif args.command=="generate-openapi": generate_openapi(load_interfaces(paths["interfaces"]),paths["openapi"])
    else:
        docs=load_interfaces(paths["interfaces"])
        matches=[x for x in docs if args.command=="list-endpoints" or (x["method"]==args.method.upper() and x["path"]==args.path)]
        print(json.dumps(matches,indent=2,ensure_ascii=False))
    return 0
if __name__=="__main__": raise SystemExit(main())
