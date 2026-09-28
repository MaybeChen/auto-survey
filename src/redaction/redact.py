from __future__ import annotations
from typing import Any
from src.models import Transaction
def redact_value(value:Any,sensitive_fields:list[str],replacement:str="***")->Any:
    names={x.casefold() for x in sensitive_fields}
    if isinstance(value,dict): return {k:(replacement if k.casefold() in names else redact_value(v,sensitive_fields,replacement)) for k,v in value.items()}
    if isinstance(value,list): return [redact_value(v,sensitive_fields,replacement) for v in value]
    return value
def redact_transaction(transaction:Transaction,header_fields:list[str],json_fields:list[str],replacement:str="***")->Transaction:
    result=transaction.model_copy(deep=True); headers={x.casefold() for x in header_fields}
    result.request.headers={k:(replacement if k.casefold() in headers else v) for k,v in result.request.headers.items()}
    result.request.body=redact_value(result.request.body,json_fields,replacement)
    if result.response:
        result.response.headers={k:(replacement if k.casefold() in headers else v) for k,v in result.response.headers.items()}
        result.response.body=redact_value(result.response.body,json_fields,replacement)
    return result
