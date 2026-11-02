"""Authenticate gateway-added metadata; raw log fields cannot assert evidence IDs."""
import hashlib
import hmac
import json
import os
import re


def export_signature(raw,event_id,batch_id):
    key=os.getenv('LAB_EVIDENCE_SIGNING_KEY') or os.getenv('LOG_LAB_API_KEY','')
    if len(key)<24:return None
    message=json.dumps([raw,event_id,batch_id],ensure_ascii=False,separators=(',',':')).encode()
    return hmac.new(key.encode(),message,hashlib.sha256).hexdigest()


def verified_export(record):
    if not isinstance(record,dict) or not isinstance(record.get('lab_raw'),str) or not isinstance(record.get('lab_signature'),str):return False
    if not isinstance(record.get('lab_event_id'),str) or type(record.get('lab_batch_id')) is not int or not re.fullmatch(r'[0-9a-f]{64}',record['lab_signature']):return False
    expected=export_signature(record['lab_raw'],record['lab_event_id'],record['lab_batch_id'])
    return bool(expected and hmac.compare_digest(record['lab_signature'],expected))
