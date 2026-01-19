#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# PROJECT:      Sentinel-Mail for Wazuh
# VERSION:      1.0.0 (Open Source Edition)
# DESCRIPTION:  High-visibility HTML notifications with Universal Evidence Tracking.
# LICENSE:      MIT License
# =============================================================================

import json
import sys
import time
import smtplib
import os
import html
import fcntl
from email.utils import formataddr
from email.message import EmailMessage

# --- SYSTEM PATHS ---
LOG_FILE = '/var/ossec/logs/integrations.log'
STATE_FILE = '/var/ossec/var/run/sentinel_mail_state.json'
CONFIG_FILE = '/var/ossec/etc/integrations/sentinel_config.json'

def write_debug(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{time.strftime('%c')}: sentinel-mail: {msg}\n")
    except Exception: pass

def load_config():
    if not os.path.exists(CONFIG_FILE):
        write_debug(f"CRITICAL: Config file missing at {CONFIG_FILE}")
        sys.exit(1)
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        write_debug(f"ERROR: JSON failure: {str(e)}")
        sys.exit(1)

PARAMS = load_config()

def flood_control():
    now = time.time()
    try:
        with open(STATE_FILE, 'a+') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.seek(0)
            content = f.read()
            state = json.loads(content) if content else {"start_time": now, "count": 0}
            if now - state["start_time"] > 60:
                state = {"start_time": now, "count": 1}
            else:
                state["count"] += 1
            f.seek(0)
            f.truncate()
            json.dump(state, f)
            return state["count"] <= 10
    except Exception: return True

def build_html_report(alert):
    lvl = int(alert.get('rule', {}).get('level', 0))
    desc = html.escape(alert.get('rule', {}).get('description', 'Security Event'))
    agent = html.escape(alert.get('agent', {}).get('name', 'N/A'))
    a_ip = html.escape(alert.get('agent', {}).get('ip', 'N/A'))
    r_id = html.escape(alert.get('rule', {}).get('id', 'N/A'))
    
    # --- UNIVERSAL EVIDENCE TRACKER ---
    # Captures logs from Linux (full_log) and Windows (eventdata)
    raw_data = alert.get('full_log') or \
               alert.get('data', {}).get('win', {}).get('eventdata', {}).get('message') or \
               alert.get('data', {}).get('win', {}).get('system', {}).get('message') or \
               alert.get('data', {}).get('description') or \
               'No forensic data available.'
    raw = html.escape(str(raw_data))

    # Alert Theme
    if lvl >= 12: color, label = "#d32f2f", "CRITICAL"
    elif 7 <= lvl <= 11: color, label = "#f57c00", "HIGH"
    else: color, label = "#388e3c", "INFO"

    subject = f"[{label}] Lvl {lvl} - {agent}"
    
    body = f"""
    <html>
    <body style="background-color: #f4f7f9; padding: 20px; font-family: sans-serif;">
        <div style="max-width: 600px; margin: auto; background: white; border-radius: 8px; border: 1px solid #ddd; overflow: hidden;">
            <div style="background-color: {color}; padding: 20px; text-align: center; color: white;">
                <h2 style="margin: 0;">{label} ALERT</h2>
                <small>Sentinel-Mail Engine</small>
            </div>
            <div style="padding: 20px;">
                <p><b>Agent:</b> {agent} ({a_ip}) | <b>Rule ID:</b> {r_id}</p>
                <p><b>Description:</b> {desc}</p>
                <div style="margin-top: 20px; padding: 10px; background: #1a1a1a; color: #00ff00; font-family: monospace; font-size: 11px; border-radius: 4px;">
                    {raw}
                </div>
            </div>
            <div style="padding: 10px; text-align: center; font-size: 10px; color: #999; border-top: 1px solid #eee;">
                SIEM Notification Engine | Created by: <b>Emanuel Carreño</b>
            </div>
        </div>
    </body>
    </html>
    """
    return subject, body

def dispatch(subject, body):
    if not flood