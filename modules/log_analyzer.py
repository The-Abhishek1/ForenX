# modules/log_analyzer.py

import re
from datetime import datetime
from collections import Counter

SUCCESS_REGEX = re.compile(
	r"(?P<ts>\w{3}\s+\d+\s[\d:]+).*Accepted password for (?P<user>[\w-]+) from (?P<ip>[\d.]+)"
)
FAILED_REGEX = re.compile(
	r"(?P<ts>\w{3}\s+\d+\s[\d:]+).*Failed password for (?P<user>[\w-]+) from (?P<ip>[\d.]+)"
)


def analyze(path):

	with open(path, 'r', errors='ignore') as f:
		lines =f.readlines()  

	success_logs = []
	failed_logs = []
	
	for line in lines:
		if m := SUCCESS_REGEX.search(line):
			success_logs.append((m.group('user'), m.group('ip'), m.group('ts')))
		elif m:= FAILED_REGEX.search(line):
			failed_logs.append((m.group('user'), m.group('ip'), m.group('ts')))
	

	# Defensive: handle empty cases
	if not success_logs and not failed_logs:
		return ["[!] No login patterns found in the provided log file."]

	# Extract user and IP for stats
	users_failed = [entry[0] for entry in failed_logs]
	ips_failed = [entry[1] for entry in failed_logs]
	
	# Summary data
	total_success = len(success_logs)
	total_failed = len(failed_logs)
	top_users = Counter(users_failed).most_common(3)
	top_ips = Counter(ips_failed).most_common(3)

	# Report
	summary = []
	summary.append("========== ForenX Log Analysix Report =========\n")
	summary.append(f"Total Successful Logins: {total_success}")
	summary.append(f"Total Failed Attempts: {total_failed}")

	# Top 3 user
	summary.append("\nTop 3 Users with Failed Attempts:")
	if top_users:
		for user, count in top_users:
			summary.append(f"  - {user}: {count} times")
	else:
		summary.append("  [No failed attempts detected]")

	# Top 3 Attacker IP
	summary.append("\nTop 3 Attacker IPs:")
	if top_ips:
		for ip, count in top_ips:
			summary.append(f"  - {ip}: {count} times")
	else:
		summary.append("  [No failed attempts detected]")

	# Recent Activtity
	summary.append("\nRecent Login Activity (last 5 entries):")
	recent = (failed_logs + success_logs)[-5:]
	for user, ip, ts in recent:
		summary.append(f"  {ts} - User: {user} - IP: {ip}")
	summary.append("\n")

	return summary
