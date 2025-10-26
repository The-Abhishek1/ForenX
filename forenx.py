#!/usr/bin/env python3
#forenx.py

import argparse
import os
import sys
from datetime import datetime

# Import modules
from modules import log_analyzer
from modules import memory_analyzer
from modules import file_extractor
from modules import network_traffic_analyzer

BANNER = r"""

    █████                █████     █████  ███            █████   
  ███░░░███             ░░███     ░░███  ░░░            ░░███    
 ███   ░░███ █████ █████ ░███   ███████  ████   ██████  ███████  
░███    ░███░░███ ░░███  ░███  ███░░███ ░░███  ███░░███░░░███░   
░███    ░███ ░░░█████░   ░███ ░███ ░███  ░███ ░███ ░███  ░███    
░░███   ███   ███░░░███  ░███ ░███ ░███  ░███ ░███ ░███  ░███ ███
 ░░░█████░   █████ █████ █████░░████████ █████░░██████   ░░█████ 
   ░░░░░░   ░░░░░ ░░░░░ ░░░░░  ░░░░░░░░ ░░░░░  ░░░░░░     ░░░░░  
                                                                 
	Linux Log & Memory Analyzer v1.0
"""

# ===========Main Function===========

def main():
	print(BANNER)

	parser = argparse.ArgumentParser(
		description="Forenx - Linux Log & Memory Analyzer"
	)
	
	parser.add_argument(
		"--action", "-a",
		required=True,
		choices=["analyze","extract","recover","report"],
		help="Action to perform: analyze | extract | recover | report"
	)

	parser.add_argument(
		"--input", "-i",
		required=True,
		help="Input file path (e.g, /var/log/auth.log or memory dump)"
	)

	parser.add_argument(
		"--output", "-o",
		default=f"report/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
	)

	args = parser.parse_args()

	# Ensure output folder exists
	os.makedirs(os.path.dirname(args.output), exist_ok=True)

	#Action handler
	if args.action == "analyze":
		print(f"[+] Starting analysis on {args.input}")
		lower = args.input.lower()

		if lower.endswith((".log", ".txt")) or "auth" in lower:
			# use log_analyzer
			results = log_analyzer.analyze(args.input)

		elif lower.endswith((".mem", ".dump", ".bin")):
			# use memory_analyzer
			results = memory_analyzer.analyze(args.input)

		elif lower.endswith((".pcap", ".pcapng")):
			# use network_traffic_analyzer
			results = network_traffic_analyzer.analyze(args.input)

		else:
			print("[!] Unsupported file type. Please provide a valid log, memory, or pcap file.")
			sys.exit(1)

		# Save results
		with open(args.output, "w") as f:
			for line in results:
				f.write(line + "\n")

		print(f"[*] Analysis complete. Results saved to {args.output}")


	elif args.action == "extract":
		print(f"[+] Starting extraction analysis on {args.input}")
		results = file_extractor.extract_full_metadata(args.input)

		# Save results
		with open(args.output, "w") as f:
			for line in results:
				f.write(line + "\n")
		print(f"[*] Extraction complete. Results saved to {args.output}")

	elif args.action == "recover":
		print(f"[*] Recovery modue not yet implemented.")
		# results = memory_analyzer.recover(args.input)


	elif args.action == "report":
		print(f"[*] Report generation not yet implemented.")
		# results = report_generator.generate(args.input, args.output)

	else:
		print(f"[-] Invalid action. Use --help for options.")
		sys.exit(1)
		
	

# ======= __main__=========
if __name__ == "__main__":
	main()
