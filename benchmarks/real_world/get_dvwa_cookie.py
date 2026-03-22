#!/usr/bin/env python3
"""
Helper script to get DVWA session cookie.
Run this after manually logging into DVWA in your browser.
"""

import sys

print("""
=== DVWA Authentication Helper ===

To get your DVWA session cookie:

1. Open http://localhost:8081 in your browser
2. Login with: admin / password
3. Open Developer Tools (F12)
4. Go to: Application → Cookies → http://localhost:8081
5. Copy the value of 'PHPSESSID' cookie
6. Paste it below

Alternatively, use this command after logging in:
  document.cookie

Then paste the PHPSESSID value here:
""")

cookie = input("PHPSESSID value: ").strip()

if cookie:
    print(f"\n✓ Cookie received: {cookie[:20]}...")
    print(f"\nTo use this cookie with xssguard, add this flag:")
    print(f'  --cookie "PHPSESSID={cookie}; security=low"')
    
    # Save to file for automation
    with open('benchmarks/real_world/.dvwa_cookie', 'w') as f:
        f.write(f"PHPSESSID={cookie}; security=low")
    
    print(f"\n✓ Cookie saved to: benchmarks/real_world/.dvwa_cookie")
    print(f"\nNow run: python3 benchmarks/real_world/run_dvwa.py")
else:
    print("No cookie provided. Exiting.")
    sys.exit(1)
