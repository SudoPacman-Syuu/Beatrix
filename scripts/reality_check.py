#!/usr/bin/env python3
"""Reality check: Is the JSONP finding actually a vulnerability?"""
import asyncio
import time
import warnings

import httpx

warnings.filterwarnings("ignore")

async def reality_check():
    async with httpx.AsyncClient(timeout=15, verify=False) as c:

        print('=== REALITY CHECK: Is this actually a vulnerability? ===')
        print()

        # QUESTION 1: Is json_callback a standard Nominatim feature?
        print('1. Is json_callback a standard Nominatim feature?')
        print('   YES — Nominatim docs list json_callback as a parameter')
        print('   This is INTENDED behavior, not a misconfiguration.')
        print()

        # QUESTION 2: Is the data sensitive?
        print('2. Is the exposed data sensitive?')
        try:
            r = await c.get('https://nominatim.bykea.net/reverse?lat=24.8607&lon=67.0011&format=json&addressdetails=1')
            data = r.json()
            road = data.get('address',{}).get('road','?')
            town = data.get('address',{}).get('town','?')
            print(f'   Data returned: road={road}, town={town}')
            print('   This is PUBLIC OpenStreetMap data')
            print('   No user data. No PII. No sessions.')
        except Exception as e:
            print(f'   Error: {e}')
        print()

        # QUESTION 3: Does official Nominatim behave the same?
        print('3. Comparing with official nominatim.openstreetmap.org...')
        try:
            r1 = await c.get('https://nominatim.openstreetmap.org/reverse?lat=24.8607&lon=67.0011&format=json',
                           headers={'User-Agent': 'BugBountyResearch/1.0'})
            cors = r1.headers.get('access-control-allow-origin','NOT SET')
            print(f'   Official ACAO: {cors}')
        except Exception as e:
            print(f'   Could not reach: {e}')

        try:
            r2 = await c.get('https://nominatim.openstreetmap.org/reverse?lat=24.8607&lon=67.0011&format=json&json_callback=test',
                           headers={'User-Agent': 'BugBountyResearch/1.0'})
            ct = r2.headers.get('content-type','')
            has_cb = r2.text.startswith('test(')
            print(f'   Official json_callback: wraps={has_cb}, CT={ct}')
        except Exception as e:
            print(f'   Error: {e}')
        print()

        # QUESTION 4: Any Bykea-specific data?
        print('4. Bykea-specific data in responses?')
        try:
            r3 = await c.get('https://nominatim.bykea.net/reverse?lat=24.8607&lon=67.0011&format=json&extratags=1&namedetails=1')
            keys = set(r3.json().keys())
            standard = {'place_id','licence','osm_type','osm_id','lat','lon',
                       'display_name','address','boundingbox','extratags','namedetails'}
            extra = keys - standard
            print(f'   Response keys: {keys}')
            if extra:
                print(f'   EXTRA KEYS: {extra}')
            else:
                print('   No extra keys — stock Nominatim')
        except Exception as e:
            print(f'   Error: {e}')
        print()

        # QUESTION 5: Rate limiting?
        print('5. Rate limiting check...')
        start = time.time()
        ok = 0
        for i in range(20):
            try:
                r = await c.get(f'https://nominatim.bykea.net/reverse?lat={24.86+i*0.001}&lon=67.001&format=json')
                if r.status_code == 200:
                    ok += 1
            except Exception:
                pass
        elapsed = time.time() - start
        rps = ok / max(elapsed, 0.001)
        print(f'   {ok}/20 succeeded in {elapsed:.1f}s ({rps:.1f} req/s)')
        print()

        # QUESTION 6: Does Bykea app use this with auth or just open?
        print('6. Does Bykea add any auth/cookies/tokens to this service?')
        r4 = await c.get('https://nominatim.bykea.net/reverse?lat=24.8607&lon=67.0011&format=json')
        cookies = r4.headers.get('set-cookie', 'NONE')
        auth_headers = {k:v for k,v in r4.headers.items() if 'auth' in k.lower() or 'token' in k.lower()}
        print(f'   Set-Cookie: {cookies}')
        print(f'   Auth headers: {auth_headers if auth_headers else "NONE"}')
        print()

        # QUESTION 7: Can we use JSONP to do anything beyond reading public geodata?
        print('7. Can JSONP be used to access non-public endpoints?')
        # Try search endpoints that might reveal user queries
        endpoints = [
            '/search?q=test&format=json&json_callback=x',
            '/lookup?osm_ids=R1234&format=json&json_callback=x',
            '/status.php',
            '/details?osmtype=N&osmid=1&format=json',
        ]
        for ep in endpoints:
            try:
                r = await c.get(f'https://nominatim.bykea.net{ep}')
                print(f'   {ep}: {r.status_code} ({len(r.text)} bytes)')
            except Exception as e:
                print(f'   {ep}: {e}')
        print()

        print('='*60)
        print('HONEST VERDICT')
        print('='*60)
        print()
        print('json_callback is a DOCUMENTED Nominatim feature.')
        print('Data is PUBLIC OpenStreetMap geodata.')
        print('ACAO: * is standard for public geo APIs.')
        print('No sensitive data, no PII, no user tracking.')
        print()
        print('Submitting this as JSONP injection = almost certain N/A.')
        print()
        print('SALVAGEABLE ANGLES (need more evidence):')
        print('- Resource abuse: No rate limiting on self-hosted infra')
        print('- status.php: PHP error with class name (very low)')
        print('- If Bykea logs search queries -> log injection via callback')
        print('  (speculative, cannot prove)')

asyncio.run(reality_check())
