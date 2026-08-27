"""Entry point — run from project root: python run.py

Auto-tunnel: if NGROK_STATIC_DOMAIN is set in .env, this script opens an
ngrok tunnel on that fixed domain every time it starts and sets APP_URL
accordingly — so email verification links always point to a reachable
address without any manual steps. One-time setup needed:

  1. pip install -r requirements.txt   (installs pyngrok)
  2. ngrok config add-authtoken <YOUR_AUTHTOKEN>   (once, from ngrok.com dashboard)
  3. Reserve a free static domain at https://dashboard.ngrok.com/domains
  4. Add to .env:
       NGROK_STATIC_DOMAIN=your-name.ngrok-free.app

After that, just run: python run.py — every single time.
"""

import os
from dotenv import load_dotenv

load_dotenv()

PORT = int(os.getenv("PORT", 5000))
NGROK_DOMAIN = os.getenv("NGROK_STATIC_DOMAIN")

if NGROK_DOMAIN:
    from pyngrok import ngrok

    # Close any leftover tunnels from a previous crashed run, then open a
    # fresh one bound to the same static domain — the public URL never changes.
    ngrok.kill()
    tunnel = ngrok.connect(PORT, domain=NGROK_DOMAIN)
    public_url = tunnel.public_url
    os.environ["APP_URL"] = public_url
    print(f"\n=======================\n Public URL (fixed):  {public_url} \n=======================\n")

from app.main import create_app

app = create_app()

if __name__ == "__main__":
    try:
        app.run(debug=True, host="0.0.0.0", port=PORT, use_reloader=False)
    finally:
        if NGROK_DOMAIN:
            from pyngrok import ngrok
            ngrok.kill()