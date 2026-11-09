#!/usr/bin/env python3
"""Automated YouTube Uploader for Runtime-Verify Product Video.

Usage:
  python scripts/upload_to_youtube.py [--client-secrets client_secret.json] [--privacy public|unlisted]
"""
import argparse
import os
import sys
from pathlib import Path

SCOPES = ["https://www.googleapis.com/auth/youtube.upload"]
DEFAULT_VIDEO = Path(__file__).resolve().parent.parent / "assets" / "runtime_verify_intro.mp4"
README_FILE = Path(__file__).resolve().parent.parent / "README.md"

TITLE = "Runtime-Verify: Fail-Closed Runtime Security for Autonomous AI Agents"
DESCRIPTION = """Runtime-Verify: Vendor-neutral statistical runtime verification, deterministic policy governance, and behavioral security for single and multi-agent autonomous AI systems.

📦 Install via PyPI:
pip install runtimeverify

⭐ Star us on GitHub:
https://github.com/RadeshKK/Runtime-Verify

Key Highlights:
- Active Pre-Execution Interception of Dangerous Tool Calls
- Mathematical Safety Invariants in Microseconds (403 Blocked)
- Multi-Agent Swarm Delegation with Cryptographic ED25519 Zero-Trust Tickets
- Real-time Prometheus Telemetry and Hash-Chained Audit Logs
"""
TAGS = [
    "ai agents", "autonomous agents", "cybersecurity", "ai security",
    "runtime verification", "python", "llm security", "prompt injection",
    "zero trust", "swarm governance", "prometheus", "devops"
]


def get_authenticated_service(client_secrets_path: Path, token_path: Path):
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build

    creds = None
    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not client_secrets_path.exists():
                print(f"\n❌ Error: '{client_secrets_path}' not found!")
                print("\nTo generate this file:")
                print("1. Open https://console.cloud.google.com/apis/credentials")
                print("2. Create an OAuth 2.0 Client ID (Application type: Desktop App)")
                print(f"3. Download JSON and save it as '{client_secrets_path.resolve()}'")
                sys.exit(1)

            flow = InstalledAppFlow.from_client_secrets_file(str(client_secrets_path), SCOPES)
            auth_url, _ = flow.authorization_url(prompt="consent")
            print(f"\n👉 Please visit this URL to authorize the YouTube upload:\n{auth_url}\n")
            creds = flow.run_local_server(port=0, open_browser=True)

        with open(token_path, "w") as token:
            token.write(creds.to_json())

    return build("youtube", "v3", credentials=creds)


def upload_video(youtube, video_path: Path, privacy_status: str) -> str:
    from googleapiclient.http import MediaFileUpload
    from googleapiclient.errors import HttpError

    print(f"\n🚀 Uploading {video_path.name} to YouTube ({privacy_status})...")
    body = {
        "snippet": {
            "title": TITLE,
            "description": DESCRIPTION,
            "tags": TAGS,
            "categoryId": "28",  # Science & Technology
        },
        "status": {
            "privacyStatus": privacy_status,
            "selfDeclaredMadeForKids": False,
        },
    }

    media = MediaFileUpload(str(video_path), mimetype="video/mp4", resumable=True, chunksize=1024 * 1024)
    request = youtube.videos().insert(part="snippet,status", body=body, media_body=media)

    response = None
    while response is None:
        status, response = request.next_chunk()
        if status:
            print(f"  Uploading: {int(status.progress() * 100)}% complete...")

    video_id = response.get("id")
    url = f"https://youtu.be/{video_id}"
    print(f"\n✅ Upload Successful!")
    print(f"🔗 Video URL: {url}")
    return url


def update_readme(youtube_url: str):
    if not README_FILE.exists():
        return

    content = README_FILE.read_text(encoding="utf-8")
    # Replace link in README
    old_target = 'href="assets/runtime_verify_intro.mp4"'
    new_target = f'href="{youtube_url}"'

    if old_target in content:
        content = content.replace(old_target, new_target)
        README_FILE.write_text(content, encoding="utf-8")
        print(f"📝 Updated {README_FILE.name} with YouTube link: {youtube_url}")


def main():
    parser = argparse.ArgumentParser(description="Upload Runtime-Verify Intro to YouTube")
    parser.add_argument("--client-secrets", default="client_secret.json", help="Path to client_secret.json")
    parser.add_argument("--token", default="youtube_token.json", help="Path to cache authorized token")
    parser.add_argument("--privacy", default="public", choices=["public", "unlisted", "private"])
    parser.add_argument("--video", default=str(DEFAULT_VIDEO), help="Video file path")
    args = parser.parse_args()

    video_path = Path(args.video)
    if not video_path.exists():
        print(f"❌ Video not found at {video_path}")
        sys.exit(1)

    secrets_path = Path(args.client_secrets)
    token_path = Path(args.token)

    youtube = get_authenticated_service(secrets_path, token_path)
    url = upload_video(youtube, video_path, args.privacy)
    update_readme(url)


if __name__ == "__main__":
    main()
