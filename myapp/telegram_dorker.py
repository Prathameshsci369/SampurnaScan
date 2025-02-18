import os
import argparse
from telethon.sync import TelegramClient
import csv

# Telegram API Credentials
api_id = "YOUR_API_ID"
api_hash = "YOUR_API_HASH"
phone_number = "YOUR_PHONE_NUMBER"

# Initialize argument parser
parser = argparse.ArgumentParser(description="Telegram OSINT Scraper")
parser.add_argument("--chats", action="store_true", help="Extract chat history")
parser.add_argument("--media", action="store_true", help="Download documents & media")
args = parser.parse_args()

# Create a Telegram client
client = TelegramClient("session_name", api_id, api_hash)

async def main():
    await client.start(phone_number)
    
    # ✅ Fetch all joined groups
    print("\n🔍 Extracting Telegram Groups...")
    dialogs = await client.get_dialogs()
    groups = [chat for chat in dialogs if chat.is_group]

    for group in groups:
        group_name = group.title.replace(" ", "_")
        group_id = group.id

        # ✅ Create a folder for each group
        folder = f"telegram_data/{group_name}"
        os.makedirs(folder, exist_ok=True)

        # ✅ Extract group invite links
        print(f"📌 Extracting links from: {group.title}")
        try:
            link = await client.export_invite_link(group)
        except:
            link = "Private Group (No Link Available)"

        # ✅ Save links
        with open(f"{folder}/group_links.txt", "w", encoding="utf-8") as f:
            f.write(f"Group Name: {group.title}\nGroup ID: {group_id}\nInvite Link: {link}\n")

        # ✅ Extract chat history (Optional)
        if args.chats:
            print(f"💬 Extracting messages from: {group.title}")
            messages = await client.get_messages(group, limit=500)

            with open(f"{folder}/chat_history.txt", "w", encoding="utf-8") as f:
                for msg in messages:
                    f.write(f"[{msg.date}] {msg.sender_id}: {msg.text}\n")

        # ✅ Extract Media & Documents (Optional)
        if args.media:
            print(f"📂 Downloading media from: {group.title}")
            messages = await client.get_messages(group, limit=100)

            for msg in messages:
                if msg.media:
                    file_path = await msg.download_media(file=f"{folder}/")
                    print(f"📥 Downloaded: {file_path}")

    print("\n✅ Data extraction complete!")

with client:
    client.loop.run_until_complete(main())
