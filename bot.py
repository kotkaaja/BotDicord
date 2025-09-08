import discord
from discord import app_commands
import mysql.connector
import os
import uuid
from datetime import datetime, timedelta

# --- KONFIGURASI ---
DISCORD_BOT_TOKEN = os.environ.get('DISCORD_BOT_TOKEN')
DB_HOST = os.environ.get('MYSQLHOST')
DB_USER = os.environ.get('MYSQLUSER')
DB_PASS = os.environ.get('MYSQLPASSWORD')
DB_NAME = os.environ.get('MYSQLDATABASE')
DB_PORT = os.environ.get('MYSQLPORT')

# --- KONEKSI BOT DISCORD ---
intents = discord.Intents.default()
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)

# --- FUNGSI UTAMA BOT ---
@tree.command(name="buat_token", description="Membuat token aktivasi baru.")
@app_commands.describe(durasi_hari="Durasi aktif token dalam jumlah hari (contoh: 30).")
async def buat_token(interaction: discord.Interaction, durasi_hari: int):
    # Hanya admin yang bisa menjalankan perintah ini
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("Hanya admin yang bisa menggunakan perintah ini.", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True) 

    try:
        # Generate token unik
        new_token = f"KOTKA-{str(uuid.uuid4()).split('-')[0].upper()}"

        # Hitung tanggal kedaluwarsa
        kedaluwarsa = datetime.now() + timedelta(days=durasi_hari)
        expiry_date_str = kedaluwarsa.strftime('%Y-%m-%d %H:%M:%S')

        # Hubungkan ke database
        db_connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME,
            port=DB_PORT
        )
        cursor = db_connection.cursor()

        # Masukkan token baru ke database
        query = "INSERT INTO tokens (token_value, expiry_date) VALUES (%s, %s)"
        values = (new_token, expiry_date_str)
        cursor.execute(query, values)
        db_connection.commit()

        cursor.close()
        db_connection.close()
        
        # Kirim pesan konfirmasi
        await interaction.followup.send(f"✅ Token berhasil dibuat!\n\n**Token:** `{new_token}`\n**Berlaku hingga:** {expiry_date_str}")

    except Exception as e:
        print(f"Error: {e}")
        await interaction.followup.send(f"❌ Terjadi kesalahan saat membuat token.")


@client.event
async def on_ready():
    await tree.sync()
    print(f'Bot {client.user} sudah online dan siap!')

# Jalankan bot
client.run(DISCORD_BOT_TOKEN)