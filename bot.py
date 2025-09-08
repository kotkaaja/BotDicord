import discord
from discord import app_commands
import os
import json
import re
import zipfile
import shutil
from PIL import Image
import pytesseract

# --- Variabel & Konfigurasi ---
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    print("FATAL ERROR: BOT_TOKEN environment variable not found.")
    exit()

TEMP_DIR = "temp_scan"
ALLOWED_EXTENSIONS = ['.lua', '.luac', '.txt', '.zip', '.js', '.html', '.htm']

PATTERNS_BY_LEVEL = {
    1: {  # Level 1: BERBAHAYA (Merah 🔴)
        "discord.com/api/webhooks": "Mengirim data ke luar melalui Discord webhook (potensi pencurian data).",
        "os.execute": "Menjalankan perintah command-line di komputer pengguna (sangat berbahaya).",
        "loadstring": "Mengeksekusi kode dari teks (metode umum untuk malware).",
        "base64.decode": "Sering digunakan untuk menyembunyikan string berbahaya (URL webhook, kode).",
        "io.popen": "Membuka program lain dan membaca outputnya.",
        "LuaObfuscator.com": "Mengindikasikan kode yang sengaja disamarkan agar sulit dibaca.",
    },
    2: {  # Level 2: MENCURIGAKAN (Kuning 🟡)
        "http.request": "Membuat permintaan jaringan, bisa untuk mengirim data.",
        "fetch(": "Membuat permintaan jaringan (umum di JavaScript).",
        "socket.http": "Modul untuk membuat permintaan jaringan.",
        "http://": "Mendeteksi URL non-HTTPS, bisa untuk mengirim data.",
        "pastebin.com": "Sering digunakan untuk hosting dan pengambilan data curian.",
        "dofile": "Menjalankan file skrip eksternal.",
        "loadfile": "Memuat file skrip eksternal untuk dieksekusi.",
        "io.open": "Membuka file di komputer (bisa untuk membaca/menulis file sensitif).",
        "os.remove": "Menghapus file dari komputer pengguna.",
        "os.rename": "Mengubah nama file di komputer pengguna.",
        "sampGetPlayerNickname": "Mengambil nama panggilan pemain.",
        "sampGetCurrentServerAddress": "Mengambil alamat server yang sedang dimainkan.",
    }
}

# --- Fungsi Helper ---
def load_config():
    if not os.path.exists('config.json'):
        default_config = {"allowed_channels_for_scan": [], "subscriber_role_id": 0}
        with open('config.json', 'w') as f:
            json.dump(default_config, f, indent=4)
        return default_config
    with open('config.json', 'r') as f:
        return json.load(f)

def save_config(data):
    with open('config.json', 'w') as f:
        json.dump(data, f, indent=4)

async def process_subscription_image(attachment):
    try:
        temp_image_path = os.path.join(TEMP_DIR, attachment.filename)
        await attachment.save(temp_image_path)
        extracted_text = pytesseract.image_to_string(Image.open(temp_image_path))
        os.remove(temp_image_path)
        return extracted_text.lower()
    except Exception as e:
        print(f"Error processing image with OCR: {e}")
        return ""

# --- PERUBAHAN 3: Logika scan diubah untuk menangkap baris kode ---
def scan_file_content(file_path):
    """Membaca file baris per baris dan mengembalikan SEMUA temuan, termasuk baris kode."""
    detections = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                for level, patterns in PATTERNS_BY_LEVEL.items():
                    for pattern, description in patterns.items():
                        if re.search(pattern, line, re.IGNORECASE):
                            detections.append({
                                "level": level,
                                "pattern": pattern,
                                "description": description,
                                "line_num": line_num,
                                "line_content": line.strip()
                            })
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return detections

# --- Inisialisasi Bot ---
class MyClient(discord.Client):
    def __init__(self, *, intents: discord.Intents):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)
    async def setup_hook(self):
        await self.tree.sync()

intents = discord.Intents.all()
client = MyClient(intents=intents)

# --- Event on_ready & on_message ---
@client.event
async def on_ready():
    print(f'Bot telah masuk sebagai {client.user}')
    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR)

@client.event
async def on_message(message):
    if message.author == client.user or not message.attachments:
        return
    
    config = load_config()
    scan_channels = config.get("allowed_channels_for_scan", [])
    if message.channel.id not in scan_channels:
        return

    attachment = message.attachments[0]
    file_extension = os.path.splitext(attachment.filename)[1].lower()

    if file_extension == '.luac':
        embed = discord.Embed(title="ℹ️ File Dilewati (Tidak Dipindai)", description=f"File `{attachment.filename}` adalah file Lua terkompilasi (`.luac`). Kontennya tidak dapat dianalisis.", color=discord.Color.blue())
        await message.reply(embed=embed)
        # PERUBAHAN 2: Fitur hapus file dinonaktifkan
        return

    if file_extension not in ALLOWED_EXTENSIONS:
        return

    download_path = os.path.join(TEMP_DIR, attachment.filename)
    await attachment.save(download_path)
    
    all_detections_in_archive = []
    overall_highest_level = 0

    if file_extension == '.zip':
        extract_folder = os.path.join(TEMP_DIR, "extracted_zip")
        with zipfile.ZipFile(download_path, 'r') as zip_ref:
            zip_ref.extractall(extract_folder)
        
        for root, _, files in os.walk(extract_folder):
            for file in files:
                file_path = os.path.join(root, file)
                detections = scan_file_content(file_path)
                if detections:
                    relative_path = os.path.relpath(file_path, extract_folder)
                    for detection in detections:
                        all_detections_in_archive.append((relative_path, detection))
                        if detection['level'] > overall_highest_level:
                            overall_highest_level = detection['level']
        shutil.rmtree(extract_folder)
    else:
        detections = scan_file_content(download_path)
        if detections:
            for detection in detections:
                all_detections_in_archive.append((attachment.filename, detection))
                if detection['level'] > overall_highest_level:
                    overall_highest_level = detection['level']
    
    os.remove(download_path)

    # PERUBAHAN 3: Logika pembuatan embed diubah untuk menampilkan baris kode
    if overall_highest_level == 0:
        embed = discord.Embed(title="✅ Analisis Selesai: Aman", description=f"File `{attachment.filename}` tidak mengandung pola berbahaya.", color=discord.Color.green())
    else:
        if overall_highest_level == 2:
            embed = discord.Embed(title="🟡 Analisis Selesai: Mencurigakan", description=f"File `{attachment.filename}` mengandung skrip yang **patut diwaspadai**. Gunakan dengan hati-hati.", color=discord.Color.gold())
        elif overall_highest_level == 1:
            embed = discord.Embed(title="🚨 Analisis Selesai: SANGAT BERBAHAYA!", description=f"Sangat disarankan untuk **TIDAK MENGGUNAKAN** file `{attachment.filename}` ini.", color=discord.Color.red())
        
        # Batasi jumlah field agar tidak terlalu panjang
        display_limit = 5 
        for i, (filename, detection) in enumerate(all_detections_in_archive):
            if i >= display_limit:
                embed.add_field(name="...", value=f"Dan {len(all_detections_in_archive) - display_limit} temuan lainnya...", inline=False)
                break
            
            field_name = f"File: `{filename}` | Baris: {detection['line_num']}"
            field_value = f"**Pattern Terdeteksi:** `{detection['pattern']}`\n"
            field_value += f"```lua\n{detection['line_content']}\n```"
            embed.add_field(name=field_name, value=field_value, inline=False)

    await message.reply(embed=embed)
    # PERUBAHAN 2: Fitur hapus file dinonaktifkan. Tidak ada lagi message.delete()

# --- Slash Commands ---
@client.tree.command(name="subscribe", description="Verifikasi subscription YouTube dengan screenshot.")
@app_commands.describe(screenshot="Upload screenshot yang menunjukkan Anda sudah subscribe.")
@app_commands.checks.cooldown(1, 300, key=lambda i: i.user.id)
async def subscribe(interaction: discord.Interaction, screenshot: discord.Attachment):
    config = load_config()
    role_id = config.get("subscriber_role_id", 0)
    
    if role_id == 0:
        await interaction.response.send_message("Fitur subscribe belum diatur oleh admin.", ephemeral=True)
        return
    if not screenshot.content_type or not screenshot.content_type.startswith('image'):
        await interaction.response.send_message("File yang diunggah bukan gambar. Coba lagi.", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)
    
    extracted_text = await process_subscription_image(screenshot)
    
    # --- PERUBAHAN 1: Target channel diubah ke 'kotkaaja' ---
    if "kotkaaja" in extracted_text and ("disubscribe" in extracted_text or "subscribed" in extracted_text):
        subscriber_role = interaction.guild.get_role(role_id)
        if subscriber_role and not any(role.id == role_id for role in interaction.user.roles):
            await interaction.user.add_roles(subscriber_role)
            await interaction.followup.send(f"Terima kasih sudah subscribe! Role **{subscriber_role.name}** telah diberikan. ✅")
        elif not subscriber_role:
            await interaction.followup.send("Verifikasi berhasil, tapi role subscriber tidak ditemukan. Hubungi admin.")
        else:
            await interaction.followup.send("Anda sudah memiliki role subscriber. Terima kasih!")
    else:
        await interaction.followup.send("Verifikasi gagal. Pastikan screenshot menunjukkan channel **Kotkaaja** dan status **sudah subscribe**.")

@subscribe.error
async def on_subscribe_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.CommandOnCooldown):
        await interaction.response.send_message(f"Perintah ini sedang dalam cooldown. Coba lagi dalam **{round(error.retry_after)} detik**.", ephemeral=True)

# ... (Kode untuk /setup tetap sama, tidak ada perubahan)
@app_commands.default_permissions(administrator=True)
class Setup(app_commands.Group):
    def __init__(self, client: discord.Client):
        super().__init__(name="setup", description="Perintah untuk mengatur bot.")
        self.client = client

    @app_commands.command(name="scan_channel", description="Tambah/hapus channel untuk pemindaian file.")
    #... (kode lengkap setup scan_channel)

    @app_commands.command(name="sub_role", description="Atur role yang diberikan setelah verifikasi subscribe.")
    #... (kode lengkap setup sub_role)
    pass # Placeholder untuk meringkas, kode aslinya lengkap dari sebelumnya

# Menambahkan grup command ke tree
client.tree.add_command(Setup(client))

# Jalankan bot
client.run(BOT_TOKEN)
