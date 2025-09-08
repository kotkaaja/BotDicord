import discord
from discord import app_commands
import os
import json
import re
import zipfile
import shutil
from PIL import Image
import pytesseract

# --- KONFIGURASI PENTING UNTUK OCR ---
# Jika Anda menginstal Tesseract di Windows di lokasi non-standar,
# hapus tanda '#' di bawah dan sesuaikan path-nya.
# pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# --- Variabel & Konfigurasi ---
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    print("FATAL ERROR: BOT_TOKEN environment variable not found.")
    exit()

TEMP_DIR = "temp_scan"
ALLOWED_EXTENSIONS = ['.lua', '.luac', '.txt', '.zip', '.js', '.html', '.htm']

# --- KLASIFIKASI POLA BAHAYA ---
PATTERNS_BY_LEVEL = {
    1: {  # Level 1: BERBAHAYA (Merah 🔴) - Indikasi kuat aktivitas jahat
        "discord.com/api/webhooks": "Mengirim data ke luar melalui Discord webhook (potensi pencurian data).",
        "os.execute": "Menjalankan perintah command-line di komputer pengguna (sangat berbahaya).",
        "loadstring": "Mengeksekusi kode dari teks (metode umum untuk malware).",
        "base64.decode": "Sering digunakan untuk menyembunyikan string berbahaya (URL webhook, kode).",
        "io.popen": "Membuka program lain dan membaca outputnya.",
        "LuaObfuscator.com": "Mengindikasikan kode yang sengaja disamarkan agar sulit dibaca.",
    },
    2: {  # Level 2: MENCURIGAKAN (Kuning 🟡) - Bisa disalahgunakan, perlu diwaspadai
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
    """Memuat konfigurasi dari config.json."""
    if os.path.exists('config.json'):
        with open('config.json', 'r') as f:
            return json.load(f)
    # Membuat file config default jika tidak ada
    default_config = {
        "allowed_channels_for_scan": [],
        "subscriber_role_id": 0
    }
    with open('config.json', 'w') as f:
        json.dump(default_config, f, indent=4)
    return default_config

def save_config(data):
    """Menyimpan konfigurasi ke config.json."""
    with open('config.json', 'w') as f:
        json.dump(data, f, indent=4)

async def process_subscription_image(attachment):
    """Memproses gambar, mengekstrak teks menggunakan OCR."""
    try:
        temp_image_path = os.path.join(TEMP_DIR, attachment.filename)
        await attachment.save(temp_image_path)
        extracted_text = pytesseract.image_to_string(Image.open(temp_image_path))
        os.remove(temp_image_path)
        return extracted_text.lower()
    except Exception as e:
        print(f"Error processing image with OCR: {e}")
        return ""

def scan_file_content(file_path):
    """Membaca file dan mencari pola, mengembalikan level bahaya tertinggi yang ditemukan."""
    highest_level_found = 0
    detected_pattern_info = None
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            # Memeriksa dari level paling berbahaya terlebih dahulu
            for level in sorted(PATTERNS_BY_LEVEL.keys(), reverse=True):
                patterns = PATTERNS_BY_LEVEL[level]
                for pattern, description in patterns.items():
                    if re.search(pattern, content, re.IGNORECASE):
                        # Langsung kembalikan temuan pertama di level tertinggi
                        return level, (pattern, description)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return highest_level_found, detected_pattern_info

# --- Inisialisasi Bot dengan Command Tree ---
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

    # --- Blok Baru untuk Menangani .luac ---
    if file_extension == '.luac':
        try:
            embed = discord.Embed(
                title="ℹ️ File Dilewati (Tidak Dipindai)",
                description=f"File `{attachment.filename}` adalah file Lua yang terkompilasi (`.luac`). Kontennya tidak dapat dianalisis.",
                color=discord.Color.blue()
            )
            await message.reply(embed=embed)
        finally:
            try:
                await message.delete()
            except discord.Forbidden:
                print(f"Gagal menghapus pesan. Periksa izin 'Manage Messages' di channel #{message.channel.name}.")
        return

    if file_extension not in ALLOWED_EXTENSIONS:
        return

    original_message = message
    try:
        download_path = os.path.join(TEMP_DIR, attachment.filename)
        await attachment.save(download_path)
        
        overall_highest_level = 0
        all_detections = []

        if file_extension == '.zip':
            extract_folder = os.path.join(TEMP_DIR, "extracted_zip")
            with zipfile.ZipFile(download_path, 'r') as zip_ref:
                zip_ref.extractall(extract_folder)
            
            for root, _, files in os.walk(extract_folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    level, info = scan_file_content(file_path)
                    if level > 0:
                        relative_path = os.path.relpath(file_path, extract_folder)
                        all_detections.append((level, relative_path, info[0], info[1]))
                        if level > overall_highest_level:
                            overall_highest_level = level
            shutil.rmtree(extract_folder)
        else:
            level, info = scan_file_content(download_path)
            if level > 0:
                overall_highest_level = level
                all_detections.append((level, attachment.filename, info[0], info[1]))
        
        os.remove(download_path)

        if overall_highest_level == 0:
            embed = discord.Embed(title="✅ Analisis Selesai: Aman", description=f"File `{attachment.filename}` tidak mengandung pola berbahaya.", color=discord.Color.green())
        elif overall_highest_level == 2:
            embed = discord.Embed(title="🟡 Analisis Selesai: Mencurigakan", description=f"File `{attachment.filename}` mengandung skrip yang **patut diwaspadai**. Gunakan dengan hati-hati.", color=discord.Color.gold())
            for _, file, pattern, description in all_detections:
                embed.add_field(name=f"🔍 File: `{file}`", value=f"**Pattern:** `{pattern}`\n**Fungsi:** {description}", inline=False)
        elif overall_highest_level == 1:
            embed = discord.Embed(title="🚨 Analisis Selesai: SANGAT BERBAHAYA!", description=f"Sangat disarankan untuk **TIDAK MENGGUNAKAN** file `{attachment.filename}` ini.", color=discord.Color.red())
            for _, file, pattern, description in all_detections:
                embed.add_field(name=f"🔥 File: `{file}`", value=f"**Pattern:** `{pattern}`\n**Potensi Bahaya:** {description}", inline=False)
        
        await original_message.reply(embed=embed)

    finally:
        try:
            await original_message.delete()
        except discord.Forbidden:
            print(f"Gagal menghapus pesan. Periksa izin 'Manage Messages' di channel #{original_message.channel.name}.")
        except Exception as e:
            print(f"Error saat menghapus pesan: {e}")

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
    
    if "dhot design" in extracted_text and ("disubscribe" in extracted_text or "subscribed" in extracted_text):
        subscriber_role = interaction.guild.get_role(role_id)
        if subscriber_role and not any(role.id == role_id for role in interaction.user.roles):
            await interaction.user.add_roles(subscriber_role)
            await interaction.followup.send(f"Terima kasih sudah subscribe! Role **{subscriber_role.name}** telah diberikan. ✅")
        elif not subscriber_role:
            await interaction.followup.send("Verifikasi berhasil, tapi role subscriber tidak ditemukan. Hubungi admin.")
        else:
            await interaction.followup.send("Anda sudah memiliki role subscriber. Terima kasih!")
    else:
        await interaction.followup.send("Verifikasi gagal. Pastikan screenshot menunjukkan channel **Dhot Design** dan status **sudah subscribe**.")

@subscribe.error
async def on_subscribe_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.CommandOnCooldown):
        await interaction.response.send_message(f"Perintah ini sedang dalam cooldown. Coba lagi dalam **{round(error.retry_after)} detik**.", ephemeral=True)

@app_commands.default_permissions(administrator=True)
class Setup(app_commands.Group):
    """Perintah untuk mengatur bot."""
    def __init__(self, client: discord.Client):
        super().__init__(name="setup", description="Perintah untuk mengatur bot.")
        self.client = client

    @app_commands.command(name="scan_channel", description="Tambah/hapus channel untuk pemindaian file.")
    @app_commands.describe(action="Pilih aksi", channel="Pilih channel")
    @app_commands.choices(action=[
        discord.app_commands.Choice(name="Tambah", value="tambah"),
        discord.app_commands.Choice(name="Hapus", value="hapus")
    ])
    async def scan_channel(self, interaction: discord.Interaction, action: str, channel: discord.TextChannel):
        config = load_config()
        scan_channels = config.get("allowed_channels_for_scan", [])
        if action == 'tambah':
            if channel.id not in scan_channels:
                scan_channels.append(channel.id)
                await interaction.response.send_message(f"✅ Channel {channel.mention} sekarang akan dipindai.", ephemeral=True)
            else:
                await interaction.response.send_message(f"ℹ️ Channel {channel.mention} sudah ada di daftar.", ephemeral=True)
        elif action == 'hapus':
            if channel.id in scan_channels:
                scan_channels.remove(channel.id)
                await interaction.response.send_message(f"❌ Channel {channel.mention} telah dihapus dari daftar pindai.", ephemeral=True)
            else:
                await interaction.response.send_message(f"ℹ️ Channel {channel.mention} tidak ada di daftar.", ephemeral=True)
        
        config["allowed_channels_for_scan"] = scan_channels
        save_config(config)

    @app_commands.command(name="sub_role", description="Atur role yang diberikan setelah verifikasi subscribe.")
    @app_commands.describe(role="Pilih role untuk subscriber")
    async def sub_role(self, interaction: discord.Interaction, role: discord.Role):
        config = load_config()
        config["subscriber_role_id"] = role.id
        save_config(config)
        await interaction.response.send_message(f"✅ Role subscriber diatur ke **{role.name}**.", ephemeral=True)

client.tree.add_command(Setup(client))

# Jalankan bot
client.run(BOT_TOKEN)
