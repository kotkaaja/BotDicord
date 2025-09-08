import discord
from discord import app_commands
import os
import json
import re
import zipfile
import shutil

# --- Variabel & Konfigurasi ---
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    print("FATAL ERROR: BOT_TOKEN environment variable not found.")
    exit()

TEMP_DIR = "temp_scan"
ALLOWED_EXTENSIONS = ['.lua', '.luac', '.txt', '.zip', '.js', '.html', '.htm']

# --- DAFTAR POLA YANG DISEMPURNAKAN DENGAN REGEX ---
PATTERNS_BY_LEVEL = {
    1: {  # Level 1: BERBAHAYA (Merah 🔴) - Indikasi Pasti Berbahaya
        # Pola Regex untuk URL webhook Discord yang lebih spesifik
        r"discord\.com/api/webhooks/\d+/[A-Za-z0-9\-_]+": "URL Webhook Discord terdeteksi, indikasi kuat pencurian data.",
        r"\bos\.execute\b": "Menjalankan perintah command-line di komputer pengguna (sangat berbahaya).",
        # Pola Regex untuk loadstring, termasuk yang disamarkan dengan pcall
        r"\b(pcall|xpcall)\s*\(\s*loadstring": "Mengeksekusi kode dinamis yang disembunyikan, sangat berbahaya.",
        r"\bloadstring\b": "Mengeksekusi kode dari teks (metode umum untuk malware).",
        r"base64\.decode": "Sering digunakan untuk menyembunyikan string berbahaya (URL webhook, kode).",
        r"\bio\.popen\b": "Membuka program lain dan membaca outputnya.",
        r"LuaObfuscator\.com": "Mengindikasikan kode yang sengaja disamarkan agar sulit dibaca.",
        r"sendToDiscordEmbed": "Nama fungsi kustom yang jelas bertujuan mengirim data ke Discord."
    },
    2: {  # Level 2: MENCURIGAKAN (Kuning 🟡) - Perlu Kewaspadaan
        r"\bhttp\.request\b": "Membuat permintaan jaringan, bisa untuk mengirim data.",
        r"\bfetch\s*\(|XMLHttpRequest": "Membuat permintaan jaringan (umum di JavaScript), bisa untuk mengirim data.",
        r"\bsocket\.http\b": "Modul untuk membuat permintaan jaringan.",
        r"require\s*\(('|\")lfs('|\")\)": "Memuat modul File System (lfs), berpotensi memanipulasi file di luar folder game.",
        r"require\s*\(('|\")socket('|\")\)": "Memuat modul Socket untuk komunikasi jaringan tingkat rendah.",
        r"\bdofile\b": "Menjalankan file skrip eksternal.",
        r"\bio\.open\b": "Membuka file di komputer (bisa untuk membaca/menulis file sensitif).",
        r"\bos\.remove\b": "Menghapus file dari komputer pengguna.",
        r"\bos\.rename\b": "Mengubah nama file di komputer pengguna.",
        r"\bsampGetPlayerNickname\b": "Mengambil nama panggilan pemain.",
        r"\bsampGetCurrentServerAddress\b": "Mengambil alamat server yang sedang dimainkan.",
    }
}

# --- Fungsi Helper ---
def load_config():
    if not os.path.exists('config.json'):
        default_config = {"allowed_channels_for_scan": []}
        with open('config.json', 'w') as f: json.dump(default_config, f, indent=4)
        return default_config
    with open('config.json', 'r') as f: return json.load(f)

def save_config(data):
    with open('config.json', 'w') as f: json.dump(data, f, indent=4)

def scan_file_content(file_path):
    """Fungsi pindai yang disempurnakan, memprioritaskan ancaman per baris."""
    all_detections = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        for line_num, line in enumerate(lines, 1):
            if not line.strip(): continue
            
            highest_threat_on_line = None
            for level in sorted(PATTERNS_BY_LEVEL.keys()):
                for pattern, description in PATTERNS_BY_LEVEL[level].items():
                    if re.search(pattern, line, re.IGNORECASE):
                        highest_threat_on_line = {
                            "level": level, "pattern": pattern, "description": description,
                            "line_num": line_num, "line_content": line.strip()
                        }
            if highest_threat_on_line:
                all_detections.append(highest_threat_on_line)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return all_detections

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
    if not os.path.exists(TEMP_DIR): os.makedirs(TEMP_DIR)

@client.event
async def on_message(message):
    if message.author == client.user or not message.attachments: return
    
    config = load_config()
    scan_channels = config.get("allowed_channels_for_scan", [])
    if message.channel.id not in scan_channels: return

    attachment = message.attachments[0]
    file_extension = os.path.splitext(attachment.filename)[1].lower()

    if file_extension == '.luac':
        embed = discord.Embed(title="ℹ️ File Dilewati (Tidak Dipindai)", description=f"File `{attachment.filename}` adalah file Lua terkompilasi (`.luac`). Kontennya tidak dapat dianalisis.", color=discord.Color.blue())
        await message.reply(embed=embed)
        return

    if file_extension not in ALLOWED_EXTENSIONS: return

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

    if not all_detections_in_archive:
        embed = discord.Embed(title="✅ Analisis Selesai: Aman", description=f"File `{attachment.filename}` tidak mengandung pola berbahaya yang terdaftar.", color=discord.Color.green())
    else:
        if overall_highest_level == 2:
            embed = discord.Embed(title="🟡 Analisis Selesai: Mencurigakan", description=f"File `{attachment.filename}` mengandung skrip yang **patut diwaspadai**. Gunakan dengan hati-hati.", color=discord.Color.gold())
        elif overall_highest_level == 1:
            embed = discord.Embed(title="🚨 Analisis Selesai: SANGAT BERBAHAYA!", description=f"Sangat disarankan untuk **TIDAK MENGGUNAKAN** file `{attachment.filename}` ini.", color=discord.Color.red())
        
        display_limit = 5
        for i, (filename, detection) in enumerate(all_detections_in_archive):
            if i >= display_limit:
                embed.add_field(name="...", value=f"Dan {len(all_detections_in_archive) - display_limit} temuan lainnya...", inline=False)
                break
            
            field_name = f"File: `{filename}` | Baris: {detection['line_num']}"
            field_value = f"**Ancaman:** {detection['description']}\n"
            field_value += f"```lua\n{detection['line_content']}\n```"
            embed.add_field(name=field_name, value=field_value, inline=False)

    await message.reply(embed=embed)

# --- Slash Commands (Hanya Setup) ---
@app_commands.default_permissions(administrator=True)
class Setup(app_commands.Group):
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
            if channel.id not in scan_channels: scan_channels.append(channel.id)
            await interaction.response.send_message(f"✅ Channel {channel.mention} sekarang akan dipindai.", ephemeral=True)
        elif action == 'hapus':
            if channel.id in scan_channels: scan_channels.remove(channel.id)
            await interaction.response.send_message(f"❌ Channel {channel.mention} telah dihapus dari daftar pindai.", ephemeral=True)
        config["allowed_channels_for_scan"] = scan_channels
        save_config(config)

client.tree.add_command(Setup(client))

# Jalankan bot
client.run(BOT_TOKEN)
