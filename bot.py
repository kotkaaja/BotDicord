import discord
from discord import app_commands
import os
import json
import re
import zipfile
import shutil
import google.generativeai as genai

# --- Konfigurasi ---
BOT_TOKEN = os.getenv("BOT_TOKEN")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not BOT_TOKEN or not GEMINI_API_KEY:
    print("FATAL ERROR: BOT_TOKEN atau GEMINI_API_KEY tidak ditemukan.")
    exit()

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-pro')

TEMP_DIR = "temp_scan"
ALLOWED_EXTENSIONS = ['.lua', '.txt', '.js', '.json', '.html', '.css'] 

# --- DAFTAR POLA REGEX (KEMBALI DIGUNAKAN) ---
PATTERNS_BY_LEVEL = {
    1: { # Level 1: BERBAHAYA
        r"discord\.com/api/webhooks/\d+/[A-Za-z0-9\-_]+": "Pencurian Data via Webhook",
        r"\bos\.execute\b": "Eksekusi Perintah Sistem",
        r"\b(pcall|xpcall)\s*\(\s*loadstring": "Eksekusi Kode Tersembunyi",
        r"\bloadstring\b": "Eksekusi Kode dari Teks",
        r"base64\.decode": "Penyamaran Kode via Base64",
    },
    2: { # Level 2: MENCURIGAKAN
        r"\bhttp\.request\b": "Permintaan Jaringan (HTTP)",
        r"require\s*\(('|\")lfs('|\")\)": "Manipulasi File Sistem (LFS)",
        r"\bio\.open\b": "Akses Baca/Tulis File",
        r"\bsampGetPlayerNickname\b": "Pengambilan Nama Panggilan Pemain",
        r"\bsampGetCurrentServerAddress\b": "Pengambilan Alamat Server",
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

def scan_file_with_regex(file_path):
    """Memindai file menggunakan daftar pola regex."""
    detections = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        for line_num, line in enumerate(lines, 1):
            if not line.strip(): continue
            found_threat = None
            for level in sorted(PATTERNS_BY_LEVEL.keys()):
                for pattern, description in PATTERNS_BY_LEVEL[level].items():
                    if re.search(pattern, line, re.IGNORECASE):
                        found_threat = {"level": level, "description": description, "line_num": line_num, "line_content": line.strip()}
                        break
                if found_threat: break
            if found_threat: all_detections.append(found_threat)
    except Exception as e:
        print(f"Error saat regex scan: {e}")
    return all_detections

def get_summary_from_ai(code_content: str):
    """Meminta ringkasan fungsi dari AI."""
    prompt = f"""
    Anda adalah seorang analis kode Lua. Tugas Anda adalah membaca kode berikut dan menjelaskan tujuannya dalam SATU kalimat singkat dan lugas. Fokus pada apa yang ingin dicapai oleh skrip ini.
    Berikan jawaban Anda sebagai string JSON dengan satu kunci: "ringkasan".
    
    Contoh Jawaban: {{"ringkasan": "Skrip ini tampaknya berfungsi untuk mencuri informasi pemain dan mengirimkannya ke server eksternal."}}

    Kode untuk dianalisis:
    ---
    {code_content}
    """
    try:
        response = model.generate_content(prompt)
        json_response_text = response.text.strip().replace("```json", "").replace("```", "")
        return json.loads(json_response_text).get("ringkasan", "AI tidak memberikan ringkasan.")
    except Exception:
        return "Gagal mendapatkan ringkasan dari AI."

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

    if file_extension not in ALLOWED_EXTENSIONS and file_extension != '.zip': return

    await message.add_reaction('🔍')

    files_to_process = []
    download_path = os.path.join(TEMP_DIR, attachment.filename)

    try:
        if file_extension == '.zip':
            await attachment.save(download_path)
            with zipfile.ZipFile(download_path, 'r') as zip_ref:
                all_files_in_zip = [f for f in zip_ref.namelist() if os.path.splitext(f)[1].lower() in ALLOWED_EXTENSIONS and not f.startswith('__MACOSX/')]
                # Batasi 5 file pertama
                for filename in all_files_in_zip[:5]:
                    with zip_ref.open(filename) as file_in_zip:
                        content = file_in_zip.read().decode('utf-8', errors='ignore')
                        files_to_process.append({"name": filename, "content": content})
            os.remove(download_path)
        else:
            content_bytes = await attachment.read()
            files_to_process.append({"name": attachment.filename, "content": content_bytes.decode('utf-8', errors='ignore')})

        if not files_to_process:
            await message.reply("Tidak ada file yang valid untuk dianalisis di dalam arsip ini.")
            await message.remove_reaction('🔍', client.user)
            return

        # Proses setiap file
        is_safe = True
        for file_data in files_to_process:
            detections = scan_file_with_regex(file_data['name']) # Disimpan sementara untuk dipindai
            with open(os.path.join(TEMP_DIR, file_data['name']), 'w', encoding='utf-8') as temp_f:
                temp_f.write(file_data['content'])
            detections = scan_file_with_regex(os.path.join(TEMP_DIR, file_data['name']))
            os.remove(os.path.join(TEMP_DIR, file_data['name']))

            if not detections: continue
            
            is_safe = False
            highest_level = min(d['level'] for d in detections)

            # Panggil AI HANYA jika ada temuan
            await message.remove_reaction('🔍', client.user)
            await message.add_reaction('🧠')
            ai_summary = get_summary_from_ai(file_data['content'])
            
            if highest_level == 2:
                embed = discord.Embed(title="🟡 Analisis Hybrid: Mencurigakan", color=discord.Color.gold())
            elif highest_level == 1:
                embed = discord.Embed(title="🚨 Analisis Hybrid: SANGAT BERBAHAYA!", color=discord.Color.red())

            embed.add_field(name="Ringkasan dari AI", value=f"_{ai_summary}_", inline=False)
            
            for detection in detections:
                field_name = f"Ancaman Level {detection['level']}: {detection['description']}"
                field_value = f"**File:** `{file_data['name']}` (Baris {detection['line_num']})\n"
                field_value += f"```lua\n{detection['line_content']}\n```"
                embed.add_field(name=field_name, value=field_value, inline=False)
            
            await message.reply(embed=embed)
        
        if is_safe:
            embed = discord.Embed(title="✅ Analisis Hybrid: Aman", description=f"Tidak ada pola berbahaya yang terdeteksi di file `{attachment.filename}`.", color=discord.Color.green())
            await message.reply(embed=embed)

    except Exception as e:
        await message.reply(f"Terjadi error saat memproses file: {e}")
    finally:
        await message.clear_reactions()

# ... (Kode /setup tetap sama persis seperti sebelumnya) ...
@app_commands.default_permissions(administrator=True)
class Setup(app_commands.Group):
    pass # Kode lengkap ada di versi sebelumnya

client.tree.add_command(Setup(client))

client.run(BOT_TOKEN)
