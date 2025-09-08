import discord
from discord import app_commands
import os
import json
import zipfile
import shutil
import google.generativeai as genai

# --- Konfigurasi ---
BOT_TOKEN = os.getenv("BOT_TOKEN")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not BOT_TOKEN or not GEMINI_API_KEY:
    print("FATAL ERROR: BOT_TOKEN atau GEMINI_API_KEY tidak ditemukan di Variables.")
    exit()

# Konfigurasi Gemini API
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-pro')

TEMP_DIR = "temp_scan"
# Hanya izinkan file berbasis teks yang bisa dianalisis AI
ALLOWED_EXTENSIONS = ['.lua', '.txt', '.js', '.json', '.html', '.css'] 

# --- Fungsi Helper ---
def load_config():
    if not os.path.exists('config.json'):
        default_config = {"allowed_channels_for_scan": []}
        with open('config.json', 'w') as f: json.dump(default_config, f, indent=4)
        return default_config
    with open('config.json', 'r') as f: return json.load(f)

def save_config(data):
    with open('config.json', 'w') as f: json.dump(data, f, indent=4)

def analyze_code_with_ai(code_content: str):
    """Mengirim kode ke Gemini dengan instruksi untuk analisis kontekstual."""
    
    # Prompt ini adalah "otak" dari AI kita.
    prompt = """
    Anda adalah seorang ahli keamanan siber yang berspesialisasi dalam menganalisis skrip Lua untuk malware.
    
    TUGAS UTAMA ANDA: Pahami tujuan keseluruhan skrip. Banyak fungsi seperti `io.open` atau `http.request` bisa digunakan untuk tujuan baik (misal: menyimpan konfigurasi) atau jahat (mencuri data). JANGAN hanya menandai nama fungsinya. Berikan penilaian berdasarkan KONTEKS penggunaannya dalam skrip. Jika sebuah skrip jelas membutuhkan fungsi tersebut untuk fitur utamanya (misal, script tema butuh `io.open` untuk membaca file tema), pertimbangkan itu sebagai penggunaan yang sah.

    Berikan jawaban HANYA dalam format JSON yang valid, tanpa teks tambahan atau markdown.

    JSON harus memiliki tiga kunci:
    1. "kategori": (string) Klasifikasikan ke dalam salah satu dari empat nilai ini: "Aman", "Mencurigakan", "Sangat Mencurigakan", atau "Sangat Berbahaya".
    2. "ringkasan": (string) Jelaskan tujuan utama skrip ini dalam SATU kalimat yang sangat singkat.
    3. "analisis_kunci": (string) Jelaskan ALASAN utama di balik klasifikasi Anda dalam satu kalimat, fokus pada konteks penggunaan fungsi yang relevan.

    Ini adalah kode yang harus dianalisis:
    ---
    """ + code_content

    try:
        response = model.generate_content(prompt)
        json_response_text = response.text.strip().replace("```json", "").replace("```", "")
        return json.loads(json_response_text)
    except Exception as e:
        print(f"Error saat menghubungi Gemini API: {e}")
        return {
            "kategori": "Error",
            "ringkasan": "Gagal menganalisis kode karena terjadi error pada API.",
            "analisis_kunci": str(e)
        }

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

    if file_extension not in ALLOWED_EXTENSIONS and file_extension != '.zip':
        return

    await message.add_reaction('🧠')
    
    try:
        file_content = ""
        file_to_analyze = ""
        
        if file_extension == '.zip':
            download_path = os.path.join(TEMP_DIR, attachment.filename)
            await attachment.save(download_path)
            
            with zipfile.ZipFile(download_path, 'r') as zip_ref:
                valid_files = [f for f in zip_ref.namelist() if os.path.splitext(f)[1].lower() in ALLOWED_EXTENSIONS and not f.startswith('__MACOSX/')]
                if not valid_files:
                    await message.reply(f"Arsip `{attachment.filename}` tidak mengandung file yang bisa dianalisis.")
                    await message.remove_reaction('🧠', client.user)
                    return
                
                first_file_name = valid_files[0]
                with zip_ref.open(first_file_name) as file_in_zip:
                    file_content_bytes = file_in_zip.read()
                    file_to_analyze = f"{attachment.filename} -> {first_file_name}"
            os.remove(download_path)
        else:
            file_content_bytes = await attachment.read()
            file_to_analyze = attachment.filename

        file_content = file_content_bytes.decode('utf-8', errors='ignore')
        
        if len(file_content) > 20000:
            await message.reply("File terlalu besar untuk dianalisis oleh AI (maks 20.000 karakter).")
            await message.remove_reaction('🧠', client.user)
            return

        analysis_result = analyze_code_with_ai(file_content)

        kategori = analysis_result.get("kategori", "Error")
        ringkasan = analysis_result.get("ringkasan", "Tidak ada ringkasan.")
        analisis_kunci = analysis_result.get("analisis_kunci", "Tidak ada.")

        if kategori == "Aman":
            color, title = discord.Color.green(), "✅ Analisis AI: Aman"
        elif kategori == "Mencurigakan":
            color, title = discord.Color.yellow(), "🤔 Analisis AI: Mencurigakan"
        elif kategori == "Sangat Mencurigakan":
            color, title = discord.Color.orange(), "🟡 Analisis AI: Sangat Mencurigakan"
        elif kategori == "Sangat Berbahaya":
            color, title = discord.Color.red(), "🚨 Analisis AI: Sangat Berbahaya"
        else:
            color, title = discord.Color.greyple(), "⚙️ Analisis AI: Error"

        embed = discord.Embed(title=title, description=f"**File Dianalisis:** `{file_to_analyze}`", color=color)
        embed.add_field(name="Ringkasan Fungsi", value=ringkasan, inline=False)
        embed.add_field(name="Poin Kunci Analisis", value=analisis_kunci, inline=False)
        
        await message.reply(embed=embed)

    except Exception as e:
        await message.reply(f"Terjadi error saat memproses file: {e}")
    finally:
        await message.remove_reaction('🧠', client.user)

# --- Slash Commands (Hanya Setup) ---
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
class Setup(app_commands.Group, name="setup", description="Perintah untuk mengatur bot."):
    
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

client.tree.add_command(Setup())

# Jalankan bot
client.run(BOT_TOKEN)
