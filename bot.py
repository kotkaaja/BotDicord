import discord
import os
import zipfile
import shutil
import re

# --- Konfigurasi ---
# Mengambil token dari environment variable. Ini cara aman untuk hosting.
# Di Railway, kita mengatur variabel bernama BOT_TOKEN.
BOT_TOKEN = os.getenv("BOT_TOKEN")

if not BOT_TOKEN:
    print("FATAL ERROR: BOT_TOKEN environment variable not found.")
    print("Pastikan Anda sudah mengaturnya di Railway (Variables) atau di sistem lokal Anda.")
    exit()

# Daftar ekstensi file yang diizinkan untuk diunggah
ALLOWED_EXTENSIONS = ['.lua', '.txt', '.zip']

# Folder sementara untuk menyimpan dan mengekstrak file
TEMP_DIR = "temp_scan"

# Daftar pola/kata kunci berbahaya yang akan dicari.
# Dibuat case-insensitive (tidak peduli huruf besar/kecil) untuk deteksi yang lebih baik.
SUSPICIOUS_PATTERNS = {
    # Eksekusi Kode Dinamis & Obfuscator
    "loadstring": "Mengeksekusi kode dari teks, sangat berbahaya.",
    "dofile": "Menjalankan file skrip eksternal.",
    "loadfile": "Memuat file skrip eksternal untuk dieksekusi.",
    "LuaObfuscator.com": "Mengindikasikan kode yang sengaja disamarkan.",
    "base64.decode": "Sering digunakan untuk menyembunyikan string berbahaya (URL webhook, kode).",
    
    # Interaksi dengan Sistem Operasi (Sangat Berbahaya)
    "os.execute": "Menjalankan perintah command-line di komputer pengguna.",
    "os.remove": "Menghapus file dari komputer pengguna.",
    "os.rename": "Mengubah nama file di komputer pengguna.",
    "io.popen": "Membuka program lain dan membaca outputnya.",
    "io.open": "Membuka dan berpotensi membaca file sensitif di komputer.",

    # Komunikasi Jaringan (Mengirim Data Keluar)
    "discord.com/api/webhooks": "Sangat mungkin digunakan untuk mencuri data via Discord webhook.",
    "socket.http": "Modul untuk membuat permintaan HTTP.",
    "http.request": "Fungsi umum untuk membuat permintaan HTTP.",
    "http://": "Mendeteksi URL non-HTTPS, bisa untuk mengirim data.",
    "pastebin.com": "Sering digunakan untuk hosting dan pengambilan data curian.",
    "hastebin.com": "Alternatif pastebin untuk mengirim data.",

    # Pencurian Informasi Spesifik Game (SAMP)
    "sampGetPlayerNickname": "Mengambil nama panggilan pemain.",
    "sampGetCurrentServerAddress": "Mengambil alamat server yang sedang dimainkan.",
    
    # Fungsi Kustom yang Mencurigakan (Nama umum untuk fungsi jahat)
    "sendToDiscordEmbed": "Nama fungsi yang jelas bertujuan mengirim data ke Discord.",
    "sendWebhook": "Nama fungsi umum untuk mengirim data via webhook."
}

# --- Inisialisasi Bot ---
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

# --- Fungsi Pemindai ---
def scan_file_content(file_path):
    """Membaca file dan mencari pola berbahaya (case-insensitive)."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            # Loop melalui setiap pola dan deskripsinya
            for pattern, description in SUSPICIOUS_PATTERNS.items():
                # Menggunakan re.search untuk pencarian case-insensitive
                if re.search(pattern, content, re.IGNORECASE):
                    return pattern, description # Mengembalikan pola dan deskripsi jika ditemukan
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return None, None # Mengembalikan None jika tidak ada yang ditemukan

# --- Event Handler Utama ---
@client.event
async def on_ready():
    """Event yang berjalan sekali saat bot berhasil terhubung."""
    print(f'Bot telah masuk sebagai {client.user}')
    print('Bot siap memindai file.')
    # Pastikan folder sementara ada atau buat baru
    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR)

@client.event
async def on_message(message):
    """Event yang berjalan setiap kali ada pesan baru di channel."""
    # Abaikan pesan dari bot itu sendiri atau jika tidak ada lampiran
    if message.author == client.user or not message.attachments:
        return

    attachment = message.attachments[0]
    file_extension = os.path.splitext(attachment.filename)[1].lower()

    # 1. Validasi Tipe File
    if file_extension not in ALLOWED_EXTENSIONS:
        await message.reply(
            f"❌ **File Type Tidak Didukung**\n"
            f"File: `{attachment.filename}`\n"
            f"File yang didukung: `{', '.join(ALLOWED_EXTENSIONS)}`"
        )
        return

    # 2. Unduh File
    download_path = os.path.join(TEMP_DIR, attachment.filename)
    await attachment.save(download_path)
    
    suspicious_files = []
    
    # 3. Ekstrak dan Pindai
    if file_extension == '.zip':
        extract_folder = os.path.join(TEMP_DIR, "extracted_zip")
        try:
            with zipfile.ZipFile(download_path, 'r') as zip_ref:
                zip_ref.extractall(extract_folder)
            
            # Pindai setiap file di dalam zip
            for root, _, files in os.walk(extract_folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    pattern, description = scan_file_content(file_path)
                    if pattern:
                        relative_path = os.path.relpath(file_path, extract_folder)
                        suspicious_files.append((relative_path, pattern, description))
            # Hapus folder ekstraksi setelah selesai
            shutil.rmtree(extract_folder)
        except zipfile.BadZipFile:
            await message.reply(f"⚠️ File `{attachment.filename}` bukan arsip ZIP yang valid.")
            os.remove(download_path)
            return
    else: # Jika bukan zip (misal .lua atau .txt langsung)
        pattern, description = scan_file_content(download_path)
        if pattern:
            suspicious_files.append((attachment.filename, pattern, description))

    # 4. Berikan Laporan
    if suspicious_files:
        # Menggunakan discord.Embed untuk tampilan yang lebih bagus
        embed = discord.Embed(
            title="🚨 PERINGATAN KEAMANAN!",
            description=f"File `{attachment.filename}` mengandung skrip yang sangat mencurigakan:",
            color=discord.Color.red()
        )
        for file, pattern, description in suspicious_files:
            embed.add_field(
                name=f"🔍 File: `{file}`",
                value=f"**Pattern Terdeteksi:** `{pattern}`\n**Potensi Bahaya:** {description}",
                inline=False
            )
        await message.reply(embed=embed)
    else:
        await message.reply(f"✅ File `{attachment.filename}` terlihat aman dan tidak menunjukkan tanda-tanda mencurigakan berdasarkan daftar pola saat ini.")

    # 5. Pembersihan
    os.remove(download_path)

# --- Jalankan Bot ---
client.run(BOT_TOKEN)
