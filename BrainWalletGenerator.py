# BrainWalletGenerator by @btcdage
import tkinter as tk
from tkinter import ttk, Canvas, Scrollbar
from hashlib import sha256
from PIL import Image, ImageTk
import qrcode
from bip_utils import Bip39SeedGenerator, Bip84, Bip84Coins
from bitcoinlib.mnemonic import Mnemonic
from bitcoinlib.keys import HDKey, Address, Key
def copy_to_clipboard(text_widget):
    text = text_widget.get("1.0", tk.END).strip()
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()
def setup_scrollable_frame(root):
    canvas = Canvas(root)
    scrollbar = Scrollbar(root, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    scrollable_frame = ttk.Frame(canvas)
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    center_frame = ttk.Frame(scrollable_frame)
    center_frame.pack(fill="both", anchor='center',expand=True)
    return canvas, scrollbar, center_frame
def clear_all_results():
    entries = [hex_entry, hash_entry, mnemonic_entry, private_key_entry, public_key_entry, p2pkh_entry, bech32_key_entry, bech32_entry]
    for entry in entries:
        entry.config(state=tk.NORMAL)
        entry.delete("1.0", tk.END)
        entry.config(state=tk.DISABLED)
    qr_frames = [mnemonic_qr_frame, private_key_qr_frame, public_key_qr_frame, p2pkh_qr_frame, bech32key_qr_frame, bech32_qr_frame]
    for qr_frame in qr_frames:
        for widget in qr_frame.winfo_children():
            widget.destroy()
def generate_qr_code(data, size=100):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img_pil = img.convert('RGB').resize((size, size), Image.Resampling.LANCZOS)  # Updated line
    img_tk = ImageTk.PhotoImage(image=img_pil)
    return img_tk
def update_text_entry(entry_widget, text, readonly=True):
    entry_widget.config(state='normal')
    entry_widget.delete(1.0, "end")
    entry_widget.insert(1.0, text)
    if readonly:
        entry_widget.config(state='disabled')
def update_text_entry_with_qr(entry_widget, text, qr_frame, readonly=True):
    update_text_entry(entry_widget, text, readonly)
    qr_code_image = generate_qr_code(text)
    for widget in qr_frame.winfo_children():
        widget.destroy()
    qr_label = tk.Label(qr_frame, image=qr_code_image)
    qr_label.image = qr_code_image
    qr_label.pack()
def create_readonly_entry_and_qr(label_text_cn, label_text_en, frame):
    label = ttk.Label(frame, text=f"{label_text_en} / {label_text_cn}")
    label.pack(anchor='center')
    entry_frame = tk.Frame(frame)
    entry_frame.pack(fill='x', expand=True)
    if "BIP39" in label_text_en:
        text_entry_height = 3
        text_entry = tk.Text(entry_frame, height=text_entry_height,  width=80, wrap="word")
    else:
        text_entry_height = 1
        text_entry = tk.Text(entry_frame, height=text_entry_height,  width=80, bg='#f0f0f0', wrap="word")
        text_entry.config(state='disabled')
    text_entry.pack(side='left')
    copy_button = ttk.Button(entry_frame, text='复制', command=lambda: copy_to_clipboard(text_entry))
    copy_button.pack(side='left', padx=5)

    qr_frame = tk.Frame(entry_frame, height=100, width=100)
    qr_frame.pack(side='left', padx=10)
    return text_entry, qr_frame
def generate_from_mnemonic():
    mnemonic_words = mnemonic_entry.get("1.0", tk.END).strip()
    if not mnemonic_words:
        clear_all_results()
        print("助记词不能为空")
        return
    hdkey = HDKey.from_passphrase(mnemonic_words, network='bitcoin')
    private_key = hdkey.private_hex
    key = Key(import_key=private_key)
    private_key_wif = key.wif()
    private_key_bech32 = "p2wpkh:"+private_key_wif
    public_key_hex = hdkey.public_hex
    address_p2pkh = Address(hdkey.public_hex, encoding='base58', script_type='p2pkh').address
    address_bech32 = Address(hdkey.public_hex, encoding='bech32', script_type='p2wpkh').address
    clear_all_results()
    update_text_entry_with_qr(public_key_entry, public_key_hex, public_key_qr_frame)
    update_text_entry_with_qr(mnemonic_entry, mnemonic_words, mnemonic_qr_frame,readonly=False)
    update_text_entry_with_qr(private_key_entry, private_key_wif, private_key_qr_frame)
    update_text_entry_with_qr(p2pkh_entry, address_p2pkh, p2pkh_qr_frame)
    update_text_entry_with_qr(bech32_key_entry, private_key_bech32, bech32key_qr_frame)
    update_text_entry_with_qr(bech32_entry, address_bech32, bech32_qr_frame)

def generate_brain_wallet():
    passphrase = passphrase_entry.get()
    salt = salt_entry.get()
    hash_times = int(hash_times_combo.get())
    for _ in range(hash_times):
        if salt:
            passphrase = passphrase + salt
        bytes_passphrase = passphrase.encode('utf-8')
        hash_result = sha256(bytes_passphrase).hexdigest()
        passphrase = hash_result
    hex_passphrase = "0x" + bytes_passphrase.hex()
    mnemo = Mnemonic('english')
    mnemonic_words = mnemo.to_mnemonic(hash_result)
    hdkey = HDKey.from_passphrase(mnemonic_words, network='bitcoin')
    private_key = hdkey.private_hex
    key = Key(import_key=private_key)
    private_key_wif = key.wif()
    private_key_bech32 = "p2wpkh:"+private_key_wif
    public_key_hex = hdkey.public_hex
    address_p2pkh = Address(hdkey.public_hex, encoding='base58', script_type='p2pkh').address
    address_bech32 = Address(hdkey.public_hex, encoding='bech32', script_type='p2wpkh').address
    update_text_entry(hex_entry, hex_passphrase)
    update_text_entry(hash_entry, hash_result)
    update_text_entry_with_qr(public_key_entry, public_key_hex, public_key_qr_frame)
    update_text_entry_with_qr(mnemonic_entry, mnemonic_words, mnemonic_qr_frame,readonly=False)
    update_text_entry_with_qr(private_key_entry, private_key_wif, private_key_qr_frame)
    update_text_entry_with_qr(p2pkh_entry, address_p2pkh, p2pkh_qr_frame)
    update_text_entry_with_qr(bech32_key_entry, private_key_bech32, bech32key_qr_frame)
    update_text_entry_with_qr(bech32_entry, address_bech32, bech32_qr_frame)
root = tk.Tk()
root.title("Brain Wallet Generator by @btcdage / 脑钱包生成器 by @囤饼达")
root.geometry("800x600")
title_label = ttk.Label(root, text="Brain Wallet Generator / 比特币脑钱包生成器", font=("Arial", 16))
title_label.pack(side="top", pady=5)
title_label1 = ttk.Label(root, text="请使用高级脑而不是直接使用一维脑钱包-@囤饼达", font=("Arial", 8))
title_label1.pack(side="top", pady=3)
title_label2 = ttk.Label(root, text="Please use advanced brain instead of directly using a one-dimensional brain wallet - @btcdage.", font=("Arial", 8))
title_label2.pack(side="top", pady=10)
passphrase_label = ttk.Label(root, text="Passphrase / 脑口令:")
passphrase_label.pack(side="top", pady=3)
passphrase_entry = ttk.Entry(root, width=80,)
passphrase_entry.pack(side="top", pady=3)
salt_label = ttk.Label(root, text="Salt / 加盐:")
salt_label.pack(side="top", pady=3)
salt_entry = ttk.Entry(root, width=80)
salt_entry.pack(side="top", pady=3)
hash_times_label = ttk.Label(root, text="Hash Times / 哈希次数:")
hash_times_label.pack(side="top", pady=3)
hash_times_combo = ttk.Combobox(root, values=[i for i in range(1, 10001)],state = 'readonly')
hash_times_combo.pack(side="top", pady=3)
hash_times_combo.set(1)
generate_button = ttk.Button(root, text="Generate Brain Wallet / 开始计算", command=generate_brain_wallet)
generate_button.pack(side="top", pady=3)
clear_button = ttk.Button(root, text="Clear All / 清空所有", command=clear_all_results)
clear_button.pack(side="top", pady=10)
canvas, scrollbar,center_frame = setup_scrollable_frame(root)
info_frame = tk.Frame(root)
info_frame.pack(fill='both')
hex_entry, _ = create_readonly_entry_and_qr("字节化","Hexadecimal Encoding:", center_frame)
hash_entry, _ = create_readonly_entry_and_qr("SHA-256哈希:","SHA-256 Hash:", center_frame)
mnemonic_entry, mnemonic_qr_frame = create_readonly_entry_and_qr("BIP39助记词","BIP39 Mnemonic Words:", center_frame)
generate_from_mnemonic_button = ttk.Button(center_frame, text="Generate from mnemonic / 根据助记词生成", command=generate_from_mnemonic)
generate_from_mnemonic_button.pack()
private_key_entry, private_key_qr_frame = create_readonly_entry_and_qr("私钥","Private Key:", center_frame)
public_key_entry, public_key_qr_frame = create_readonly_entry_and_qr("公钥","Public Key:", center_frame)
p2pkh_entry, p2pkh_qr_frame = create_readonly_entry_and_qr("P2PKH地址:","P2PKH Address:", center_frame)
bech32_key_entry, bech32key_qr_frame = create_readonly_entry_and_qr("Bech32私钥:","Bech32 Private Key:", center_frame)
bech32_entry, bech32_qr_frame = create_readonly_entry_and_qr("Bech32地址:","Bech32 Address:", center_frame)
root.mainloop()
