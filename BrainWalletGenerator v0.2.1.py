# BrainWalletGenerator v0.2.1 by @btcdage
import tkinter as tk
from tkinter import ttk, Canvas, Scrollbar, messagebox
from hashlib import sha256
from bip_utils import Bip39SeedGenerator, Bip84, Bip84Coins
from bitcoinlib.mnemonic import Mnemonic
from bitcoinlib.keys import HDKey, Address, Key
import threading

def copy_to_clipboard(text_widget):
    text = text_widget.get("1.0", tk.END).strip()
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()

def clear_all_results():
    results_text.config(state=tk.NORMAL)
    results_text.delete("1.0", tk.END)
    results_text.config(state=tk.DISABLED)

    update_text_entry(hex_entry, "")
    update_text_entry(hash_entry, "")
    update_text_entry(mnemonic_entry, "", readonly=False)


def validate_hash_times(new_value):
    if new_value == "":
         return True
    try:
        value = int(new_value)
        if 1 <= value <= 10000:
            return True
        else:
            return False
    except ValueError:
        return False
def validate_generate_count(new_value):
    if new_value == "":
         return True
    try:
        value = int(new_value)
        if 1 <= value <= 1000:
            return True
        else:
            return False
    except ValueError:
        return False

def update_text_entry(entry_widget, text, readonly=True):
    entry_widget.config(state='normal')
    entry_widget.delete(1.0, "end")
    entry_widget.insert(1.0, text)
    if readonly:
        entry_widget.config(state='disabled')

def create_readonly_entry(label_text_cn, label_text_en, frame):
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
    text_entry.pack(side='left', expand=True)
    copy_button = ttk.Button(entry_frame, text='Copy / 复制', command=lambda: copy_to_clipboard(text_entry))
    copy_button.pack(side='left', padx=5)

    return text_entry

def generate_addresses(mnemonic_words, count):
    output_text = ""

    hdkey = HDKey.from_passphrase(mnemonic_words, network='bitcoin')
    private_key = hdkey.private_hex
    key = Key(import_key=private_key)
    private_key_wif = key.wif()
    private_key_bech32 = "p2wpkh:" + private_key_wif
    public_key_hex = hdkey.public_hex
    address_p2pkh = Address(hdkey.public_hex, encoding='base58', script_type='p2pkh').address
    address_bech32 = Address(hdkey.public_hex, encoding='bech32', script_type='p2wpkh').address

    output_text += f"1. 私钥: {private_key_wif}\n"
    output_text += f"2. 公钥: {public_key_hex}\n"
    output_text += f"3. P2PKH地址: {address_p2pkh}\n"
    output_text += f"4. Bech32私钥: {private_key_bech32}\n"
    output_text += f"5. Bech32地址: {address_bech32}\n"

    for i in range(1, count):
        seed_str = mnemonic_words + f"[{i}]"
        hash_result = sha256(seed_str.encode('utf-8')).hexdigest()

        mnemo = Mnemonic('english')
        mnemonic_words_new = mnemo.to_mnemonic(hash_result)
        hdkey = HDKey.from_passphrase(mnemonic_words_new, network='bitcoin')
        private_key = hdkey.private_hex
        key = Key(import_key=private_key)
        private_key_wif = key.wif()
        private_key_bech32 = "p2wpkh:" + private_key_wif
        public_key_hex = hdkey.public_hex
        address_p2pkh = Address(hdkey.public_hex, encoding='base58', script_type='p2pkh').address
        address_bech32 = Address(hdkey.public_hex, encoding='bech32', script_type='p2wpkh').address

        base_line_number = (i * 5) + 1
        output_text += f"{base_line_number}. 私钥: {private_key_wif}\n"
        output_text += f"{base_line_number + 1}. 公钥: {public_key_hex}\n"
        output_text += f"{base_line_number + 2}. P2PKH地址: {address_p2pkh}\n"
        output_text += f"{base_line_number + 3}. Bech32私钥: {private_key_bech32}\n"
        output_text += f"{base_line_number + 4}. Bech32地址: {address_bech32}\n"
    return output_text

def generate_from_mnemonic_thread():
    clear_all_results()
    results_text.config(state=tk.NORMAL)
    results_text.insert("1.0", "正在生成...\n")
    results_text.config(state=tk.DISABLED)
    mnemonic_words = mnemonic_entry.get("1.0", tk.END).strip()
    if not mnemonic_words:
        results_text.config(state=tk.NORMAL)
        results_text.delete("1.0", tk.END)
        results_text.config(state=tk.DISABLED)
        messagebox.showerror("错误", "助记词不能为空")
        return

    count_str = generate_count_entry.get()
    if not count_str:
        results_text.config(state=tk.NORMAL)
        results_text.delete("1.0", tk.END)
        results_text.config(state=tk.DISABLED)
        messagebox.showerror("错误", "请输入生成数量")
        return
    try:
        count = int(count_str)
        if not 1 <= count <= 1000:
           results_text.config(state=tk.NORMAL)
           results_text.delete("1.0", tk.END)
           results_text.config(state=tk.DISABLED)
           messagebox.showerror("错误", "生成数量必须是1到1000的整数")
           return
    except ValueError:
        results_text.config(state=tk.NORMAL)
        results_text.delete("1.0", tk.END)
        results_text.config(state=tk.DISABLED)
        messagebox.showerror("错误", "生成数量必须是整数")
        return

    output_text = generate_addresses(mnemonic_words, count)

    results_text.config(state=tk.NORMAL)
    results_text.delete("1.0", tk.END)
    results_text.insert("1.0", output_text)
    results_text.config(state=tk.DISABLED)

def generate_from_mnemonic():
    threading.Thread(target=generate_from_mnemonic_thread).start()


def generate_brain_wallet_thread():
    clear_all_results()
    results_text.config(state=tk.NORMAL)
    results_text.insert("1.0", "正在生成...\n")
    results_text.config(state=tk.DISABLED)
    passphrase = passphrase_entry.get()
    salt = salt_entry.get()
    hash_times_str = hash_times_entry.get()
    if not hash_times_str:
        results_text.config(state=tk.NORMAL)
        results_text.delete("1.0", tk.END)
        results_text.config(state=tk.DISABLED)
        messagebox.showerror("错误", "请输入哈希次数")
        return

    try:
      hash_times = int(hash_times_str)
      if not 1 <= hash_times <= 10000:
          results_text.config(state=tk.NORMAL)
          results_text.delete("1.0", tk.END)
          results_text.config(state=tk.DISABLED)
          messagebox.showerror("错误", "哈希次数必须是1到10000的整数")
          return
    except ValueError:
      results_text.config(state=tk.NORMAL)
      results_text.delete("1.0", tk.END)
      results_text.config(state=tk.DISABLED)
      messagebox.showerror("错误", "哈希次数必须是整数")
      return

    for _ in range(hash_times):
        if salt:
            passphrase = passphrase + salt
        bytes_passphrase = passphrase.encode('utf-8')
        hash_result = sha256(bytes_passphrase).hexdigest()
        passphrase = hash_result
    hex_passphrase = "0x" + bytes_passphrase.hex()
    mnemo = Mnemonic('english')
    mnemonic_words = mnemo.to_mnemonic(hash_result)
    update_text_entry(hex_entry, hex_passphrase)
    update_text_entry(hash_entry, hash_result)
    update_text_entry(mnemonic_entry, mnemonic_words, readonly=False)

    count_str = generate_count_entry.get()
    if not count_str:
        return
    try:
        count = int(count_str)
        if not 1 <= count <= 1000:
            return
    except ValueError:
        return
    output_text = generate_addresses(mnemonic_words, count)
    results_text.config(state=tk.NORMAL)
    results_text.delete("1.0", tk.END)
    results_text.insert("1.0", output_text)
    results_text.config(state=tk.DISABLED)

def generate_brain_wallet():
    threading.Thread(target=generate_brain_wallet_thread).start()

root = tk.Tk()
root.title("Brain Wallet Generator by @btcdage / 脑钱包生成器 by 达哥（@btcdage）")
root.geometry("700x600")

title_label = ttk.Label(root, text="Brain Wallet Generator V0.2.1/ 比特币脑钱包生成器 V0.2.1", font=("Arial", 16), anchor='center')
title_label.pack(side="top", pady=5)
title_label1 = ttk.Label(root, text="请使用高级脑而不是直接使用一维脑钱包-达哥（@btcdage）", font=("Arial", 8), anchor='center')
title_label1.pack(side="top", pady=3)
title_label2 = ttk.Label(root, text="Please use advanced brain instead of directly using a one-dimensional brain wallet - @btcdage.", font=("Arial", 8), anchor='center')
title_label2.pack(side="top", pady=10)

main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill="both", expand=True)

# Passphrase Label and Entry
passphrase_frame = ttk.Frame(main_frame)
passphrase_frame.pack(side="top", fill='x')

passphrase_label = ttk.Label(passphrase_frame, text="Passphrase / 脑口令:")
passphrase_label.pack(side="left", pady=3, padx=5)
passphrase_entry = ttk.Entry(passphrase_frame, width=60)
passphrase_entry.pack(side="left", pady=3, padx=5, fill='x', expand=True)

salt_frame = ttk.Frame(main_frame)
salt_frame.pack(side="top", fill='x')

salt_label = ttk.Label(salt_frame, text="Salt / 加盐:")
salt_label.pack(side="left", pady=3, padx=5)
salt_entry = ttk.Entry(salt_frame, width=60)
salt_entry.pack(side="left", pady=3, padx=5, fill='x', expand=True)


hash_generate_frame = ttk.Frame(main_frame)
hash_generate_frame.pack(side="top", fill='x')


hash_times_label = ttk.Label(hash_generate_frame, text="Hash Times / 哈希次数 (1-10000):")
hash_times_label.pack(side="left", pady=3, padx=5)
hash_times_entry = ttk.Entry(hash_generate_frame, width=10, validate="key")
hash_times_entry['validatecommand'] = (hash_times_entry.register(validate_hash_times), '%P')
hash_times_entry.pack(side="left", pady=3, padx=5)
hash_times_entry.insert(0, "1")

generate_count_label = ttk.Label(hash_generate_frame, text="Generate Count / 生成数量(1-1000):")
generate_count_label.pack(side="left", pady=3, padx=5)
generate_count_entry = ttk.Entry(hash_generate_frame, width=10, validate="key")
generate_count_entry['validatecommand'] = (generate_count_entry.register(validate_generate_count), '%P')
generate_count_entry.pack(side="left", pady=3, padx=5)
generate_count_entry.insert(0, "1")


button_frame = ttk.Frame(main_frame)
button_frame.pack(side="top", pady=3, fill='x')

generate_button = ttk.Button(button_frame, text="Generate Brain Wallet / 开始计算", command=generate_brain_wallet)
generate_button.pack(side="left", pady=3, padx=5)
clear_button = ttk.Button(button_frame, text="Clear All / 清空所有", command=clear_all_results)
clear_button.pack(side="left", pady=10, padx=5)


hex_entry_frame = ttk.Frame(main_frame)
hex_entry_frame.pack(fill='x', padx=10, pady=5)
hex_entry = create_readonly_entry("字节化","Hexadecimal Encoding:", hex_entry_frame)

hash_entry_frame = ttk.Frame(main_frame)
hash_entry_frame.pack(fill='x', padx=10, pady=5)
hash_entry = create_readonly_entry("SHA-256哈希:","SHA-256 Hash:", hash_entry_frame)

mnemonic_entry_frame = ttk.Frame(main_frame)
mnemonic_entry_frame.pack(fill='x', padx=10, pady=5)
mnemonic_entry = create_readonly_entry("BIP39助记词","BIP39 Mnemonic Words:", mnemonic_entry_frame)

mnemonic_button_frame = ttk.Frame(main_frame)
mnemonic_button_frame.pack(fill="x", pady=5)

generate_from_mnemonic_button = ttk.Button(mnemonic_button_frame, text="Generate from mnemonic / 根据助记词生成", command=generate_from_mnemonic)
generate_from_mnemonic_button.pack(side='left', padx=5)

copy_results_button = ttk.Button(mnemonic_button_frame, text='Copy bitcoin Keys /复制结果', command=lambda: copy_to_clipboard(results_text))
copy_results_button.pack(side='left', padx=5)



results_text_frame = tk.Frame(main_frame)
results_text_frame.pack(fill='both', expand=True, padx=10)

results_text = tk.Text(results_text_frame, height=10, width=100, wrap="word")
results_text.config(state='disabled')
results_text.pack(side='left', fill='both', expand=True,  )

results_scrollbar = Scrollbar(results_text_frame, command=results_text.yview)
results_scrollbar.pack(side='right', fill='y') 
results_text.config(yscrollcommand=results_scrollbar.set)

root.mainloop()
