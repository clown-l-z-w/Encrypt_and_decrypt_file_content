import base64
from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import random
import os

f_p = ""


def aes_encryption(data, key):
    """aes加密"""
    c_key = key.encode('utf-8')
    p_k = pad(c_key, 16, 'pkcs7')
    p_d = pad(data, 16, 'pkcs7')
    c_mode = AES.MODE_ECB
    c_cryption = AES.new(p_k, c_mode)
    c_msg = base64.b64encode(c_cryption.encrypt(p_d))
    return c_msg.decode('utf-8')


def aes_decryption(data, key):
    """aes解密"""
    d_key = key.encode('utf-8')
    mode_d = AES.new(pad(d_key, 16, 'pkcs7'), AES.MODE_ECB)
    msg_d = mode_d.decrypt(base64.b64decode(data))
    msg_d = unpad(msg_d, 16, 'pkcs7')
    return msg_d


def des3_encryption(data, key):
    """des3加密"""
    p_d = pad(data, DES3.block_size)
    c_cryption = DES3.new(key, DES3.MODE_ECB)
    c_msg = c_cryption.encrypt(p_d)
    return base64.b64encode(c_msg).decode('utf-8')


def des3_decryption(enc_data, key):
    """des3解密"""
    d_key = base64.b64decode(key.encode('utf-8'))
    enc_data = base64.b64decode(enc_data.decode('utf-8'))
    cipher = DES3.new(d_key, DES3.MODE_ECB)
    c = cipher.decrypt(enc_data)
    decrypted_data = unpad(c, DES3.block_size)
    return decrypted_data


def encrypt_file(file_path, mode):
    """加密文件"""
    try:
        path = file_path.rsplit('/', 1)[0]
        file_name = "加密后的" + file_path.split('/')[-1]
        with open(file_path, "rb") as f:
            data = f.read()
            if mode == "AES":
                key = aes_key()
                encrypted_data = aes_encryption(data, key)
            elif mode == "DES3":
                key = des3_key()
                encrypted_data = des3_encryption(data, key)
                key = base64.b64encode(key).decode('utf-8')
        with open(path + "/" + "密钥.txt", "w") as f:
            f.write(key)

        new_file_path = path + "/" + file_name
        with open(new_file_path, "w") as f:
            f.write(encrypted_data)
            messagebox.showinfo('提示', '加密成功！')
    except Exception:
        raise messagebox.showerror('错误', '加密失败！请检查文件路径！')


def decrypt_file(file_path, key, mode):
    """解密文件"""
    try:
        path = file_path.rsplit('/', 1)[0]
        file_name = "解密后的" + file_path.split('/')[-1]
        with open(file_path, "rb") as f:
            data = f.read()
            if mode == "AES":
                decrypted_data = aes_decryption(data, key)
            elif mode == "DES3":
                decrypted_data = des3_decryption(data, key)

        new_file_path = path + "/" + file_name
        with open(new_file_path, "wb") as f:
            f.write(decrypted_data)
            messagebox.showinfo('提示', '解密成功！')
    except Exception:
        raise messagebox.showerror('错误', '解密失败！请检查文件路径！')


def select_file(s):
    """选择文件"""
    try:
        global f_p
        f_p = filedialog.askopenfilename()
        if f_p:
            s.config(text=f"选中的文件：{f_p}")
    except Exception:
        raise messagebox.showerror('错误', '打开文件失败！')


def aes_key():
    """生成aes密钥"""
    return ''.join(random.sample('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 16))


def des3_key():
    """生成des3密钥"""
    return DES3.adjust_key_parity(os.urandom(24))


def window_mian():
    """主窗体"""
    try:
        root = tk.Tk()
        root.title("文件内容加密解密工具")
        root.geometry("500x512")
        root.maxsize(500, 512)
        root.minsize(500, 512)
        canvas = tk.Canvas(root, width=500, height=512)
        canvas.pack(fill="both", expand=True)

        s_l = tk.Label(root, text="请选择一个文件或保存路径", borderwidth=0, font=("Arial", 12))
        s_l.place(relx=0.5, rely=0.15, anchor='center')

        m_l = tk.Label(root, text="请选择加密模式：", borderwidth=0, font=("Arial", 15))
        m_l.place(relx=0.38, rely=0.3, anchor='center')

        options = ["AES", "DES3"]
        mode_var = tk.StringVar(value=options[0])
        mode_dropdown = tk.OptionMenu(root, mode_var, *options)
        mode_dropdown.config(height=1, font=("Arial", 9))
        mode_dropdown.place(relx=0.65, rely=0.3, anchor='center')

        open_button = tk.Button(text="打开文件", command=lambda: select_file(s_l), borderwidth=0, width=10)
        open_button.place(relx=0.2, rely=0.45, anchor='center')

        encryption_button = tk.Button(root, text="加密文件内容", command=lambda: encrypt_file(f_p, mode_var.get()),
                                      borderwidth=0, width=10)
        encryption_button.place(relx=0.5, rely=0.45, anchor='center')

        decryption_button = tk.Button(root, text="解密文件内容",
                                      command=lambda: decrypt_file(f_p, entry_d.get(), mode_var.get()), borderwidth=0,
                                      width=10)
        decryption_button.place(relx=0.8, rely=0.45, anchor='center')

        entry_d = tk.Entry(root, width=50)
        entry_d.insert(0, '请输入解密密钥')
        entry_d.place(relx=0.5, rely=0.6, anchor='center')

        root.mainloop()
    except Exception:
        raise messagebox.showerror('错误', '程序运行失败！可能已损坏，请重新安装！')


if __name__ == '__main__':
    window_mian()
