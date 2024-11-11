import base64
from Crypto.Cipher import AES, DES3, Blowfish
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import random
import zipfile
import shutil
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization


f_p = ""
k_f = ""


def aes_key():
    """生成aes密钥"""
    return ''.join(random.sample('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 16))


def des3_key():
    """生成des3密钥"""
    return DES3.adjust_key_parity(os.urandom(24))


def blowfish_key(key_mode):
    """生成blowfish密钥"""
    if key_mode == 'blowfish':
        return os.urandom(16)
    elif key_mode == 'rsa':
        return os.urandom(56)


def rsa_key():
    """生成rsa密钥"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    password = os.urandom(16)
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key, private_key, salt, password


def rsa_encryption(data, private_key, key, path):
    """rsa加密"""
    key_data = blowfish_key('rsa')
    public_key = private_key.public_key()
    encrypted_data = public_key.encrypt(
        key_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    pem_data = private_key.private_bytes(
            format=serialization.PrivateFormat.PKCS8,
            encoding=serialization.Encoding.PEM,
            encryption_algorithm=serialization.BestAvailableEncryption(key)
        )
    handle_data = blowfish_encryption(data, key_data)
    zip_file(path, encrypted_data, handle_data, pem_data)


def rsa_decryption(data_file, key):
    """rsa解密"""
    key_salt = base64.b64decode(key[0:24].encode('utf-8'))
    key_password = base64.b64decode(key[24:].encode('utf-8'))
    decryption_kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=key_salt,
        iterations=100000,
        backend=default_backend()
    )
    decryption_key = decryption_kdf.derive(key_password)
    extract_file = unzip_file(data_file)
    with open(extract_file + '/private_key.pem', "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=decryption_key,
            backend=default_backend()
        )
    with open(extract_file + '/key', "rb") as d_f_one:
        key_data = d_f_one.read()

    decrypted_key = private_key.decrypt(
        key_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(extract_file + '/data', "rb") as d_f_two:
        encrypted_data = d_f_two.read()
    mode = 'rsa'
    blowfish_decrypted_data = blowfish_decryption(encrypted_data, decrypted_key)
    shutil.rmtree(extract_file)
    return blowfish_decrypted_data


def aes_encryption(data, key):
    """aes加密"""
    c_key = key.encode('utf-8')
    p_k = pad(c_key, 16, 'pkcs7')
    p_d = pad(data, 16, 'pkcs7')
    c_mode = AES.MODE_ECB
    c_cryption = AES.new(p_k, c_mode)
    c_msg = c_cryption.encrypt(p_d)
    return c_msg


def aes_decryption(data, key):
    """aes解密"""
    d_key = key.encode('utf-8')
    mode_d = AES.new(pad(d_key, 16, 'pkcs7'), AES.MODE_ECB)
    msg_d = mode_d.decrypt(data)
    msg_d = unpad(msg_d, 16, 'pkcs7')
    return msg_d


def des3_encryption(data, key):
    """des3加密"""
    p_d = pad(data, DES3.block_size)
    c_cryption = DES3.new(key, DES3.MODE_ECB)
    c_msg = c_cryption.encrypt(p_d)
    return c_msg


def des3_decryption(enc_data, key):
    """des3解密"""
    d_key = base64.b64decode(key.encode('utf-8'))
    cipher = DES3.new(d_key, DES3.MODE_ECB)
    c = cipher.decrypt(enc_data)
    decrypted_data = unpad(c, DES3.block_size)
    return decrypted_data


def blowfish_encryption(data, key):
    """blowfish加密"""
    c_cryption = Blowfish.new(key, Blowfish.MODE_ECB)
    p_d = pad(data, Blowfish.block_size)
    c_msg = c_cryption.encrypt(p_d)
    return c_msg


def blowfish_decryption(enc_data, key):
    """blowfish解密"""
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    c = cipher.decrypt(enc_data)
    decrypted_data = unpad(c, Blowfish.block_size)
    return decrypted_data


def file_name(path, mode):
    """新文件名"""
    if mode == "加密":
        new_file_name = path.rsplit('/', 1)[0] + "/加密后的" + path.split('/')[-1]
        return new_file_name
    elif mode == "解密":
        new_file_name = path.rsplit('/', 1)[0] + "/解密后的" + path.split('/')[-1]
        return new_file_name
    elif mode == "密钥":
        new_file_name = path.rsplit('.', 1)[0] + "的密码.txt"
        return new_file_name
    elif mode == "temp":
        new_file_name = "E:/cc/temp"
        return new_file_name


def create_file(path, data, mode):
    """创建文件"""
    with open(path, mode) as f:
        f.write(data)


def zip_file(main_path, data_key, data_main, data_pem):
    """压缩文件"""
    new_folder_path = file_name(main_path, "加密")
    os.makedirs(new_folder_path, exist_ok=True)
    with open(new_folder_path + "/data", "wb") as f:
        f.write(data_main)
    with open(new_folder_path + "/key", "wb") as f:
        f.write(data_key)
    with open(new_folder_path + "/private_key.pem", "wb") as f:
        f.write(data_pem)
    zip_path = new_folder_path.rsplit('.', 1)[0] + ".zip"

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(new_folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                zf.write(file_path, arcname=os.path.relpath(file_path, new_folder_path))
    suffix = '.' + main_path.rsplit('.', 1)[1]
    shutil.rmtree(new_folder_path)
    change_file_extension(zip_path, suffix)


def unzip_file(zip_path):
    """解压文件"""
    extract_path = file_name(zip_path, "temp")
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(extract_path)
    return extract_path


def change_file_extension(old_file_path, new_extension):
    dir_path, change_file_name = os.path.split(old_file_path)
    new_file_name = os.path.splitext(change_file_name)[0] + new_extension
    new_file_path = dir_path + '/' + new_file_name
    os.rename(old_file_path, new_file_path)


def encrypt_file(file_path, mode):
    """加密文件"""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            if mode == "AES":
                key = aes_key()
                encrypted_data = aes_encryption(data, key)
                file_write_mode = "wb"
            elif mode == "DES3":
                key = des3_key()
                encrypted_data = des3_encryption(data, key)
                key = base64.b64encode(key).decode('utf-8')
                file_write_mode = "wb"
            elif mode == "Blowfish":
                key = blowfish_key('blowfish')
                encrypted_data = blowfish_encryption(data, key)
                key = base64.b64encode(key).decode('utf-8')
                file_write_mode = "wb"
            elif mode == "RSA":
                kdf, private_key, salt, password = rsa_key()
                rsa_encryption(data, private_key, kdf, file_path)
                key = base64.b64encode(salt).decode() + base64.b64encode(password).decode()
            elif mode == "DSA":
                print("DSA加密暂不支持！")
            elif mode == "ECC":
                print("ECC加密暂不支持！")
        if mode == "AES" or mode == "DES3" or mode == "Blowfish":
            encrypted_data_file_name = file_name(file_path, "加密")
            create_file(encrypted_data_file_name, encrypted_data, file_write_mode)
        encrypted_key_file_name = file_name(file_path, "密钥")
        create_file(encrypted_key_file_name, key, 'w')

        messagebox.showinfo('提示', '加密成功！')
    except Exception:
        raise messagebox.showerror('错误', '加密失败！请检查文件路径！')


def decrypt_file(file_path, key, mode):
    """解密文件"""
    try:

        with open(file_path, "rb") as f:
            data = f.read()
            if mode == "AES":
                decrypted_data = aes_decryption(data, key)
                file_write_mode = "wb"
            elif mode == "DES3":
                decrypted_data = des3_decryption(data, key)
                file_write_mode = "wb"
            elif mode == "Blowfish":
                d_key = base64.b64decode(key.encode('utf-8'))
                decrypted_data = blowfish_decryption(data, d_key)
                file_write_mode = "wb"
            elif mode == "RSA":
                decrypted_data = rsa_decryption(file_path, key)
                file_write_mode = "wb"
        decrypted_data_file_name = file_name(file_path, "解密")
        create_file(decrypted_data_file_name, decrypted_data, file_write_mode)
        messagebox.showinfo('提示', '解密成功！')
    except Exception:
        raise messagebox.showerror('错误', '解密失败！请检查文件路径！')


def select_file(s):
    """选择文件"""
    try:
        global f_p
        f_p = filedialog.askopenfilename()
        s.config(text=f"选中需加密或解密文件：{f_p}")
    except Exception:
        raise messagebox.showerror('错误', '打开文件失败！')


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

        s_l_one = tk.Label(root, text="", borderwidth=0, font=("Arial", 12))
        s_l_one.place(relx=0.5, rely=0.15, anchor='center')

        m_l = tk.Label(root, text="请选择加密模式：", borderwidth=0, font=("Arial", 15))
        m_l.place(relx=0.38, rely=0.3, anchor='center')

        options = ["AES", "DES3", "Blowfish", "RSA"]
        mode_var = tk.StringVar(value=options[0])
        mode_dropdown = tk.OptionMenu(root, mode_var, *options)
        mode_dropdown.config(height=1, font=("Arial", 9))
        mode_dropdown.place(relx=0.65, rely=0.3, anchor='center')

        open_file = tk.Button(text="选择需要加密或者解密文件", command=lambda: select_file(s_l_one),
                              width=50)
        open_file.place(relx=0.5, rely=0.45, anchor='center')

        encryption_button = tk.Button(root, text="加密文件内容", command=lambda: encrypt_file(f_p, mode_var.get()),
                                      width=20)
        encryption_button.place(relx=0.3, rely=0.55, anchor='center')

        decryption_button = tk.Button(root, text="解密文件内容",
                                      command=lambda: decrypt_file(f_p, entry_d.get(), mode_var.get()),
                                      width=20)
        decryption_button.place(relx=0.7, rely=0.55, anchor='center')

        entry_d = tk.Entry(root, width=50)
        entry_d.insert(0, '请输入解密密钥')
        entry_d.place(relx=0.5, rely=0.7, anchor='center')

        root.mainloop()
    except Exception:
        raise messagebox.showerror('错误', '程序运行失败！可能已损坏，请重新安装！')


if __name__ == '__main__':
    window_mian()
