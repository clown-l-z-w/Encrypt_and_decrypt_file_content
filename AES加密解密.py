import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from PIL import Image, ImageTk
import random

f_p = ""
text = ""


def encryption(data, key):
    try:
        c_key = key.encode('utf-8')
        p_k = pad(c_key, 16, 'pkcs7')
        p_d = pad(data, 16, 'pkcs7')
        c_mode = AES.MODE_ECB
        c_cryption = AES.new(p_k, c_mode)
        c_msg = base64.b64encode(c_cryption.encrypt(p_d))
        return c_msg
    except Exception:
        raise messagebox.showerror('错误', '加密失败！请检查数据然后重试！')


def decryption(data, key):
    try:
        d_key = key.encode('utf-8')
        mode_d = AES.new(pad(d_key, 16, 'pkcs7'), AES.MODE_ECB)
        msg_d = mode_d.decrypt(base64.b64decode(data))
        msg_d = unpad(msg_d, 16, 'pkcs7')
        return msg_d
    except Exception:
        raise messagebox.showerror('错误', '解密失败！请检查密钥和数据然后重试！')


def encrypt_file(file_path, key, t):
    try:
        if key == '' or key == '请输入密钥,如不输入则随机生成一个16位的密钥':
            key = random_key()
        else:
            key = key
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted_data = encryption(data, key)
        with open(file_path, "wb") as f:
            f.write(encrypted_data)
            t.config(state=tk.NORMAL)
            t.delete('1.0', tk.END)
            t.insert(tk.END, f"{key}")
            t.config(state=tk.DISABLED)
            messagebox.showinfo('提示', '加密成功！')
    except Exception:
        raise messagebox.showerror('错误', '加密失败！请检查文件路径！')


def decrypt_file(file_path, key):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        decrypted_data = decryption(data, key)
        with open(file_path, "wb") as f:
            f.write(decrypted_data)
            messagebox.showinfo('提示', '解密成功！')
    except Exception:
        raise messagebox.showerror('错误', '解密失败！请检查文件路径！')


def select_file(s):
    try:
        global f_p
        f_p = filedialog.askopenfilename()
        if f_p:
            s.config(text=f"选中的文件：{f_p}")
    except Exception:
        raise messagebox.showerror('错误', '打开文件失败！')


def random_key():
    return ''.join(random.sample('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 16))


def window_mian():
    try:
        root = tk.Tk()
        root.title("AES加密解密工具")
        root.geometry("512x512")
        root.maxsize(512, 512)
        root.minsize(512, 512)
        canvas = tk.Canvas(root, width=512, height=512)
        canvas.pack(fill="both", expand=True)

        # background_image = Image.open('./bg.png')
        # bg_image = ImageTk.PhotoImage(background_image)
        # canvas.create_image(0, 0, anchor='nw', image=bg_image)

        s_l = tk.Label(root, text="请选择一个文件或保存路径", borderwidth=0, font=("Arial", 12))
        s_l.place(relx=0.5, rely=0.1, anchor='center')

        # icon_image = tk.PhotoImage(file='./img.png')
        # root.iconphoto(True, icon_image)

        entry_e = tk.Entry(root, width=50)
        entry_e.insert(0, '请输入密钥,如不输入则随机生成一个16位的密钥')
        entry_e.place(relx=0.5, rely=0.2, anchor='center')

        entry_d = tk.Entry(root, width=50)
        entry_d.insert(0, '请输入解密密钥')
        entry_d.place(relx=0.5, rely=0.3, anchor='center')
        global text
        text = tk.Text(root, height=1, width=20, borderwidth=0, font=("Arial", 12))
        text.insert(tk.END, "密钥显示处")
        text.config(state=tk.DISABLED)
        text.place(relx=0.5, rely=0.4, anchor='center')

        open_button = tk.Button(text="打开文件", command=lambda: select_file(s_l), borderwidth=0, width=10, height=2)
        open_button.place(relx=0.2, rely=0.6, anchor='center')

        encryption_button = tk.Button(root, text="加密文件内容", command=lambda: encrypt_file(f_p, entry_e.get(), text),
                                      borderwidth=0, width=10, height=2)
        encryption_button.place(relx=0.5, rely=0.6, anchor='center')

        decryption_button = tk.Button(root, text="解密文件内容", command=lambda: decrypt_file(f_p, entry_d.get()),
                                      borderwidth=0, width=10, height=2)
        decryption_button.place(relx=0.8, rely=0.6, anchor='center')

        root.mainloop()
    except Exception:
        raise messagebox.showerror('错误', '程序运行失败！可能已损坏，请重新安装！')


if __name__ == '__main__':
    window_mian()
