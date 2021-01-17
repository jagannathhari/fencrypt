import os
import struct

import nacl.secret
import nacl.utils
import nacl.pwhash



def generate_key(secrate_string, salt):
    password = secrate_string.encode("utf-8")
    kdf = nacl.pwhash.argon2i.kdf
    key = kdf(nacl.secret.SecretBox.KEY_SIZE, password, salt)
    return key


class EncryptFile:
  

    def __init__(self, file_path, destination=None, password=""):
        self.file_path = file_path
        self.file_extension = (os.path.splitext(
            self.file_path)[1][1:]).encode("utf-8")
        self.file_extension_len = len(self.file_extension)
        self.file_size = os.stat(self.file_path).st_size
        self.EXTENSION = ".fenc"
        self.file_name = os.path.basename(self.file_path)
        self.destination = destination
        self.SALT_SIZE = 16  # size of salt in byte
        self.password = password
        self._salt = None  # generate salt
        self._key = None  # generate key from string
        self.safe_box = None
        self.NONCE_SIZE = None
        self.MACBYTES = None
        self.DISCRIPTION = b"This File Is Created With Fenc"  # File description
        self.VERSION = (1, 0, 0)  # app version 1.0.0 major:1 minor:0 patch:0
        self.DISCRIPTION_LEN = len(self.DISCRIPTION)
        self.FILEINFO_LEN = struct.calcsize(
            f'{self.DISCRIPTION_LEN}s i i i 16s i i i')  # lenth of file header
        self.BUFFER_SIZE = 64 * 1024
        self.progress = self.progress_bar

    def progress_bar(self, percentage):

        print(f"[{'#'*int(percentage//10)}" + f"{' '*(10-int(percentage//10))}]",
              "{:.2f}%".format(percentage), end="\r")
        if percentage >= 100:
            print()

    def _create_file_info(self):
        '''
        function create_file_info()
        return struct.pack({SALT_SIZE}siiii,major,minor,patch,header_size)
        '''

        version_major = self.VERSION[0]
        version_minor = self.VERSION[1]
        version_patch = self.VERSION[2]
        file_info = struct.pack(f'{self.DISCRIPTION_LEN}s i i i 16s i i i', self.DISCRIPTION, version_major, version_minor,
                                version_patch, self._salt, self.NONCE_SIZE, self.MACBYTES, self.file_extension_len)
        return file_info

    def _generate_salt(self):
        print("Generating salt..")
        salt = nacl.utils.random(self.SALT_SIZE)
        self._salt = salt

    def _generate_key(self, password):
        key = generate_key(secrate_string=password, salt=self._salt)
        return key

    def _encrypt_file(self, key, input_file, out_file=None):
        if os.path.exists(input_file):
            if out_file == None or out_file == "":
                # if output file is none then output dir is input dir
                out_file = os.path.join(os.path.dirname(input_file), os.path.splitext(
                    os.path.basename(input_file))[0]) + self.EXTENSION

            with open(input_file, "rb") as file_to_encrypt:
                if out_file:

                    with open(out_file, "wb") as encrypt_file:
                        encrypt_file.write(self._create_file_info())
                        extension = struct.pack(
                            f"{self.file_extension_len}s", self.file_extension)
                        encrypt_file.write(extension)
                        while True:
                            data = file_to_encrypt.read(self.BUFFER_SIZE)
                            if not data:
                                break
                            chipher_data = self.safe_box.encrypt(data)
                            encrypt_file.write(chipher_data)
                            self.progress(
                                (file_to_encrypt.tell() / self.file_size) * 100)

    def start(self):
        self._generate_salt()
        print("Genrating Key From password")
        self._key = self._generate_key(self.password)
        self.safe_box = nacl.secret.SecretBox(self._key)
        self.NONCE_SIZE = self.safe_box.NONCE_SIZE
        self.MACBYTES = self.safe_box.MACBYTES

    def encrypt_file(self):
        self.start()
        self._encrypt_file(self._key, self.file_path, self.destination)


class DecryptFile(EncryptFile):
    def __init__(self, file_path, destination=None, password=""):
        super(DecryptFile, self).__init__(
            file_path, destination, password)
        self.file_info = self._get_file_info()
        self.BUFFER_SIZE += self.file_info[5] + self.file_info[6]
        print("Genrating Key From password")
        self.key = generate_key(password, self.file_info[4])
        self.safe_box = nacl.secret.SecretBox(self.key)
        self._salt = self.file_info[4]
        self._key = self._generate_key(password)
        self.safe_box = nacl.secret.SecretBox(self._key)

    def _get_file_info(self):
        if os.path.exists(self.file_path):
            with open(self.file_path, "rb") as file_to_decrypt:
                data = file_to_decrypt.read(self.FILEINFO_LEN)
                file_info = struct.unpack(
                    f'{self.DISCRIPTION_LEN}s i i i 16s i i i', data)
                return file_info
        return False

    def _decrypt_file(self, key, input_file, out_file=None):
        if os.path.exists(input_file):
            if self.file_info[1] > self.VERSION[0]:
                print("This file is created with greater version of fencrypt")
                return False
            with open(input_file, "rb") as file_to_decrypt:
                file_extension_len = self.file_info[7]
                file_extension_size = struct.calcsize(
                    f"{file_extension_len}s")
                file_to_decrypt.seek(self.FILEINFO_LEN)
                file_e = file_to_decrypt.read(file_extension_size)
                file_extension = "." + (struct.unpack(
                    f"{file_extension_len}s", file_e)[0]).decode("utf-8")
                if not out_file:
                    out_file = os.path.join(os.path.dirname(input_file), (os.path.splitext(
                        os.path.basename(input_file))[0]) + file_extension)
                else:
                    out_file = out_file + file_extension
                with open(out_file, "wb") as decrypted:
                    while True:
                        data = file_to_decrypt.read(self.BUFFER_SIZE)
                        if not data:
                            break
                        plain_data = self.safe_box.decrypt(data)
                        decrypted.write(plain_data)
                        self.progress(
                            (file_to_decrypt.tell() / self.file_size) * 100)

    def decrypt_file(self):
        try:
            self._decrypt_file(self._key, self.file_path, self.destination)
        except Exception as e:
            print(e)


# DecryptFile("main.fenc", "None", "l").decrypt_file()
#EncryptFile("main.py", None, "l").encrypt_file()
if __name__ == "__main__":

    import getpass
    import fire

    def encrypt(file_path=None, file_destination=None):
        correct = False

        while not correct:
            password = getpass.getpass(prompt="Enter Password: ")
            confirm_passwrd = getpass.getpass(
                prompt="Enter Confirm Password: ")
            print()
            if password == confirm_passwrd:
                correct = True
                break
            print("confirm password does not match")

        if not file_path:
            print("Please enter file path")

        if os.path.exists(file_path):
            encrypter = EncryptFile(
                file_path, file_destination, confirm_passwrd)
            encrypter.encrypt_file()

        else:
            print("Enter valid file location")

    def decrypt(file_path=None, file_destination=None):

        password = getpass.getpass(prompt="Enter password: ")
        if not file_path:
            print("Please enter file path")

        if os.path.exists(file_path):

            decrypter = DecryptFile(file_path, file_destination, password)
            decrypter.decrypt_file()

        else:
            print("Enter valid file location")

    def main():
        print("Starting ")
        fire.Fire({
            'encrypt': encrypt,
            'decrypt': decrypt,
        })
    main()
