import streamlit as st
from modules import static
from modules import dynamic
import sqlite3
import hashlib
import pefile
import os
import magic
import ssdeep
import warnings
import yaml
import platform

warnings.filterwarnings('ignore')


def load_config(file_path):
    with open(file_path, "r") as f:
        return yaml.safe_load(f)

config = load_config("config.yaml")
webapp_config = config['WEBAPP']

sqlite_database = webapp_config['SQLITE_DATABASE']
exclusions = webapp_config['EXCLUSIONS']
magic_path = webapp_config['MAGIC_PATH']

connection = sqlite3.connect(sqlite_database)

if platform.system() == 'Windows':
    magic = magic.Magic(magic_file=magic_path) 

st.set_page_config(layout="wide")

st.subheader("Malware detection using machine learning (MDML)")

st.info("Code: https://github.com/mohamedbenchikh/MDML")

file = st.file_uploader("Upload File")

def compute_sha256(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()

def main():
    if file is not None:
        file_details = {"filename": file.name, "filetype": file.type,
                        "filesize": file.size}
        st.write(file_details)

        with open(file.name, 'wb') as outfile:
            outfile.write(file.read())

        magic_file = magic.from_file(file.name)

        if magic_file.split()[0] in exclusions:
            message = f"<b>{file.name}</b> is {magic_file}"
            os.remove(file.name)
            return st.markdown(message, unsafe_allow_html=True)

        fileinfo = magic_file.split(',')[0]
        
        cursor = connection.cursor()

        sha256 = compute_sha256(file.name)

        with open(file.name, 'rb') as infile:
            ssdeep_hash = ssdeep.hash(infile.read())

        message = f"Filename: <b>{file.name}</b> <br> File info: <b>{fileinfo}</b> <br>SHA256: <b>{sha256}</b> <br>SSDEEP: <b>{ssdeep_hash}</b>"        

        try:
            pe = pefile.PE(file.name)

            imphash = pe.get_imphash()

            if not imphash:
                imphash = sha256
            else:
                message += f"<br>imphash: <b>{imphash}</b>"

            cursor.execute(
                f'SELECT ssdeep FROM signatures WHERE imphash = "{imphash}" OR sha256 = "{sha256}"')

            ssdeep_hash_db = cursor.fetchone()[0]

            if ssdeep.compare(ssdeep_hash, ssdeep_hash_db) > 50:
                cursor.execute(
                    f'SELECT class, confidence FROM signatures WHERE imphash = "{imphash}" OR sha256 = "{sha256}"')
                result = cursor.fetchone()
            else:
                result = None

        except:
            result = None

        with st.expander("File details"):
            st.markdown(message, unsafe_allow_html=True)

        if not result:
            result = static.process(file)

            if not result:
                form = st.form(key='dynamic')
                form.text('Static analysis can only handle PE files, do you want to submit this file for dynamic analysis instead?')
                submit = form.form_submit_button('Submit')
                if submit:
                    imphash = sha256
                    message = f"Initiating dynamic analysis for: <b>{file.name}</b>"
                    st.markdown(message, unsafe_allow_html=True)
                    result = dynamic.process(file)

            if result:
                status, confidence = result

                cursor.execute(
                    f'INSERT INTO signatures (sha256, imphash, ssdeep, class, confidence) VALUES ("{sha256}", "{imphash}", "{ssdeep_hash}", "{status}", "{confidence}")')

                connection.commit()

        else:
            status, confidence = result

            if status == 'Benign':
                status = f'<font color="green">{status}</font>'
            else:
                status = f'<font color="red">{status}</font>'

            message = f"Source: <b>Database</b> <br> Status: <b>{status}</b> <br> Confidence: <b>{confidence}%</b>"

            st.markdown(message, unsafe_allow_html=True)

            cursor.close()

        try:
            pe.close()            
        except:
            pass
        
        os.remove(file.name)
        


if __name__ == '__main__':
    main()
