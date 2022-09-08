import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import time
import yaml

from xgboost import XGBClassifier

from sklearn.preprocessing import LabelEncoder 
from sklearn.model_selection import train_test_split

from PIL import Image
from io import BytesIO
from mpl_toolkits.axes_grid1 import ImageGrid
import requests
import streamlit as st
import os
import joblib

import warnings

warnings.filterwarnings("ignore")


def load_config(file_path):
    with open(file_path, "r") as f:
        return yaml.safe_load(f)

config = load_config("config.yaml")
dynamic_config = config['DYNAMIC']

cuckoo_api_url = dynamic_config['CUCKOO_API_URL']
cuckoo_submit_endpoint = dynamic_config['CUCKOO_SUBMIT_ENDPOINT']
cuckoo_token = dynamic_config['CUCKOO_TOKEN']
cuckoo_screenshots_endpoint = dynamic_config['CUCKOO_SCREENSHOTS_ENDPOINT']

headers = {"Authorization": f"Bearer {cuckoo_token}"}

def train_model():

    priority_calls = ['InternetOpen', 'GetProcAddress', 'CreateToolhelp32Snapshot', 'HttpOpenRequest', 'ioctlsocket', 'OpenProcess', 'CreateThread', 'SetWindowsHookExA', 'InternetReadFile', 'FindResource', 'CountClipboardFormats', 'WriteProcessMemory', 'free', 'GetEIP', 'GetAsyncKeyState', 'DispatchMessage', 'SizeOfResource', 'GetFileSize', 'GetTempPathA', 'NtUnmapViewOfSection', 'WSAIoctl', 'ReadFile', 'GetTickCount', 'Fopen', 'malloc', 'InternetConnect', 'Sscanf', 'GetKeyState', 'GetModuleHandle', 'ReadProcessMemory', 'LockResource', 'RegSetValueEx', 'ShellExecute', 'IsDebuggerPresent', 'WSASocket', 'VirtualProtect', 'bind', 'WinExec', 'GetForeGroundWindow', 'CreateProcessA', 'LoadLibraryA', 'socket', 'LoadResource', 'CreateFileA', 'VirtualAllocEx', 'HTTPSendRequest', 'BroadcastSystemMessage', 'FindWindowsA', 'Process32First', 'CreateRemoteThread', 'GetWindowsThreadProcessId', 'URLDownloadToFile', 'SetWindowsHookEx', 'GetMessage']

    interesting_calls = ['VirtualAlloc', 'MoveFileA', 'FindResourceA', 'GetWindowsDirectoryA', 'PeekMessageA', 'FindClose', 'MapVirtualKeyA', 'SetEnvironmentVariableA', 'GetKeyboardState', 'mciSendStringA', 'GetFileType', 'RasEnumConnectionsA', 'FlushFileBuffers', 'GetVersionExA', 'ioctlsocket', 'WSAAsyncSelect', 'GetCurrentThreadId', 'LookupPrivilegeValueA', 'GetCurrentProcess', 'SetStdHandle', 'WSACleanup', 'WSAStartup', 'CreateMutexA', 'GetForegroundWindow', 'SetKeyboardState', 'OleInitialize', 'SetUnhandledExceptionFilter', 'UnhookWindowsHookEx', 'GetModuleHandleA', 'GetSystemDirectoryA', 'RegOpenKey', 'GetFileAttributesA', 'AdjustTokenPrivileges', 'FreeLibrary', 'GetStartupInfoA', 'RasGetConnectStatusA', 'OpenProcessToken', 'PostMessageA', 'GetTickCount', 'GetExitCodeProcess', 'SetFileTime', 'DispatchMessageA', 'RegDeleteValueA', 'FreeEnvironmentStringsA', 'CallNextHookEx', 'GetUserNameA', 'HeapCreate', 'GlobalMemoryStatus', 'SetFileAttributesA', 'URLDownloadToFileA', 'RaiseException', 'WSAGetLastError', 'RegCreateKeyExA', 'keybd_event', 'ExitWindowsEx', 'GetCommandLineA', 'RegCreateKeyA', 'FreeEnvironmentStringsW', 'UnhandledExceptionFilter', 'GetExitCodeThread', 'PeekNamedPipe']

    calls = priority_calls + interesting_calls

    features = list(map(str.lower, calls))

    dataset_path = "datasets/dynamic.csv"

    df = pd.read_csv(dataset_path, index_col='id')

    X = df.values[:,1:]
    y = df.values[:,0]

    le = LabelEncoder()

    y_df = pd.DataFrame(y, dtype=str)

    y = y_df.apply(le.fit_transform).values[:,:]

    encoded_labels = dict(zip(le.classes_, le.transform(le.classes_)))

    target_names = list(encoded_labels.keys())

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.4, random_state=42, stratify=y)

    xgb_clf = XGBClassifier()
    xgb_clf.fit(X_train, y_train)

    return (xgb_clf, target_names, features)

if not os.path.exists("models/dynamic.joblib"):
    model, target_names, features = train_model()
    joblib.dump(model, "models/dynamic.joblib")
    joblib.dump(target_names, "labels/dynamic.joblib")
    joblib.dump(features, "features/dynamic.joblib")
else:
    target_names = ['AdWare', 'Backdoor', 'Benign', 'Email-Worm', 'Generic Malware', 'Hoax', 'Packed', 'Trojan', 'Trojan-Downloader', 'Trojan-Dropper', 'Trojan-FakeAV', 'Trojan-GameThief', 'Trojan-PSW', 'Trojan-Ransom', 'Trojan-Spy', 'Virus', 'Worm']
    model = joblib.load("models/dynamic.joblib")
    features = joblib.load("features/dynamic.joblib")
    target_names = joblib.load("labels/dynamic.joblib")
    

def process(file):

    try:
        requests.get(cuckoo_api_url, timeout=30)
    except:
        st.error("Cuckoo API is not running")   
        return None

    with open(file.name, "rb") as infile:
        files = {"file": ("temp_file_name", infile)}
        r = requests.post(cuckoo_api_url + cuckoo_submit_endpoint, headers=headers, files=files)
        
    resp = r.json()

    task_id = resp['task_id']

    task_endpoint = "/tasks/report/" + str(task_id)

    st.spinner(text="Sample is running in the sandbox, please wait...")
    
    while True:
        try:
            r = requests.get(cuckoo_api_url + task_endpoint, headers=headers)
            report = r.json()
            if r.status_code == 200:
                break
        except:
            pass
        time.sleep(2.5)
    

    apis = []

    class_ = 'Unknown'

    try:
        api_keys = report['behavior']['apistats']
    except:
        api_keys = []
        
    for key in api_keys:
        apis += list(api_keys[key].keys())
        
    apis = [class_] + apis

    data_df = pd.DataFrame(np.array(apis).reshape(1, -1))

    df = pd.DataFrame(0, index=np.arange(len(data_df)), columns=["class"] + features)

    for i in range(len(data_df.values)):
        df.iloc[i, 0] = data_df.values[i][0]
        for value in data_df.values[i][1:]:
            if type(value) != str:
                continue
            value = value.lower()
            if not value in features:
                continue
            df.loc[i, value] = 1
            
    X_sample = df.values[:,1:]
    y = df.values[:,0]

    proba = model.predict_proba(X_sample)
    result = model.predict(X_sample)[0]
    confidence = round(proba[0][result]*100, 2)

    if result == 2:
        status = f'<font color="green">{target_names[result]}</font>'
    else:
        status = f'<font color="red">{target_names[result]}</font>'

    score = report['info']['score']

    message = f"Source: <b>Dynamic Analysis</b> <br> Status: <b>{status}</b> <br> Confidence: <b>{confidence}%</b> <br> Malicious Score: <b>{score}/10</b>"

    st.markdown(message, unsafe_allow_html=True)

    signatures = report['signatures']
    signatures = [(sig['name'], sig['description']) for sig in signatures]

    if signatures:
        msg = 'Capabilities:<br><font color="red">'
        msg += '<br>'.join([f'<b>{sig[0]}</b>: <font color="black">{sig[1]}</font>' for sig in signatures])
        msg += '</font>'

        st.markdown(msg, unsafe_allow_html=True)

    screenshots_endpoint = cuckoo_screenshots_endpoint + str(task_id) + "/"

    try:        
        screenshots = report['screenshots']
        screenshots_ids = [sc['path'].split('/')[-1].split('.')[0] for sc in screenshots]

        columns_count = 1
        rows_count = round(len(screenshots_ids)/columns_count)  

        fig = plt.figure(figsize=(200., 200.))
        grid = ImageGrid(fig, 111, 
                        nrows_ncols=(rows_count, columns_count),  
                        axes_pad=0.1,
                        )
        images_array = []

        for _, sc_id in zip(grid, screenshots_ids):
            r = requests.get(cuckoo_api_url + screenshots_endpoint + str(sc_id), headers=headers)
            img = Image.open(BytesIO(r.content))
            im_array = np.asarray(img)    
            images_array.append(im_array)

        st.image(images_array)
    except:
        pass

    return (target_names[result], confidence)
    