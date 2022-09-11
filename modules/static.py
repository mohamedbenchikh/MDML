import pandas as pd
import datetime
import streamlit as st

from xgboost import XGBClassifier

from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler

from signify.authenticode import SignedPEFile
import yara
import lief
import yaml
import hashlib
import pefile
import os
import joblib

import warnings

warnings.filterwarnings("ignore")


def load_config(file_path):
    with open(file_path, "r") as f:
        return yaml.safe_load(f)


config = load_config("config.yaml")
static_config = config['STATIC']

yara_rules_path = static_config['YARA_RULES_PATH']

all_capabilities = ['inject_thread', 'create_process', 'persistence', 'hijack_network', 'create_service', 'create_com_service', 'network_udp_sock', 'network_tcp_listen', 'network_dyndns', 'network_toredo', 'network_smtp_dotNet', 'network_smtp_raw', 'network_smtp_vb', 'network_p2p_win', 'network_tor', 'network_irc', 'network_http', 'network_dropper', 'network_ftp', 'network_tcp_socket', 'network_dns', 'network_ssl', 'network_dga', 'bitcoin', 'certificate', 'escalate_priv',
                    'screenshot', 'lookupip', 'dyndns', 'lookupgeo', 'keylogger', 'cred_local', 'sniff_audio', 'cred_ff', 'cred_vnc', 'cred_ie7', 'sniff_lan', 'migrate_apc', 'spreading_file', 'spreading_share', 'rat_vnc', 'rat_rdp', 'rat_telnet', 'rat_webcam', 'win_mutex', 'win_registry', 'win_token', 'win_private_profile', 'win_files_operation', 'Str_Win32_Winsock2_Library', 'Str_Win32_Wininet_Library', 'Str_Win32_Internet_API', 'Str_Win32_Http_API', 'ldpreload', 'mysql_database_presence']

capabilities_descriptions = ['Code injection with CreateRemoteThread in a remote process', 'Create a new process', 'Install itself for autorun at Windows startup', 'Hijack network configuration', 'Create a windows service', 'Create a COM server', 'Communications over UDP network', 'Listen for incoming communication', 'Communications dyndns network', 'Communications over Toredo network', 'Communications smtp', 'Communications smtp', 'Communications smtp', 'Communications over P2P network', 'Communications over TOR network', 'Communications over IRC network', 'Communications over HTTP', 'File downloader/dropper', 'Communications over FTP', 'Communications over RAW socket', 'Communications use DNS', 'Communications over SSL', 'Communication using dga', 'Perform crypto currency mining', 'Inject certificate in store', 'Privilege Escalation', 'Take screenshot',
                             'Lookup external IP', 'Dynamic DNS', 'Lookup Geolocation', 'Run a keylogger', 'Steal credential', 'Record Audio', 'Steal Firefox credential', 'Steal VNC credential', 'Steal IE 7 credential', 'Sniff Lan network traffic', 'APC queue tasks migration', 'Malware can spread east-west file', 'Malware can spread east-west using share drive', 'Remote Administration toolkit VNC', 'Remote Administration toolkit enable RDP', 'Remote Administration toolkit enable Telnet', 'Remote Administration toolkit using webcam', 'Create or check mutex', 'Affect system registries', 'Affect system token', 'Affect private profile', 'Affect private profile', 'Match Winsock 2 API library declaration', 'Match Windows Inet API library declaration', 'Match Windows Inet API call', 'Match Windows Http API call', 'Load specified shared libraries', 'This rule checks MySQL database presence']

# Capabilities

capabilities_rules_path = yara_rules_path + '/capabilities/'
capabilities_rules = yara.compile(capabilities_rules_path + 'capabilities.yar')

# Packers

packer_rules_path = yara_rules_path + '/packers/'
packer_compiler_rules = yara.compile(packer_rules_path + 'packer_compiler_signatures.yar')

class PEFile:

    def __init__(self, filename):

        binary = lief.parse(filename.__str__())

        def has_manifest(binary):
            if binary.has_resources and not binary.resources_manager.has_manifest:
                return 0
            else:
                return 1

        def has_aslr(binary):
            if binary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE):
                return 1
            else:
                return 0

        def has_tls(binary):
            if binary.has_tls:
                return 1
            else:
                return 0

        def has_dep(binary):
            if binary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.NX_COMPAT):
                return 1
            else:
                return 0

        def suspicious_dbgts(binary):
            if binary.has_debug:
                debug_list = binary.debug
                for item in debug_list:
                    ts = item.timestamp
                    dbg_time = datetime.datetime.fromtimestamp(ts)
                    if dbg_time > datetime.datetime.now():
                        return 1
                return 0
            else:
                return -1

        def check_ci(binary):
            if binary.has_configuration:
                if isinstance(binary.load_configuration, lief.PE.LoadConfigurationV2) and binary.load_configuration.code_integrity.catalog == 0xFFFF:
                    return 0
                else:
                    return 1
            else:
                return -1

        def supports_cfg(binary):
            if binary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.GUARD_CF):
                return 1
            else:
                return 0

        def isSigned(filename):
            with open(filename, "rb") as f:
                signed_pe = SignedPEFile(f)
                status, err = signed_pe.explain_verify()
                if status.value == 1:
                    return 1
                elif status.value == 2:
                    return 0
                else:
                    return -1

        def isPacked(filename):
            matches = packer_compiler_rules.match(filename)
            matches = [m.rule for m in matches]
            if 'IsPacked' in matches:
                return 1
            else:
                return 0

        def calculate_sha256(filename, block_size=65536):
            sha256 = hashlib.sha256()
            with open(filename, 'rb') as f:
                for block in iter(lambda: f.read(block_size), b''):
                    sha256.update(block)
            return sha256.hexdigest()

        pe = pefile.PE(filename, fast_load=False)
        self.filename = filename
        self.sha256 = calculate_sha256(filename)
        self.isSigned = isSigned(filename)

        self.isPacked = isPacked(filename)

        self.MajorLinkerVersion = pe.OPTIONAL_HEADER.MajorLinkerVersion
        self.MinorLinkerVersion = pe.OPTIONAL_HEADER.MinorLinkerVersion
        self.SizeOfUninitializedData = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        self.ImageBase = pe.OPTIONAL_HEADER.ImageBase
        self.FileAlignment = pe.OPTIONAL_HEADER.FileAlignment
        self.MajorOperatingSystemVersion = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        self.MajorImageVersion = pe.OPTIONAL_HEADER.MajorImageVersion
        self.MinorImageVersion = pe.OPTIONAL_HEADER.MinorImageVersion
        self.MajorSubsystemVersion = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        self.SizeOfImage = pe.OPTIONAL_HEADER.SizeOfImage
        self.SizeOfHeaders = pe.OPTIONAL_HEADER.SizeOfHeaders
        self.CheckSum = pe.OPTIONAL_HEADER.CheckSum
        self.Subsystem = pe.OPTIONAL_HEADER.Subsystem
        self.DllCharacteristics = pe.OPTIONAL_HEADER.DllCharacteristics
        self.SizeOfStackReserve = pe.OPTIONAL_HEADER.SizeOfStackReserve
        self.SizeOfHeapReserve = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        self.NumberOfSections = pe.FILE_HEADER.NumberOfSections
        self.e_cblp = pe.DOS_HEADER.e_cblp
        self.e_lfanew = pe.DOS_HEADER.e_lfanew
        self.SizeOfRawData = sum(map(lambda x: x.SizeOfRawData, pe.sections))
        self.Characteristics = pe.FILE_HEADER.Characteristics
        self.Misc = sum(map(lambda x: x.Misc_VirtualSize, pe.sections))

        try:
            self.BaseOfData = pe.OPTIONAL_HEADER.BaseOfData
        except AttributeError:
            self.BaseOfData = 0

        capabilities = capabilities_rules.match(filename.__str__())
        capabilities = [capability.rule for capability in capabilities]

        for capability in all_capabilities:
            if capability in capabilities:
                exec(f'self.{capability} = 1')
            else:
                exec(f'self.{capability} = 0')

        # Extra Features

        self.has_manifest = has_manifest(binary)
        self.has_aslr = has_aslr(binary)
        self.has_tls = has_tls(binary)
        self.has_dep = has_dep(binary)
        self.code_integrity = check_ci(binary)
        self.supports_cfg = supports_cfg(binary)
        self.suspicious_dbgts = suspicious_dbgts(binary)

        pe.close()
        

    def Build(self):
        item = {}
        for attr, k in self.__dict__.items():
            item[attr] = k
        return item


def train_model():

    dataset_path = "datasets/static.csv"

    df = pd.read_csv(dataset_path, index_col='id')

    df.dropna(subset=['family'], inplace=True)

    threshold = df['family'].value_counts()
    df = df[df.isin(threshold.index[threshold >= 800]).values]

    features = df.columns[2:-1]

    X = df[features].values
    y = df.iloc[:, -1].values

    le = LabelEncoder()

    y_df = pd.DataFrame(y, dtype=str)
    y_df.apply(le.fit_transform)

    y = y_df.apply(le.fit_transform).values[:, :]

    encoded_labels = dict(zip(le.classes_, le.transform(le.classes_)))

    target_names = list(encoded_labels.keys())

    X = df[features].values

    class_column = ['family']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.4, random_state=42, stratify=y)

    y_train = y_train.ravel()

    
    
    data = X_train
    scaler = MinMaxScaler()

    scaler.fit(data)

    scaler.transform(data)

    X_train = scaler.transform(data)
    X_test = scaler.transform(X_test)

    xgb_clf = XGBClassifier()
    xgb_clf.fit(X_train, y_train)

    return (xgb_clf, target_names, features, scaler)


if not os.path.exists("models/static.joblib"):
    model, target_names, features, scaler = train_model()
    joblib.dump(model, "models/static.joblib")
    joblib.dump(target_names, "labels/static.joblib")
    joblib.dump(features, "features/static.joblib")
    joblib.dump(scaler, "models/static_scaler.joblib")
else:
    target_names = joblib.load("labels/static.joblib")
    model = joblib.load("models/static.joblib")
    features = joblib.load("features/static.joblib")    
    scaler = joblib.load("models/static_scaler.joblib")


def process(file):

    try:
        pe = PEFile(file.name)
        sample = pe.Build()
    except Exception as e:
        print(e)
        return None

    sample_df = pd.DataFrame([sample])

    sample_df.insert(loc=0, column="family", value="-1")

    X_sample = sample_df[features].values

    X_sample = scaler.transform(X_sample)

    proba = model.predict_proba(X_sample)
    result = model.predict(X_sample)[0]
    confidence = round(proba[0][result], 2)

    if result != 0 and X_sample[0][0] == 1:
        result = 0

    if result == 0:
        status = f'<font color="green">{target_names[result]}</font>'
    else:
        status = f'<font color="red">{target_names[result]}</font>'

    confidence = round(confidence*100, 2)

    message = f"Source: <b>Static Analysis</b> <br> Status: <b>{status}</b> <br> Confidence: <b>{confidence}%</b>"

    st.markdown(message, unsafe_allow_html=True)

    detected_capabilities = []

    for index in range(len(all_capabilities)):
        capability = all_capabilities[index]
        description = capabilities_descriptions[index]
        if sample_df[capability][0] == 1:
            detected_capabilities.append((capability, description))

    if detected_capabilities:
        msg = 'Capabilities:<br><font color="red">'
        msg += '<br>'.join(
            [f'<b>{cap[0]}</b>: <font color="black">{cap[1]}</font>' for cap in detected_capabilities])
        msg += '</font>'

        st.markdown(msg, unsafe_allow_html=True)

    return (target_names[result], confidence)
