import streamlit as st
import pandas as pd
import numpy as np
import os
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler

# ------------------------------------
# Streamlit config
# ------------------------------------
st.set_page_config(page_title="AI-Based NIDS", layout="wide")
st.title("AI-Based Network Intrusion Detection System")

st.write(
    "This project demonstrates a Machine Learning–based Intrusion Detection System "
    "using the CIC-IDS2017 dataset. Due to dataset size constraints, the online version "
    "runs in demo mode."
)

# ------------------------------------
# Paths
# ------------------------------------
DATA_PATH = "MachineLearningCVE\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

# ------------------------------------
# Data loader
# ------------------------------------
@st.cache_data
def load_real_data():
    df = pd.read_csv(DATA_PATH)
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    df["Label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)
    return df


def generate_demo_data():
    np.random.seed(42)
    size = 1000
    df = pd.DataFrame({
        "Flow Duration": np.random.randint(1, 100000, size),
        "Total Fwd Packets": np.random.randint(1, 500, size),
        "Total Backward Packets": np.random.randint(1, 500, size),
        "Flow Bytes/s": np.random.rand(size) * 10000,
        "Flow Packets/s": np.random.rand(size) * 1000,
        "Label": np.random.choice([0, 1], size, p=[0.7, 0.3])
    })
    return df

# ------------------------------------
# Sidebar
# ------------------------------------
st.sidebar.header("Controls")

use_demo = st.sidebar.checkbox("Run in Demo Mode (Online Safe)", value=True)

if st.sidebar.button("Load Dataset"):
    if not use_demo and os.path.exists(DATA_PATH):
        df = load_real_data()
        st.session_state["mode"] = "real"
        st.success("Real CIC-IDS2017 dataset loaded")
    else:
        df = generate_demo_data()
        st.session_state["mode"] = "demo"
        st.warning("Dataset not found. Running in DEMO mode.")

    st.session_state["df"] = df
    st.sidebar.write("Dataset shape:", df.shape)

# ------------------------------------
# Train model
# ------------------------------------
if st.sidebar.button("Train Model"):
    if "df" not in st.session_state:
        st.error("Load dataset first")
    else:
        df = st.session_state["df"]

        X = df.drop("Label", axis=1)
        y = df["Label"]

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.25, random_state=42, stratify=y
        )

        model = RandomForestClassifier(
            n_estimators=100, random_state=42, n_jobs=-1
        )
        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)

        st.session_state["model"] = model
        st.session_state["scaler"] = scaler
        st.session_state["y_test"] = y_test
        st.session_state["y_pred"] = y_pred

        st.success("Model trained successfully")

# ------------------------------------
# Evaluation
# ------------------------------------
if "model" in st.session_state:
    st.subheader("Model Evaluation")

    col1, col2 = st.columns(2)

    with col1:
        st.text("Classification Report")
        st.text(
            classification_report(
                st.session_state["y_test"],
                st.session_state["y_pred"],
                target_names=["Benign", "Attack"]
            )
        )

    with col2:
        cm = confusion_matrix(
            st.session_state["y_test"],
            st.session_state["y_pred"]
        )
        fig, ax = plt.subplots()
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=ax)
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")
        st.pyplot(fig)

# ------------------------------------
# Manual test
# ------------------------------------
st.subheader("Manual Traffic Test (Demo)")

if "model" in st.session_state:
    features = st.session_state["df"].drop("Label", axis=1).columns

    user_input = []
    for f in features:
        user_input.append(st.number_input(f, value=0.0))

    if st.button("Detect Intrusion"):
        input_arr = np.array(user_input).reshape(1, -1)
        input_scaled = st.session_state["scaler"].transform(input_arr)
        pred = st.session_state["model"].predict(input_scaled)[0]

        if pred == 1:
            st.error("⚠️ Attack Detected")
        else:
            st.success("✅ Benign Traffic")
