import streamlit as st
import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix

# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------
st.set_page_config(page_title="AI NIDS Dashboard", layout="wide")

st.title("AI-Powered Network Intrusion Detection System")
st.markdown("""
### Project Overview
This system uses **Machine Learning (Random Forest Algorithm)** to analyze
network traffic patterns.

**Classification Types**
- **Benign** → Normal network traffic  
- **Malicious** → Attack traffic (DDoS, Scan, etc.)

⚠️ *Note:* This is a **simulation-based academic prototype**, not a real packet sniffer.
""")

# --------------------------------------------------
# DATA LOADING (SIMULATED)
# --------------------------------------------------
@st.cache_data
def load_data():
    np.random.seed(42)
    n_samples = 5000

    data = {
        "Destination_Port": np.random.randint(1, 65535, n_samples),
        "Flow_Duration": np.random.randint(100, 100000, n_samples),
        "Total_Fwd_Packets": np.random.randint(1, 100, n_samples),
        "Packet_Length_Mean": np.random.uniform(10, 1500, n_samples),
        "Active_Mean": np.random.uniform(0, 1000, n_samples),
        "Label": np.random.choice([0, 1], size=n_samples, p=[0.7, 0.3])
    }

    df = pd.DataFrame(data)

    # Inject attack patterns
    attack_idx = df["Label"] == 1
    df.loc[attack_idx, "Total_Fwd_Packets"] += np.random.randint(50, 200, attack_idx.sum())
    df.loc[attack_idx, "Flow_Duration"] = np.random.randint(1, 1000, attack_idx.sum())

    return df


df = load_data()

# --------------------------------------------------
# SIDEBAR CONTROLS
# --------------------------------------------------
st.sidebar.header("Control Panel")

split_size = st.sidebar.slider("Training Data Size (%)", 50, 90, 80)
n_estimators = st.sidebar.slider("Number of Trees", 10, 200, 100)

# --------------------------------------------------
# DATA PREPARATION
# --------------------------------------------------
X = df.drop("Label", axis=1)
y = df["Label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=(100 - split_size) / 100,
    random_state=42
)

# --------------------------------------------------
# MODEL TRAINING
# --------------------------------------------------
st.divider()
col_train, col_metrics = st.columns([1, 2])

with col_train:
    st.subheader("1. Model Training")

    if st.button("Train Model Now"):
        with st.spinner("Training Random Forest Model..."):
            model = RandomForestClassifier(
                n_estimators=n_estimators,
                random_state=42
            )
            model.fit(X_train, y_train)
            st.session_state["model"] = model
            st.success("Model trained successfully")

    if "model" in st.session_state:
        st.info("Model is ready for testing")

# --------------------------------------------------
# MODEL EVALUATION
# --------------------------------------------------
with col_metrics:
    st.subheader("2. Performance Metrics")

    if "model" in st.session_state:
        model = st.session_state["model"]
        y_pred = model.predict(X_test)

        acc = accuracy_score(y_test, y_pred)

        m1, m2, m3 = st.columns(3)
        m1.metric("Accuracy", f"{acc*100:.2f}%")
        m2.metric("Total Samples", len(df))
        m3.metric("Detected Attacks", int(np.sum(y_pred)))

        st.write("### Confusion Matrix")
        cm = confusion_matrix(y_test, y_pred)
        fig, ax = plt.subplots(figsize=(4, 3))
        sns.heatmap(cm, annot=True, fmt="d", cmap="Reds", ax=ax)
        st.pyplot(fig)

    else:
        st.warning("Train the model first")

# --------------------------------------------------
# LIVE TRAFFIC SIMULATOR
# --------------------------------------------------
st.divider()
st.subheader("3. Live Traffic Simulator (Demo)")

c1, c2, c3, c4 = st.columns(4)

flow_duration = c1.number_input("Flow Duration (ms)", 0, 100000, 500)
total_packets = c2.number_input("Total Packets", 0, 500, 100)
packet_length = c3.number_input("Packet Length Mean", 0, 1500, 500)
active_mean = c4.number_input("Active Mean Time", 0, 1000, 50)

if st.button("Analyze Packet"):
    if "model" not in st.session_state:
        st.error("Train the model first")
    else:
        input_data = np.array([[80, flow_duration, total_packets, packet_length, active_mean]])
        prediction = st.session_state["model"].predict(input_data)[0]

        if prediction == 1:
            st.error("🚨 MALICIOUS TRAFFIC DETECTED")
            st.write("Reason: Unusual packet volume and timing pattern")
        else:
            st.success("✅ BENIGN TRAFFIC")
