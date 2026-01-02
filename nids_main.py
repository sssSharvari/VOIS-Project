import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
from sklearn.preprocessing import StandardScaler

# --------------------------------------------------
# Streamlit config
# --------------------------------------------------
st.set_page_config(page_title="AI-Based NIDS", layout="wide")
st.title("AI-Based Network Intrusion Detection System")
st.write("ML-based Intrusion Detection using CIC-IDS2017 Dataset")

# --------------------------------------------------
# Load and preprocess dataset
# --------------------------------------------------
@st.cache_data
def load_data():
    df = pd.read_csv(
        "MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    )

    # Clean column names
    df.columns = df.columns.str.strip()

    # Replace infinities and NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # Binary classification
    df["Label"] = df["Label"].apply(
        lambda x: 0 if x == "BENIGN" else 1
    )

    return df


# --------------------------------------------------
# Sidebar
# --------------------------------------------------
st.sidebar.header("Model Control")

if st.sidebar.button("Load Dataset"):
    df = load_data()
    st.session_state["df"] = df
    st.sidebar.success("Dataset loaded")

if "df" in st.session_state:
    st.sidebar.write("Dataset shape:", st.session_state["df"].shape)

# --------------------------------------------------
# Train Model
# --------------------------------------------------
if st.sidebar.button("Train Model"):

    if "df" not in st.session_state:
        st.sidebar.error("Load dataset first")
    else:
        df = st.session_state["df"]

        X = df.drop("Label", axis=1)
        y = df["Label"]

        # Feature scaling
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled,
            y,
            test_size=0.25,
            random_state=42,
            stratify=y
        )

        model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1
        )

        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        st.session_state["model"] = model
        st.session_state["scaler"] = scaler
        st.session_state["X_test"] = X_test
        st.session_state["y_test"] = y_test
        st.session_state["y_pred"] = y_pred

        acc = accuracy_score(y_test, y_pred)
        st.sidebar.success(f"Model trained | Accuracy: {acc:.3f}")

# --------------------------------------------------
# Evaluation
# --------------------------------------------------
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
        st.text("Confusion Matrix")
        cm = confusion_matrix(
            st.session_state["y_test"],
            st.session_state["y_pred"]
        )

        fig, ax = plt.subplots()
        sns.heatmap(
            cm,
            annot=True,
            fmt="d",
            cmap="Blues",
            ax=ax
        )
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")
        st.pyplot(fig)

# --------------------------------------------------
# Manual Traffic Testing (demo only)
# --------------------------------------------------
st.subheader("Manual Traffic Test (Demo)")

if "df" in st.session_state:

    sample_features = st.session_state["df"].drop("Label", axis=1).columns

    user_input = []
    for feature in sample_features[:10]:  # limit inputs
        value = st.number_input(
            feature,
            value=0.0,
            step=1.0
        )
        user_input.append(value)

    if st.button("Detect Traffic"):

        if "model" not in st.session_state:
            st.error("Train the model first")
        else:
            # Pad remaining features with zeros
            while len(user_input) < len(sample_features):
                user_input.append(0)

            input_array = np.array(user_input).reshape(1, -1)
            input_scaled = st.session_state["scaler"].transform(input_array)

            prediction = st.session_state["model"].predict(input_scaled)[0]

            if prediction == 1:
                st.error("⚠️ Attack Detected")
            else:
                st.success("✅ Benign Traffic")
